# Architecture

hermes-firewall puts the Docker sandbox of each Hermes Agent profile behind its own
nftables table. Everything is in `hermes_firewall.py` (CLI, rules, Hermes coupling,
install/upgrade, DNS client; standard library only) plus the Hermes plugin in
`plugin/hermes-firewall/`. Function index: [FUNCTIONS.md](FUNCTIONS.md); rules that must
stay true: [INVARIANTS.md](INVARIANTS.md); tests: [TESTING.md](TESTING.md).

## Files on the host

```text
/usr/local/bin/hermes-firewall            the program (hermes_firewall.py)
/usr/local/share/hermes-firewall/plugin/  plugin source that `add` copies into profiles
/etc/hermes-firewall/config.toml          settings (admin-owned, never overwritten)
/etc/hermes-firewall/profiles.json        registry of protected profiles
/etc/hermes-firewall/resolved.json        last addresses of lan.hosts and DNS64 prefixes that resolved
/etc/sudoers.d/hermes-firewall            NOPASSWD open/close/status per protected profile
/etc/systemd/system/hermes-firewall.service           restore at boot (all closed)
/etc/systemd/system/hermes-firewall-refresh.{service,timer}   every 5 minutes
/etc/systemd/system/docker.service.d/90-hermes-firewall.conf  Docker Requires= the firewall
/run/lock/hermes-firewall.lock            global lock of all root commands
~/.hermes[/profiles/P]/plugins/hermes-firewall/   the plugin inside a profile (user-owned)
```

## Identity per profile

`identity(profile)` is deterministic. Names follow Hermes' profile rule
`[a-z0-9][a-z0-9_-]{0,63}`; `default` is the profile in `~/.hermes`.
`d = sha256(name)`: bridge `hfw` + `d[:12]` (15 characters, the Linux limit), Docker
network `hermes-fw-NAME` (label `hermes-firewall.profile=NAME`, `enable_icc=false`),
nft table `inet hermes_fw_` + `d[:12]`, IPv6 subnet `fdXX:XXXX:XXXX::/64` from `d[12:22]`.

Registry `profiles.json`: `{"version": 2, "profiles": {NAME: {"user", "ipv6", "label", "dns"}}}`.
`user` is the Hermes user (from `SUDO_USER` at `add`), `ipv6` whether the network has
IPv6 (decided at `add`), `label` the `hermes-profile` label Hermes puts on this profile's
containers, `dns` the DNS servers last written into the profile. Leases are never stored.

## nft table

Created by `rules(profile, sets)`. Lease sets `open_internet` and `open_lan` (type
ifname, `flags timeout`, size 1) hold the bridge name while a lease is open; the kernel
removes it when the timeout runs out. Address sets (`SETS`), all refreshed at runtime:
`lan_v4/v6`, `dns_v4/v6`, `allow_v4/v6` (all ports), `allow_ports_v4/v6`
(`addr . proto . port`, intervals), `non_public_v6`, `host_ports_v4` (egress proxy);
`non_public_v4` is static.

`chain outbound` (packets from the sandbox), order matters:

1. DNS to `dns_v4/v6`, tcp/udp 53: accept in every state.
2. `allow_*`: accept in every state.
3. `lan_v4/v6` with a LAN lease: accept; otherwise drop. So an Internet lease never
   opens the LAN, also not public addresses of LAN hosts or NAT64-embedded LAN addresses.
4. `non_public_v4/v6`: drop (private and special ranges, 6to4, Teredo, NAT64-embedded
   non-public IPv4).
5. Internet lease: accept; final drop.

`forward_guard` (hook forward, priority -10, before Docker's own rules) jumps to
`outbound` for traffic from the bridge; return traffic is only accepted for
established/related flows that the outbound rules allow. `host_input_guard` /
`host_output_guard` block the host itself in both directions, except IPv6 neighbour
discovery (needed for IPv6 forwarding), ICMP errors from the host and the Hermes egress
proxy ports (`host_ports_v4`, replies only for established connections).

`health()` checks hooks, priorities and that the kernel has exactly as many rules per
chain as `rules()` generates (`chain_rules`). Any change of the rule layout therefore
makes `upgrade` reload all tables, which closes all leases.

Leases: `lease_transaction(profile, kinds, seconds)` flushes the lease sets and adds the
bridge with `timeout Ns` in one nft transaction.

## Addresses

`common_sets(conf)` builds the elements shared by all profiles:

- LAN: configured networks, or with `"auto"` the networks the host is directly connected
  to (`host_networks`: interface addresses and on-link routes, without Docker and other
  virtual bridges), plus the addresses of `lan.hosts`, plus all IPv4 LAN entries embedded
  in every NAT64 prefix.
- Resolution of `lan.hosts` and DNS64 is strict for `add`, `refresh` and `upgrade` (on a
  failure nothing changes). At boot (`restore`) DNS may not work yet: then the last
  results from `resolved.json` are used, so an Internet lease never reaches a LAN host
  just because its name did not resolve.
- `[[allow]]` entries with ports are collapsed per protocol and port
  (`ipaddress.collapse_addresses`): nft refuses overlapping intervals in a concatenated set.
- NAT64 prefixes: `64:ff9b::/96` plus prefixes announced by DNS64 (`ipv4only.arpa`,
  RFC 7050), detected on every refresh.
- Host names are resolved by a small DNS client (`dns_query`, `dns_answer`, `resolve`,
  A and AAAA incl. CNAME) against the **sandbox DNS servers**, not the host resolver, so
  firewall and sandbox see the same address (split DNS).

`proxy_ports(conf)` finds iron-proxy listeners on the docker0 address (what
`host.docker.internal` points to) and their owner uid (`ss -ltnpe`); each profile only
gets the ports of its own user.

## Configuration

`load_config()` reads `/etc/hermes-firewall/config.toml` with `tomllib`, refuses unknown
keys and returns a normalized dict. LAN networks must be private IPv4, IPv6 ULA or a
global IPv6 prefix of /48 or longer; DNS servers must be reachable unicast addresses;
`[[allow]]` entries may be public on purpose (admin decision). The installer writes the
file from `config.example.toml` with the DNS servers found in `/etc/resolv.conf` (or
behind systemd-resolved).

## Hermes coupling

Hermes files are changed only by the Hermes user's own process: root runs
`runuser -l USER -c 'hermes-firewall _hermes info|attach|detach PROFILE'` (no stdin, own
session, output stripped of control characters and not trusted), which uses the
Hermes CLI (`hermes -p P config get terminal --json`, `config set ...`,
`plugins enable|disable`). Hermes' `config set` keeps comments in `config.yaml`.

- `info`: refuses profiles without `terminal.backend: docker` and profiles that share one
  sandbox (`docker_shared_container_key` used by another profile of the user); returns
  the shared key and hints (e.g. `docker_mount_cwd_to_workspace`, `--privileged`,
  `docker.sock`). Root computes the container label from the key itself
  (`container_label`) and refuses a label another protected profile already uses.
- `attach`: `docker_network: true`, own `--network=hermes-fw-P` and `--dns=` entries in
  `docker_extra_args` (other entries stay), installs and enables the plugin.
- `detach`: `docker_network: false` (Hermes then runs the sandbox with `--network=none`),
  removes the own entries and the plugin.

Nothing else is set; `container_persistent`, `docker_shared_container_key`, `cwd` and
`docker_mount_cwd_to_workspace` stay the user's choice.

## Existing sandboxes

Hermes reuses long-lived containers (`container_persistent: true`); its reuse check does
not include the network. `protect_sandboxes()` therefore looks up the profile's
containers (`hermes-agent=1`, `hermes-profile=LABEL`) and moves those outside the
profile network into it (never containers in another profile's `hermes-fw-*` network) (`docker network disconnect`, then `connect`). That only ever
restricts access, so `add`, `status` and `refresh` do it without asking. Containers that
cannot be moved (host, none or container network mode) or still have other DNS servers
(the DNS servers of a container cannot be changed) need a reset: `add` asks on a
terminal and shows what is kept (mounts) and lost; elsewhere a one-line message says
to run `sudo hermes-firewall add PROFILE`.

## Commands

- `add PROFILE`: checks (as the user), creates table (persist registry, load rules
  closed) and only then the Docker network, attaches the profile, writes sudoers,
  protects existing sandboxes. Running it again repairs network, profile and sandboxes.
- `remove PROFILE`: detaches the profile, disconnects containers from the network,
  removes the network, then the table, registry entry and sudoers line.
- `open|close PROFILE ...`: lease transactions; `status`: health, sandboxes, leases.
- `restore` (boot): all tables in one transaction, all closed.
- `refresh` (timer): restores missing tables (closed), replaces all address sets in one
  transaction (strict: on a resolution failure nothing changes), re-attaches profiles
  whose DNS servers changed, protects sandboxes. Every step runs even if another failed;
  failures are reported at the end (exit code 1, journal).

All root commands take the global lock; a command waits at most 2 minutes for it.

## Plugin and sudoers

`plugin/hermes-firewall/__init__.py` registers the slash command `/firewall` (not a tool,
so the model cannot call it). It finds its profile from `HERMES_HOME`
(`hermes_cli.profiles.get_active_profile_name`) and runs
`sudo -n /usr/local/bin/hermes-firewall open|close|status PROFILE ...`. `write_sudoers()`
generates one NOPASSWD line per protected profile with exactly `open P`, `open P *`,
`close P`, `close P *` and `status P`, validated with `visudo -cf`. Because of the
wildcards, `open` and `close` accept no options at all (`parse`).

## Boot, install, upgrade

- `hermes-firewall.service` (oneshot, `RemainAfterExit`, no `ExecStop`) runs `restore`;
  ordered after nftables/firewalld/ufw and before Docker. The Docker drop-in
  (`docker_requires_firewall = true`) makes Docker fail closed if it fails. The refresh
  timer does not depend on the service, so it also repairs a failed boot restore.
- `install.sh` copies the files to a private temporary directory and runs
  `hermes_firewall.py --bundle=DIR install` (or `upgrade` if `profiles.json` exists).
  `install` must not start the service itself (its ExecStart would wait for the lock);
  `install.sh` starts it afterwards.
- `upgrade` writes program, plugin source, units and sudoers, reloads all tables only if
  `health()` fails (rule layout changed: all leases close), otherwise refreshes, and
  re-attaches every profile (new plugin, DNS).
- `uninstall` refuses while profiles, package networks or tables exist; keeps
  `config.toml` unless `--purge`.

## Known limits

Lease timeouts do not run while the host is suspended (kernel timers). NAT64 prefixes
other than /96 and prefixes announced only by the router (PREF64) are not detected.
LAN parts that are not directly connected (e.g. other /64s of a delegated prefix) and
router hairpin NAT must be configured. After `flush ruleset` by another tool, sandboxes
are unfiltered until the next refresh (at most 5 minutes). Profile names are global per
host (one registry), even with several Hermes users.

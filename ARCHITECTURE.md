# Architecture

hermes-firewall puts the Docker sandbox of each Hermes Agent profile behind its own nftables table. Everything is in `hermes_firewall.py` (CLI, rules, Hermes coupling, install/upgrade, DNS client; standard library only) plus the Hermes plugin in `plugin/hermes-firewall/`. Function index: [FUNCTIONS.md](FUNCTIONS.md); rules that must stay true: [INVARIANTS.md](INVARIANTS.md); tests: [TESTING.md](TESTING.md).

## Files on the host

```text
/usr/local/bin/hermes-firewall            the program (hermes_firewall.py)
/usr/local/share/hermes-firewall/plugin/  plugin source that `add` copies into profiles
/etc/hermes-firewall/config.toml          settings (admin-owned, never overwritten)
/etc/hermes-firewall/profiles.json        registry of protected profiles
/etc/hermes-firewall/resolved.json        last addresses of lan.hosts, DNS64 prefixes and MCP allow-list names that resolved
/etc/sudoers.d/hermes-firewall            NOPASSWD open/close/status per protected profile
/etc/systemd/system/hermes-firewall.service           restore at boot (all closed)
/etc/systemd/system/hermes-firewall-refresh.{service,timer}   every 5 minutes
/etc/systemd/system/docker.service.d/90-hermes-firewall.conf  Docker Requires= the firewall
/run/lock/hermes-firewall.lock            global lock of all root commands
/run/hermes-firewall/PROFILE.json         lease end times for the plugin's status line (report only, gone after a reboot)
~/.hermes[/profiles/P]/plugins/hermes-firewall/   the plugin inside a profile (user-owned)
```

## Identity per profile

`identity(profile)` is deterministic. Names follow Hermes' profile rule `[a-z0-9][a-z0-9_-]{0,63}`; `default` is the profile in `~/.hermes`. `d = sha256(name)`: bridge `hfw` + `d[:12]` (15 characters, the Linux limit), Docker network `hermes-fw-NAME` (label `hermes-firewall.profile=NAME`, `enable_icc=false`), nft table `inet hermes_fw_` + `d[:12]`, IPv6 subnet `fdXX:XXXX:XXXX::/64` from `d[12:22]`.

Registry `profiles.json`: `{"version": 2, "profiles": {NAME: {"user", "ipv6", "label", "dns"}}}`. `user` is the Hermes user (from `SUDO_USER` at `add`), `ipv6` whether the network has IPv6 (decided at `add`; `ipv6 = "auto"` only if the host has an IPv6 default route AND Docker masquerades IPv6, `docker_nat66`: Docker >= 27 or `ip6tables` in daemon.json; without NAT66 the ULA addresses would never get an answer), `label` the `hermes-profile` label Hermes puts on this profile's containers, `dns` the DNS servers last written into the profile. Leases are never stored.

## nft table

Created by `rules(profile, sets)`; it starts with `drop_table` (`table` + `delete table`, which works with every nft version, unlike `destroy table` from nft 1.0.8). Lease sets `open_internet` and `open_lan` (type ifname, `flags timeout`, size 1) hold the bridge name while a lease is open; the kernel removes it when the timeout runs out. Address sets (`SETS`), all refreshed at runtime: `lan_v4/v6`, `dns_v4/v6`, `allow_v4/v6` (all ports), `allow_ports_v4/v6` (`addr . proto . port`, intervals), `non_public_v6`, `host_ports_v4` (egress proxy); `non_public_v4` is static.

`chain outbound` (packets from the sandbox), order matters:

1. DNS to `dns_v4/v6`, tcp/udp 53: accept in every state.
2. `allow_*`: accept in every state.
3. `lan_v4/v6` with a LAN lease: accept; otherwise drop. So an Internet lease never opens the LAN, also not public addresses of LAN hosts or NAT64-embedded LAN addresses.
4. `non_public_v4/v6`: drop (private and special ranges, 6to4, Teredo, NAT64-embedded non-public IPv4).
5. Internet lease: accept; final drop.

Lookups with ports read `ip protocol` / `ip6 nexthdr`, not `meta l4proto`. nft before 1.1.0 adds a `byteorder` step for `meta l4proto` in a concatenation of an interval set (fixed in nftables by `9fe58952c45a`), and kernels with `netfilter: nft_byteorder: remove multi-register support` (since 6.12.115, 6.18.59 and 7.1) refuse the whole table for that, so old LTS distributions could no longer load it. The price: an IPv6 packet with an extension header does not match an `[[allow]]` entry with a port, unless a lease or an entry without a port lets it through.

Every "drop" towards the outside (steps 3 to 5 and the host guard) is a reject, so programs in the sandbox fail at once instead of waiting for a timeout: TCP gets a reset (not subject to the kernel's per-destination ICMP rate limit, which would turn many parallel connects into timeouts again), everything else ICMP admin-prohibited. Packets from outside to the sandbox are still dropped silently.

`forward_guard` (hook forward, priority -10, before Docker's own rules) jumps to `outbound` for traffic from the bridge; return traffic is only accepted for established/related flows that the outbound rules allow. `host_input_guard` / `host_output_guard` block the host itself in both directions, except IPv6 neighbour discovery (needed for IPv6 forwarding), ICMP errors from the host and the Hermes egress proxy ports (`host_ports_v4`, replies only for established connections).

`health()` checks hooks, priorities, that the kernel has exactly as many rules per chain as `rules()` generates (`chain_rules`) and the layout fingerprint in the table comment (`layout()`, a hash of the chains; read from `nft list table` text, because nft < 1.1 omits table comments from JSON). Any change of the rules therefore makes `upgrade` reload all tables, which closes all leases.

Leases: `lease_transaction(profile, kinds, seconds)` flushes the lease sets and adds the bridge with `timeout Ns` in one nft transaction.

## Addresses

`common_sets(conf)` builds the elements shared by all profiles:

- LAN: configured networks, or with `"auto"` the networks the host is directly connected to (`host_networks`: interface addresses and on-link routes, without Docker and other virtual bridges), plus the addresses of `lan.hosts`, plus all IPv4 LAN entries embedded in every NAT64 prefix.
- Resolution of `lan.hosts` and DNS64 is strict for `add`, `refresh` and `upgrade` (on a failure nothing changes). At boot (`restore`) DNS may not work yet: then the last results from `resolved.json` are used, so an Internet lease never reaches a LAN host just because its name did not resolve.
- `[[allow]]` entries with ports are collapsed per protocol and port (`ipaddress.collapse_addresses`): nft refuses overlapping intervals in a concatenated set.
- NAT64 prefixes: `64:ff9b::/96` plus prefixes announced by DNS64 (`ipv4only.arpa`, RFC 7050), detected on every refresh.
- Host names are resolved by a small DNS client (`dns_query`, `dns_answer`, `resolve`, A and AAAA incl. CNAME) against the **sandbox DNS servers**, not the host resolver, so firewall and sandbox see the same address (split DNS).

`proxy_ports(conf)` finds iron-proxy listeners on the docker0 address (what `host.docker.internal` points to) and their owner uid (`ss -ltnpe`); each profile only gets the ports of its own user.

## Configuration

`load_config()` reads `/etc/hermes-firewall/config.toml` with `tomllib`, refuses unknown keys and returns a normalized dict. LAN networks must be private IPv4, IPv6 ULA or a global IPv6 prefix of /48 or longer; DNS servers must be reachable unicast addresses; `[[allow]]` entries may be public on purpose (admin decision). The installer writes the file from `config.example.toml` with the DNS servers found in `/etc/resolv.conf` (or behind systemd-resolved).

## Hermes coupling

Hermes files are changed only by the Hermes user's own process: root runs `runuser -l USER -c 'hermes-firewall _hermes info|attach|detach PROFILE'` (no stdin, own session, output stripped of control characters and not trusted), which uses the Hermes CLI (`hermes -p P config get terminal --json`, `config set ...`, `plugins enable|disable`). Hermes' `config set` keeps comments in `config.yaml`.

- `info`: refuses profiles without `terminal.backend: docker`, profiles whose Hermes egress proxy enforces its own Docker rules (`proxy.enabled` with `proxy.enforce_on_docker`: Hermes then refuses any `--network=` and the sandbox would not start; the fix is the user's choice) and profiles that share one sandbox (`docker_shared_container_key` used by another profile of the user); returns the shared key and hints (e.g. `docker_mount_cwd_to_workspace`, `--privileged`, `docker.sock`). Root computes the container label from the key itself (`container_label`) and refuses a label another protected profile already uses.
- `attach`: `docker_network: true`, own `--network=hermes-fw-P` and `--dns=` entries in `docker_extra_args` (other entries stay), installs and enables the plugin.
- `detach`: `docker_network: false` (Hermes then runs the sandbox with `--network=none`), removes the own entries and the plugin.

Nothing else is set; `container_persistent`, `docker_shared_container_key`, `cwd` and `docker_mount_cwd_to_workspace` stay the user's choice.

## Existing sandboxes

Hermes reuses long-lived containers (`container_persistent: true`); its reuse check does not include the network. `protect_sandboxes()` therefore looks up the profile's containers (`hermes-agent=1`, `hermes-profile=LABEL`) and moves those outside the profile network into it (never containers in another profile's `hermes-fw-*` network) (`docker network disconnect`, then `connect`). That only ever restricts access, so `add`, `status` and `refresh` do it without asking. Containers that cannot be moved (host, none or container network mode) or still have other DNS servers (the DNS servers of a container cannot be changed) need a reset: `add` asks on a terminal and shows what is kept (mounts) and lost; elsewhere a one-line message says to run `sudo hermes-firewall add PROFILE`.

## Commands

- No arguments or `--help`: `usage_text`, without root, as the registry is readable by everyone: description, what is inactive, the commands in a sandbox and an MCP part. `status` warns the same way, for MCP only if no profile is protected or a protected profile has Docker MCP servers without a firewall, because a profile without any needs none; the usage cannot check that without calling Hermes.
- `add PROFILE`: checks (as the user), creates table (persist registry, load rules closed) and only then the Docker network, attaches the profile, writes sudoers, protects existing sandboxes. Running it again repairs network, profile and sandboxes.
- `mcp scan|add|remove`: see [MCP firewalls](#mcp-firewalls). `remove PROFILE` refuses while the profile has MCP firewalls.
- `remove PROFILE`: detaches the profile, disconnects containers from the network, removes the network, then the table, registry entry and sudoers line.
- `open|close PROFILE ...`: lease transactions; `status`: health, sandboxes, leases, in two parts: sandbox firewalls and MCP container firewalls. `status PROFILE` of a profile without MCP firewalls stays one line, which is what `/firewall status` shows in a chat.
- `restore` (boot): all tables in one transaction, all closed.
- `refresh` (timer): restores missing tables (closed), replaces all address sets in one transaction (strict: on a resolution failure nothing changes), re-attaches profiles whose DNS servers changed, protects sandboxes. Every step runs even if another failed; failures are reported at the end (exit code 1, journal).

All root commands take the global lock; a command waits at most 2 minutes for it.

## MCP firewalls

Hermes starts MCP servers on the host (`mcp_servers.NAME`: `command` + `args`, or `url`), so the sandbox firewall does not cover them, and Hermes knows no MCP containers: `docker run` is simply the command. A firewall exists per server per profile, named `PROFILE/SERVER`. `identity("PROFILE/SERVER")` gives it its own bridge, table (same `hermes_fw_` prefix) and IPv6 subnet, and the network `hermes-mcp-PROFILE-SERVER`; a name clash fails the ownership check of `check_network`. Registry: `"mcp": {"PROFILE/SERVER": {"user", "ipv6", "subnet", "dns"}}` beside `profiles`, optional, so older registries stay valid. `targets(data)` lists both kinds for `restore`, `refresh`, `upgrade` and `uninstall`.

The rules are the same chains as for a profile (`rules`, `health`, `layout`). What makes it locked is what is missing: `mcp_sets` fills only `allow_ports_v4/v6` and, for a list with names, the DNS sets. The lease sets stay empty because nothing can fill them: `record_of` refuses `PROFILE/SERVER`, so `open` and `close` fail, and sudoers has no rule for them. A server is reached over stdio through `docker run -i`, so no traffic has to enter the network.

The allow list is `[[mcp]]` in `config.toml` (root-owned), and every entry must name ports (`mcp_servers_config`). For a server without one, `mcp_ask_allow` asks on the terminal, before the global lock, so `/firewall` and the timer keep working while a person types; without a terminal `mcp add` explains how to write the list. `mcp_save_allow` appends the table to `config.toml` and first checks that the whole new file loads. `mcp_addresses` resolves names against the sandbox DNS servers and keeps every address seen in the last `MCP_ADDRESS_KEEP` seconds in `resolved.json`, because services rotate addresses and the container may get another answer than the firewall. A failed lookup keeps what is known; a name that never resolved allows nothing. So a lookup failure never blocks a refresh of the other firewalls, unlike `lan.hosts`, where a missing address would widen an Internet lease.

DNS: a list of only addresses gets `--dns=192.0.2.1` (`NO_DNS`, a documentation address) and no DNS rule. The option is needed: without `--dns`, Docker's embedded resolver answered from the host's side, past the table (seen live on Docker 29). Every failing `--dns` value makes a lookup take about 5 seconds; that is Docker's resolver, not the rules.

Subnets: `free_subnet` hands out a /28 from `mcp_subnet`, skipping what the registry, Docker networks and host routes use, because Docker's default pools only last for about 30 networks.

As the Hermes user: `_hermes mcp-scan PROFILE` reads `hermes config get mcp_servers --json --raw` and reports `{name, state, text}` for each server (`mcp_state`); root validates that report and only prints it (`mcp_report`). `_hermes mcp-attach` puts the own entries right after `run` (`own_mcp_args` finds them again) with `hermes config set mcp_servers.NAME.args JSON` and reads the value back. `config get` returns `${VAR}` already expanded (and masks secrets without `--raw`), so writing it back could put a secret into the file. Arguments are therefore only written when each of them is found literally in `config.yaml`; otherwise the state is `manual`: the network is created and the user gets a hint. `_hermes mcp-detach` replaces the entries with `--network=none`, so a server never ends up unfiltered. A server that still names a removed network fails to start.

`mcp_warnings` (at `add`, in `status` and `refresh`) reports Docker MCP servers without a firewall. It cannot enforce anything: whoever can use Docker can start containers elsewhere.

## status --proof

`prove(name, record, conf)` tests a firewall with real packets. A Docker network and its bridge exist whether or not a container runs, but something must send. `ProofEndpoint` is that sender: a process in its own network namespace (`unshare -n sleep 300`) with a veth pair on the bridge and an address from the top of the subnet (Docker hands out from the bottom; addresses in use are skipped). No image and no container are needed. The namespace lives only as long as the process, so a crash leaves at most a sleeping process for 5 minutes; a host-side link left over is deleted first on the next run. Packets take the path of a container's from the bridge on, which is also what `tests/netns.sh` relies on.

`proof_targets` chooses what to try and what the current state should do with it: public addresses, a LAN address (the router if it is in the LAN, never the host itself), the host, a DNS server, and for an MCP firewall each allowed target plus another port. Addresses on an allow list are avoided, since they would pass in any state.

`probe_verdict` decides from the reject counters, read before and after each attempt with `reject_count`, because a refused connection could also come from the target. Only the matching rules count: outbound rejects for targets outside, `host_input_guard` for the host, and per protocol. A new interface sends IPv6 multicast to the host by itself, which `host_input_guard` refuses too; counting everything made passed attempts look blocked. Another container on the same bridge could still raise a counter at that moment: a connection that was answered always counts as passed, and only a refusal by the target at the same moment could be misread.

It finds what `health` cannot see: `health` compares the rule structure, not the contents of the sets or the real packet path. A failed proof makes `status` fail; an endpoint that cannot be set up is reported as not tested. `sudoers` allows `status P` with no arguments, so `--proof` needs a full sudo.

## Plugin and sudoers

`plugin/hermes-firewall/__init__.py` registers the slash command `/firewall` (not a tool, so the model cannot call it). It finds its profile from `HERMES_HOME` (`hermes_cli.profiles.get_active_profile_name`) and runs `sudo -n /usr/local/bin/hermes-firewall open|close|status PROFILE ...`. What the model learns depends on three plugin settings (`ctx.get_config`, checked at use). `prompt_rule` (default on) is a frozen section (`register_system_prompt_section`, skipped on Hermes versions without it): the rule without any state, rendered once per new session and cached with the prompt; off, it renders empty and Hermes adds nothing. `status_line` (default off) is a `pre_llm_call` hook: one line per user message with the current state, which Hermes stores with that message and replays unchanged, so the cache prefix stays stable and the lines stay in the history until compaction. It reads `/run/hermes-firewall/PROFILE.json` without sudo, so a turn costs no sudo call and no journal line. `write_state()` writes that file (end times per kind, `null` = closed) after every lease change, at `add`, `restore` and `upgrade` and on every refresh; the plugin compares the end times with the clock, so an expired lease reads as closed without a new file. The kernel decides, the file only reports: a failed write only warns and the next refresh repairs it. `agent_notice` (default off) registers a `transform_terminal_output` hook: only for a Docker sandbox command that failed (`returncode` != 0) with a typical network error (curl exit 6/7/28/35/56, wget exit 4, resolver/connect/timeout messages of curl, wget, git, pip, npm, apt) it asks `status PROFILE` and, if a lease is closed, appends one line naming the closed kinds and `/firewall open`. Off, it returns before any work; it never touches successful or other output. `write_sudoers()` generates one NOPASSWD line per protected profile with exactly `open P`, `open P *`, `close P`, `close P *` and `status P`, validated with `visudo -cf`. Because of the wildcards, `open` and `close` accept no options at all (`parse`). Whatever follows `open P` / `close P` must be a valid lease request or fail before anything changes (`tests/test_firewall.py`, `SudoArgumentFuzzTests`). `replaceable_by_others()` checks that nobody but root can replace `/usr/local/bin/hermes-firewall` or a directory above it (`install`, `upgrade`, `status`).

## Boot, install, upgrade

- `hermes-firewall.service` (oneshot, `RemainAfterExit`, no `ExecStop`) runs `restore`; ordered after nftables/firewalld/ufw and before Docker. The Docker drop-in (`docker_requires_firewall = true`) makes Docker fail closed if it fails. The refresh timer does not depend on the service, so it also repairs a failed boot restore.
- `install.sh` copies the files to a private temporary directory and runs `hermes_firewall.py --bundle=DIR install` (or `upgrade` if `profiles.json` exists). `install` must not start the service itself (its ExecStart would wait for the lock); `install.sh` starts it afterwards.
- `upgrade` writes program, plugin source, units and sudoers, reloads all tables only if `health()` fails (rule layout changed: all leases close), otherwise refreshes, and re-attaches every profile (new plugin, DNS).
- `uninstall` refuses while profiles, MCP firewalls, package networks or tables exist; keeps `config.toml` unless `--purge`.

## Known limits

MCP servers from Hermes plugins are not in `mcp_servers` and stay unseen by `mcp scan`; MCP servers over HTTP are not covered. Lease timeouts do not run while the host is suspended (kernel timers); until the next refresh after a resume, the status line may call a lease closed that still runs. NAT64 prefixes other than /96 and prefixes announced only by the router (PREF64) are not detected. LAN parts that are not directly connected (e.g. other /64s of a delegated prefix) and router hairpin NAT must be configured. After `flush ruleset` by another tool, sandboxes are unfiltered until the next refresh (at most 5 minutes). Profile names are global per host (one registry), even with several Hermes users.

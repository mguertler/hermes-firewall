# hermes-firewall

A firewall for the Docker sandboxes of [Hermes Agent](https://github.com/NousResearch/hermes-agent):
every Hermes profile gets its own sandbox network that is **closed** by default and after
every reboot. You open it when the agent needs it, for a limited time, and the Linux
kernel closes it again on its own.

```text
$ sudo hermes-firewall open default for 30m
default: firewall active, Internet open for 30m (until 14:23), LAN closed
```

Or right in a Hermes chat:

```text
/firewall open lan 2h
/firewall close
/firewall status
```

- **Closed on boot**: a reboot closes everything; leases are never stored.
- **Time limits in the kernel** (nftables set timeouts): nothing to forget, no daemon.
- **Internet and LAN separately**: an Internet lease never opens your LAN, and vice versa.
- **Per profile**: profiles have independent networks and leases.
- **IPv4 and IPv6** (including NAT64), nothing else.
- **Small**: one Python file (standard library only) plus a tiny Hermes plugin.

## Requirements

Linux with systemd, nftables (kernel 5.6 or newer), the local rootful Docker and
Python 3.11 or newer. Tested distributions: see [TESTING.md](TESTING.md); intended
for Debian/Ubuntu, Fedora/RHEL, Arch and openSUSE. Hermes Agent with the Docker
terminal backend (`terminal.backend: docker`).

## Install

```bash
git clone https://github.com/mguertler/hermes-firewall.git
cd hermes-firewall
sudo ./install.sh                  # running it again later upgrades
```

Then, as the user who runs Hermes, protect a profile (`default` is the profile in `~/.hermes`):

```bash
sudo hermes-firewall add default
```

`add` connects the profile's sandbox to its firewall network, installs the `/firewall`
command into that profile and allows it to open and close exactly this profile's
firewall (`/etc/sudoers.d/hermes-firewall`). Restart the Hermes gateway if you use one
(`hermes -p default gateway restart`) and start a new session.

## Usage

```text
sudo hermes-firewall add PROFILE                    protect a profile (everything closed)
sudo hermes-firewall open PROFILE [for] [internet|lan|all] [DURATION]
sudo hermes-firewall close PROFILE [internet|lan|all]
sudo hermes-firewall status [PROFILE]
sudo hermes-firewall remove PROFILE                 remove the firewall; the sandbox then has no network
```

`open PROFILE` opens the Internet for 1 hour. Kind and duration can come in any order:
`open default lan 30m`, `open default for 2h`, `open default all 1h`. The longest lease
is 24 hours (or less, see `lease.max` below). Opening again restarts the time.
`close PROFILE` closes everything.

In a chat of a protected profile, `/firewall` does the same for that profile:
`/firewall open`, `/firewall open lan 30m`, `/firewall close`, `/firewall status`.

### What a sandbox can reach

| Lease      | LAN | Internet | DNS servers | `[[allow]]` list | the host itself |
|------------|-----|----------|-------------|------------------|-----------------|
| none       | no  | no       | yes         | yes              | no              |
| `lan`      | yes | no       | yes         | yes              | no              |
| `internet` | no  | yes      | yes         | yes              | no              |
| `all`      | yes | yes      | yes         | yes              | no              |

The only exception for the host: the Hermes egress proxy (iron-proxy), if it runs.

## Settings

`/etc/hermes-firewall/config.toml` is written once by the installer (with the DNS
servers it found) and never overwritten by upgrades. After changing it run
`sudo hermes-firewall refresh` (it happens every 5 minutes anyway; open leases stay open).
All settings, with comments: [config.example.toml](config.example.toml).

```toml
[lease]
default = "1h"
max = "24h"

[sandbox]
dns = ["192.168.0.5"]           # always reachable, port 53 only

[lan]
networks = ["auto"]             # = the networks this host is connected to
hosts = ["nas.example.org"]     # their current addresses count as LAN too

[[allow]]                       # always reachable; without tcp/udp: all ports
net = "192.168.0.2"
tcp = [8088]
```

## Things to know

- **Only the sandbox is filtered.** Hermes itself, its gateway, MCP servers and plugins
  run on the host and are not affected.
- **DNS is always open** to the configured servers, so names resolve while closed. Code
  in a closed sandbox could leak small amounts of data through DNS queries to them.
- **`/firewall` and sudo**: the sudoers rule lets *any* process of the Hermes user open
  leases for its profiles. The model cannot call slash commands, but a tool or MCP
  server that runs shell commands on the host could. Keep that in mind when you give
  Hermes host-side tools.
- **Existing sandboxes** of a profile are moved into its firewall automatically (by `add`,
  `status` and every 5 minutes). A sandbox that cannot be moved, for example one using
  the host's network, has to be reset; `sudo hermes-firewall add PROFILE` explains what is
  kept and what is lost and asks first.
- hermes-firewall never changes `container_persistent`, `docker_shared_container_key`,
  `cwd` or other sandbox settings; it only sets `docker_network` and its own `--network=`
  and `--dns=` entries in `docker_extra_args`. Profiles that share one sandbox
  (`docker_shared_container_key`) cannot be protected.
- With `docker_requires_firewall = true` (default) Docker does not start at all if the
  firewall cannot be loaded at boot. If `nftables.service` uses `flush ruleset` and is
  restarted later, the firewall is restored (closed) within 5 minutes.
- IP based, not a domain allow list.

## Uninstall

```bash
sudo hermes-firewall remove PROFILE      # for every protected profile
sudo ./uninstall.sh                      # keeps config.toml; --purge removes it too
```

## License

Apache License 2.0, see [LICENSE](LICENSE). Developer documentation:
[ARCHITECTURE.md](ARCHITECTURE.md), [INVARIANTS.md](INVARIANTS.md),
[FUNCTIONS.md](FUNCTIONS.md), [TESTING.md](TESTING.md).

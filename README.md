# hermes-firewall

A firewall for the Docker sandboxes of [Hermes Agent](https://github.com/NousResearch/hermes-agent): every Hermes profile gets its own sandbox network that is **closed** by default and after every reboot. You open it when the agent needs it, for a limited time, and the Linux kernel closes it again on its own.

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

Linux with systemd, nftables (kernel 5.6 or newer), the local rootful Docker and Python 3.11 or newer; Hermes Agent with the Docker terminal backend (`terminal.backend: docker`). Checked on Debian 12 and 13, Ubuntu 24.04, Fedora 42, Arch Linux and openSUSE Tumbleweed; tested live on Debian 13 with Hermes Agent 0.22.5 (details: [TESTING.md](TESTING.md)).

IPv6 for sandboxes needs Docker 27 or newer (or `"ip6tables": true` with `"experimental": true` in `/etc/docker/daemon.json` on Docker 26, as in Debian 13); otherwise sandboxes get IPv4 only.

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

`add` connects the profile's sandbox to its firewall network, installs the `/firewall` command into that profile and allows it to open and close exactly this profile's firewall (`/etc/sudoers.d/hermes-firewall`). Running Hermes processes load plugins only when they start: restart the gateway (`hermes -p default gateway restart`, for Telegram, Discord, ...) and the backend of the desktop app (`hermes -p default dashboard --stop`, then start it again), then start a new chat.

### What the agent is told

Three settings per profile decide what the model learns about the firewall. Set them like this:

```bash
hermes -p default config set plugins.entries.hermes-firewall.settings.prompt_rule false
hermes -p default config set plugins.entries.hermes-firewall.settings.status_line true
hermes -p default config set plugins.entries.hermes-firewall.settings.agent_notice true
```

| Setting | Default | What the model gets | Cost |
|---|---|---|---|
| `prompt_rule` | on | The rule in the frozen part of the system prompt of new sessions: there is a firewall, an immediate refusal usually means it is closed, only the user can open it. Never says whether it is open or closed, so it cannot go stale. | One short paragraph, once per session, cached with the prompt |
| `status_line` | off | The current state as one line on every user message, e.g. `Internet closed, LAN open for 41m`. | About 15 tokens per message; the lines stay in the history until compaction |
| `agent_notice` | off | One line on a command that failed with a network error while the firewall is closed. | Only when that happens |

`prompt_rule` needs Hermes 0.22.5 or newer and applies to new sessions; on older versions it is left out. `status_line` reads `/run/hermes-firewall/PROFILE.json` without sudo; this file only reports what the kernel enforces. It is refreshed on every `open` and `close` and by the 5-minute timer, and a lease that runs out reads as closed without a new file. The model can never open anything, whatever these settings say.

`status_line` and `agent_notice` take effect without a restart once the plugin is loaded.

## Usage

```text
sudo hermes-firewall add PROFILE                    protect a profile (everything closed)
sudo hermes-firewall open PROFILE [for] [internet|lan|all] [DURATION]
sudo hermes-firewall close PROFILE [internet|lan|all]
sudo hermes-firewall status [PROFILE]
sudo hermes-firewall remove PROFILE                 remove the firewall; the sandbox then has no network
```

`open PROFILE` opens the Internet for 1 hour. Kind and duration can come in any order: `open default lan 30m`, `open default for 2h`, `open default all 1h`. The longest lease is 24 hours (or less, see `lease.max` below). Opening again restarts the time. `close PROFILE` closes everything.

In a chat of a protected profile, `/firewall` does the same for that profile: `/firewall open`, `/firewall open lan 30m`, `/firewall close`, `/firewall status`. It works when typed on every platform and shows up in the desktop app's command search and Telegram's inline search (`@yourbot firewall`). Hermes' `/help` and `/commands` list only built-in and skill commands, no plugin commands. Telegram's `/` menu holds only 60 commands and Hermes' own fill it; to list `/firewall` there too: `hermes -p PROFILE config set platforms.telegram.extra.command_menu.priority '["firewall"]'` and restart the gateway.

### What a sandbox can reach

| Lease      | LAN | Internet | DNS servers | `[[allow]]` list | the host itself |
|------------|-----|----------|-------------|------------------|-----------------|
| none       | no  | no       | yes         | yes              | no              |
| `lan`      | yes | no       | yes         | yes              | no              |
| `internet` | no  | yes      | yes         | yes              | no              |
| `all`      | yes | yes      | yes         | yes              | no              |

Blocked connections fail at once instead of timing out: TCP connections are refused (`Connection refused`), everything else gets an ICMP "administratively prohibited" (`No route to host`). When a lease expires, open connections are reset. Traffic from outside to a sandbox is still dropped silently.

The only exception for the host: the Hermes egress proxy (iron-proxy), if it runs. It runs on the host, outside the firewall, so in every state sandboxes reach what iron-proxy itself allows (its allow list of AI provider APIs). To combine both, Hermes must accept the firewall network: `hermes -p PROFILE config set proxy.enforce_on_docker false` (`add` says so; the proxy keeps protecting your API keys).

## MCP servers in Docker

The sandbox firewall does not cover MCP servers: Hermes starts them on the host, so a container started with `docker run` has the open network of any other container, whatever the sandbox's state. `hermes-firewall mcp` gives such a server a network of its own that is locked for good: no leases, no `/firewall`, only the targets and ports in its allow list.

```text
sudo hermes-firewall mcp scan PROFILE               what the profile's MCP servers can reach
sudo hermes-firewall mcp add PROFILE SERVER         lock a server to its allow list
sudo hermes-firewall mcp remove PROFILE SERVER      remove its firewall; the server then has no network
```

The allow list is in the root-owned `/etc/hermes-firewall/config.toml`, not in the Hermes configuration, and every target names its ports:

```toml
[[mcp]]
profile = "default"
server = "github"
allow = [{ host = "api.github.com", tcp = [443] }, { net = "140.82.112.0/20", tcp = [443] }]

[[mcp]]
profile = "default"
server = "filesystem"
allow = []                      # reaches nothing at all
```

`mcp add` creates the network and puts `--network=hermes-mcp-PROFILE-SERVER` and `--dns=...` right after `run` in the server's `args`; everything else stays as it is. It applies when the server starts again: `/reload-mcp` in the chat, or restart the gateway. Changes to an allow list reach the firewall within 5 minutes (or with `sudo hermes-firewall refresh`).

What `mcp scan` finds and what happens to it:

| The server in the Hermes configuration | `mcp add` |
|---|---|
| `command: docker`, `args: [run, ...]` | Sets it up completely |
| Its `args` use `${VAR}`, or it starts Docker another way (`docker compose`, a shell, Podman) | Creates the network and tells you what to add yourself, because Hermes hands out `${VAR}` already expanded and writing that back would put secrets into the file |
| `--network=...` of its own, `--privileged`, `docker.sock`, `DOCKER_HOST` | Refuses and says why |
| `url:` (HTTP), or a command that runs on the host (`npx`, `uvx`, ...) | Refuses: no container for this firewall to lock |

Limits you should know:

- It is not enforced. Anyone who can use Docker can start a container without this network, so it protects against a compromised MCP server, not against the Hermes user. `status` and the 5-minute timer warn about Docker MCP servers without a firewall, in the journal for the timer.
- MCP servers from Hermes plugins are not in `mcp_servers`, so `mcp scan` does not see them. A server of the same name in `mcp_servers` takes their place, and that one can be locked.
- Names are only as exact as IP addresses. The firewall opens the addresses a name resolves to (all seen in the last 24 hours, checked every 5 minutes), which on a CDN also reaches other services on the same address. A brand-new address is refused until the next check.
- A server with a name in its list also gets DNS, so it could leak small amounts of data through DNS queries. A list of only addresses gets no DNS at all, and a lookup there fails after about 5 seconds, so use addresses in that server's own settings.
- The host itself stays blocked, even if its address is in the list.

## Settings

`/etc/hermes-firewall/config.toml` is written once by the installer (with the DNS servers it found) and never overwritten by upgrades. After changing it run `sudo hermes-firewall refresh` (it happens every 5 minutes anyway; open leases stay open). All settings, with comments: [config.example.toml](config.example.toml).

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

- **Only the sandbox is filtered.** Hermes itself, its gateway, MCP servers and plugins run on the host and are not affected.
- **DNS is always open** to the configured servers, so names resolve while closed. Code in a closed sandbox could leak small amounts of data through DNS queries to them.
- **`/firewall` and sudo**: the sudoers rule lets *any* process of the Hermes user open leases for its profiles. The model cannot call slash commands, but a tool or MCP server that runs shell commands on the host could. Keep that in mind when you give Hermes host-side tools. sudo logs every call: `journalctl -t sudo | grep hermes-firewall` shows who opened or closed what, and when.
- **Existing sandboxes** of a profile are moved into its firewall automatically (by `add`, `status` and every 5 minutes). A sandbox that cannot be moved, for example one using the host's network, has to be reset; `sudo hermes-firewall add PROFILE` explains what is kept and what is lost and asks first.
- hermes-firewall never changes `container_persistent`, `docker_shared_container_key`, `cwd` or other sandbox settings; it only sets `docker_network` and its own `--network=` and `--dns=` entries in `docker_extra_args`. Profiles that share one sandbox (`docker_shared_container_key`) cannot be protected.
- With `docker_requires_firewall = true` (default) Docker does not start at all if the firewall cannot be loaded at boot. If `nftables.service` uses `flush ruleset` and is restarted later, the firewall is restored (closed) within 5 minutes; until then the sandboxes are not filtered.
- Settings like `--privileged` or a mounted `docker.sock` let code escape the sandbox; `add` warns about them, but no firewall can contain an escaped process.
- LAN detection (`"auto"`) sees the networks the host is directly connected to. Add other parts of your LAN yourself, e.g. the rest of a delegated IPv6 prefix. If your router forwards ports from its public address into the LAN (hairpin NAT), add the router's public name to `lan.hosts`. NAT64 is handled for `64:ff9b::/96` and for /96 prefixes announced by your DNS64 server.
- Profile names are unique per host: if several users run Hermes on one host, give their profiles different names.
- Lease times do not run while the host is suspended.
- IP based, not a domain allow list.

## Uninstall

```bash
sudo hermes-firewall remove PROFILE      # for every protected profile
sudo ./uninstall.sh                      # keeps config.toml; --purge removes it too
```

## License

Apache License 2.0, see [LICENSE](LICENSE). Developer documentation: [ARCHITECTURE.md](ARCHITECTURE.md), [INVARIANTS.md](INVARIANTS.md), [FUNCTIONS.md](FUNCTIONS.md), [TESTING.md](TESTING.md).

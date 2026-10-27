# Invariants

These must stay true. Change them only deliberately, together with tests and docs.

## Security

- Default closed. A boot or `restore` closes all leases; leases are never persisted; the time limit is enforced by the kernel (nft set timeouts), never by a process.
- An Internet lease never opens the LAN (`lan_v4/v6`, including public addresses of LAN hosts and NAT64-embedded LAN addresses). A LAN lease opens only the LAN.
- In every state only the configured DNS servers (port 53) and the `[[allow]]` entries are reachable. A name that does not resolve never widens what a lease opens: strict resolution, or the last known addresses at boot. LAN networks in the configuration must be private (IPv4) or ULA / prefixes of /48 or longer (IPv6), so a typo cannot turn "lan" into Internet.
- The host itself is never reachable from a sandbox, except IPv6 neighbour discovery and the egress-proxy ports of the profile's own user.
- IPv4 and IPv6 are filtered the same way. Addresses that embed IPv4 (NAT64, 6to4, Teredo) must never bypass the IPv4 rules.
- Fail closed, never open: no automatic fallback to unfiltered networking, a different Docker daemon or a disabled firewall. A failed step leaves things closed.
- Protection first: the table exists before the Docker network; the network is removed before the table. Detach leaves a sandbox with NO network, never an unfiltered one.
- `bash tests/netns.sh` must pass after any rule change.

## Scope of changes

- Never flush the global ruleset, touch other tables (Docker's, firewalld's, ...), or stop/restart Docker. Only this package's tables, networks, files and units.
- Profiles are independent: adding or removing one never changes another's leases.
- Root never edits Hermes files. Only `_hermes info|attach|detach`, run as the Hermes user, changes a profile, and only through the Hermes CLI. Root never trusts what that process prints: it validates the answer, computes container labels itself, strips control characters and gives the process no terminal (no stdin, new session).
- Sandboxes of one protected profile are never moved into another's network; two protected profiles never share a container label.
- In a Hermes profile only `terminal.docker_network` and the own `--network=` / `--dns=` entries of `terminal.docker_extra_args` are set, plus the plugin directory. Never `container_persistent`, `docker_shared_container_key`, `cwd`, `backend` or other settings: for those, only hints.
- Sandboxes are moved (restricting only) without asking; a sandbox is removed (reset) only after confirmation on a terminal or `add --yes`, and only containers carrying the profile's Hermes labels.
- Files are removed only when known to be ours: plugin files by name, no recursive deletion; `uninstall` refuses unknown files and remaining networks/tables.
- The model never gets a way to open the firewall: `/firewall` is a slash command (user only), no tool. The optional agent notice (`agent_notice`, off by default) only adds one line to the output of a sandbox command that failed with a network error while a lease is closed; never to the prompt or to other output.
- sudoers allows exactly `open`, `close` and `status` of protected profiles. Those verbs accept no options. `visudo -cf` validates every sudoers file before it is installed.

## Usability

- Users think in profiles, Internet, LAN, open/closed and time left. Network, bridge, table and container names belong in `--verbose` and errors, not in normal output.
- A message says what is going on and what to do, in at most two lines.
- `open PROFILE` alone means Internet for `lease.default` (1h); kind and duration may come in any order, `for` is optional; `close PROFILE` closes everything.
- The installer writes `config.toml` once; upgrades never overwrite it.

## Code

- One program file, Python >= 3.11 standard library only; LF line endings; executable bits on the program and shell scripts.
- No credentials, host names or personal data in the repository.

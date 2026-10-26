# Functions

Index of `hermes_firewall.py` (in file order) and the plugin. Keep it in sync when
functions are added, removed or change their job. Architecture: [ARCHITECTURE.md](ARCHITECTURE.md).

## Input

| Function | Job |
|---|---|
| `require(condition, message)` | Raise `FirewallError(message)` unless `condition`. |
| `identity(profile)` | Validate a profile name; bridge, network, table and IPv6 subnet derived from it. |
| `duration(value)` | `30s`/`10m`/`2h` -> seconds, at most 24h. |
| `lease_kinds(word)` | `internet`/`lan`/`all` -> tuple of kinds. |
| `open_arguments(words, conf)` | `[for] [kind] [duration]` in any order -> (kinds, seconds) with defaults and `lease.max`. |

## Configuration

| Function | Job |
|---|---|
| `lan_network(text)` | Validate one LAN network (private IPv4, IPv6 ULA or global prefix >= /48). |
| `ports(entry, key)` | Validate the `tcp`/`udp` port list of an `[[allow]]` entry. |
| `load_config(path)` | Read and validate `config.toml` -> normalized dict. |
| `detected_dns(files)` | Upstream DNS servers of the host (skips loopback, follows systemd-resolved). |
| `config_text(example, dns)` | Example configuration with the detected DNS servers filled in. |

## Addresses

| Function | Job |
|---|---|
| `family(address)` | 4 or 6. |
| `unique(items)` | Remove duplicates, keep order. |
| `nat64(prefixes, networks)` | IPv4 networks as seen through NAT64 /96 prefixes. |
| `dns_query(name, qtype)` / `dns_answer(...)` / `skip_name(...)` | Minimal DNS client: build a query, parse A/AAAA answers (CNAME chains, compression). |
| `resolve(host, servers, qtype)` | Ask the sandbox DNS servers (UDP, IPv4 or IPv6). |
| `resolve_host(host, servers)` | A + AAAA of a LAN host name. |
| `nat64_prefixes(servers)` | Well-known NAT64 prefix plus DNS64-announced ones (`ipv4only.arpa`). |
| `host_networks()` | Networks the host is directly connected to (for `lan.networks = ["auto"]`). |
| `docker_gateway()` | IPv4 address of docker0 (`host.docker.internal`). |
| `proxy_ports(conf)` | `{uid: [elements]}` of iron-proxy listeners on docker0. |
| `common_sets(conf, strict)` | Set elements shared by all profiles; `strict` fails on unresolvable hosts. |
| `profile_sets(record, common, proxies)` | Add the egress-proxy ports of the profile's user. |

## nftables

| Function | Job |
|---|---|
| `elements(items)` | `elements = { ... }` or nothing. |
| `rules(profile, sets)` | The whole table of a profile (closed). |
| `chain_rules(text)` | `{chain: [rules]}` of a table text; used by `health` and tests. |
| `lease_transaction(profile, kinds, seconds)` | Open (with seconds) or close leases. |
| `refresh_transaction(data, sets)` | Replace all address sets of all tables; leases untouched. |
| `all_sets(data, strict)` | `{profile: sets}` for all protected profiles. |
| `restore_transaction(data)` | All tables, closed (boot). |

## State and system

| Function | Job |
|---|---|
| `trusted(path)` | Refuse symlinks and files not owned by root or writable by others. |
| `validate_registry(data)` / `load_registry()` / `save_registry(data)` | Registry `profiles.json`. |
| `atomic_write(path, data, mode)` | Write via temporary file, fsync, rename. |
| `run(*arguments)` | Run a system command with a fixed environment; raise on failure. |
| `nft_apply(text)` | `nft --check`, then apply. |
| `docker_ready()` | Local rootful Linux Docker is running. |
| `networks()` / `interface_exists(name)` / `table_names()` | Docker networks, links, nft tables. |
| `check_network(profile, record)` | The profile network is ours and configured as expected. |
| `health(profile)` | Hooks, priorities and rule counts of a table match `rules()`. |
| `set_elements(profile, name)` | Current elements of a set (for `--verbose`). |
| `lease_remaining(profile, kind)` | Seconds left or `None` (closed). |

## Wording

| Function | Job |
|---|---|
| `left(seconds)` | `30s`, `41m`, `2h 03m`. |
| `lease_state(seconds)` | `closed` or `open for 41m (until 14:32)`. |
| `profile_line(profile)` | `research: firewall active, Internet ..., LAN ...`. |
| `always_text(conf)` | What is reachable in every state. |

## Hermes (as the Hermes user)

| Function | Job |
|---|---|
| `hermes_home(home, profile)` | `~/.hermes` or `~/.hermes/profiles/P`. |
| `hermes_profiles(user)` | Profiles of a user (incl. `default`). |
| `hermes(*arguments)` | Run the Hermes CLI. |
| `terminal_settings(profile)` | `hermes -p P config get terminal --json`. |
| `container_label(profile, settings)` | The `hermes-profile` label Hermes gives the profile's containers. |
| `firewall_arg(argument)` | Is it an own `--network=`/`--net=`/`--dns=` entry? Refuses split `--network VALUE`. |
| `hermes_info(profile)` | Checks (Docker backend, no shared sandbox), label and hints. |
| `install_plugin(profile)` / `remove_plugin_files(target)` | Plugin into/out of a profile, own files only. |
| `hermes_attach(profile, dns)` / `hermes_detach(profile)` | Connect the profile to its firewall / leave it without network. |
| `user_command(words)` | Internal `_hermes info|attach|detach PROFILE`; refuses root. |
| `hermes_user()` | The user behind sudo. |
| `as_user(user, *arguments)` | Root runs `_hermes ...` as that user (`runuser -l`). |

## Sandboxes and sudoers

| Function | Job |
|---|---|
| `sandboxes(label)` | `docker inspect` of the profile's Hermes containers. |
| `kept_text(container)` | What a reset keeps and loses. |
| `protect_sandboxes(profile, record, conf, interactive, yes)` | Move sandboxes into the firewall; reset (asked) or report the rest. |
| `sudoers_text(data)` / `write_sudoers(data)` | Generate, validate (`visudo -cf`) and install the sudoers file. |

## Commands

| Function | Job |
|---|---|
| `record_of(data, profile)` | Registry entry or a "not protected" error. |
| `ipv6_enabled(conf)` | `ipv6` setting; `auto` = the host has an IPv6 default route. |
| `create_firewall(...)` / `create_network(...)` | Table first (registry persisted), then the Docker network. |
| `add_profile(data, profile, user, yes)` | `add`. |
| `remove_profile(data, profile)` | `remove`. |
| `open_lease(...)` / `close_lease(...)` | `open` / `close`. |
| `status(data, user, selected, verbose)` | `status`. |
| `refresh(data)` | Timer job. |

## Installation

| Function | Job |
|---|---|
| `flush_warnings()` | Warn about `flush ruleset` in nftables.conf and a missing sudoers.d include. |
| `write_program(bundle)` | Program and plugin source. |
| `write_units(conf)` | Units and Docker drop-in as configured. |
| `install(bundle)` / `upgrade(bundle)` / `uninstall(data, purge)` | Package lifecycle. |
| `parse(argv)` | Words and options; options only where allowed. |
| `main(argv)` | Dispatch under the global lock. |

## Plugin (`plugin/hermes-firewall/__init__.py`)

| Function | Job |
|---|---|
| `profile_name()` | This gateway's profile from `HERMES_HOME`. |
| `handle(raw_args)` | `/firewall open|close|status ...` -> `sudo -n hermes-firewall VERB PROFILE ...`. |
| `register(ctx)` | Registers the slash command `/firewall`. |

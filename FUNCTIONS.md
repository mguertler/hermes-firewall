# Functions

Index of `hermes_firewall.py` (in file order) and the plugin. Keep it in sync when functions are added, removed or change their job. Architecture: [ARCHITECTURE.md](ARCHITECTURE.md).

## Input

| Function | Job |
|---|---|
| `require(condition, message)` | Raise `FirewallError(message)` unless `condition`. |
| `identity(name)` | Validate a profile name or `PROFILE/SERVER`; bridge, network, table and IPv6 subnet derived from it. |
| `duration(value)` | `30s`/`10m`/`2h` -> seconds, at most 24h. |
| `lease_kinds(word)` | `internet`/`lan`/`all` -> tuple of kinds. |
| `open_arguments(words, conf)` | `[for] [kind] [duration]` in any order -> (kinds, seconds) with defaults and `lease.max`. |

## Configuration

| Function | Job |
|---|---|
| `lan_network(text)` | Validate one LAN network (private IPv4, IPv6 ULA or global prefix >= /48). |
| `ports(entry, key)` | Validate the `tcp`/`udp` port list of an `[[allow]]` entry. |
| `load_config(path)` | Read and validate `config.toml` -> normalized dict. |
| `mcp_subnet(text)` | Validate the range MCP firewalls take their /28 from. |
| `mcp_servers_config(entries, path)` | `[[mcp]]` tables -> `{"PROFILE/SERVER": allow list}`; every target names its ports. |
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
| `host_networks()` | Networks the host is directly connected to: addresses and on-link routes (for `lan.networks = ["auto"]`). |
| `docker_gateway()` | IPv4 address of docker0 (`host.docker.internal`). |
| `proxy_ports(conf)` | `{uid: [elements]}` of iron-proxy listeners on docker0. |
| `load_cache()` | Last resolved `lan.hosts` addresses and DNS64 prefixes (`resolved.json`). |
| `common_sets(conf, strict)` | Set elements shared by all profiles; `strict` fails on unresolvable names, otherwise the cache is used; collapses overlapping `[[allow]]` networks. |
| `service_sets(allow)` | `allow_ports_v4/v6` of entries with ports, overlapping networks collapsed. |
| `mcp_dns(conf, key)` | DNS servers of an MCP container: the real ones only if its list has names, else `NO_DNS`. |
| `mcp_addresses(conf)` | Addresses of allow-list names: all seen recently, kept in `resolved.json`. |
| `mcp_sets(conf, key, addresses)` | Set elements of an MCP firewall: only its list, and DNS only for names. |
| `free_subnet(data, conf)` | First /28 of `mcp_subnet` nothing else uses. |
| `profile_sets(record, common, proxies)` | Add the egress-proxy ports of the profile's user. |

## nftables

| Function | Job |
|---|---|
| `chains(bridge)` | The four chains of a profile table (rule layout without set contents). |
| `layout(bridge)` | Fingerprint of that layout, stored in the table comment and checked by `health`. |
| `drop_table(table)` | Delete a table if it exists, in one transaction, with any nft version. |
| `elements(items)` | `elements = { ... }` or nothing. |
| `rules(profile, sets)` | The whole table of a profile (closed). |
| `chain_rules(text)` | `{chain: [rules]}` of a table text; used by `health` and tests. |
| `lease_transaction(profile, kinds, seconds)` | Open (with seconds) or close leases. |
| `targets(data)` | All firewalls: protected profiles and MCP servers. |
| `refresh_transaction(data, sets)` | Replace all address sets of all tables; leases untouched. |
| `all_sets(data, strict)` | `{name: sets}` for all firewalls. |
| `restore_transaction(data)` | All tables, closed (boot). |

## State and system

| Function | Job |
|---|---|
| `trusted(path)` | Refuse symlinks and files not owned by root or writable by others. |
| `replaceable_by_others(path)` | Path and parents a non-root user could change (owner, write bits, symlink). |
| `require_safe_program()` | Refuse when the password-less sudo program could be replaced. |
| `validate_registry(data)` / `load_registry()` / `save_registry(data)` | Registry `profiles.json`. |
| `atomic_write(path, data, mode)` | Write via temporary file, fsync, rename. |
| `run(*arguments, input, check, session)` | Run a system command with a fixed environment and no stdin; raise on failure. |
| `nft_apply(text)` | `nft --check`, then apply. |
| `docker_ready()` | Local rootful Linux Docker is running. |
| `networks()` / `interface_exists(name)` / `table_names()` | Docker networks, links, nft tables. |
| `check_network(profile, record)` | The profile network is ours and configured as expected. |
| `health(profile)` | Hooks, priorities and rule counts of a table match `rules()`. |
| `set_elements(profile, name)` | Current elements of a set (for `--verbose`). |
| `lease_remaining(profile, kind)` | Seconds left or `None` (closed). |
| `write_state(profile)` | Lease end times to `/run/hermes-firewall/PROFILE.json` for the status line; a failure only warns. |

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
| `config_section(profile, section)` | `hermes -p P config get SECTION --json`. |
| `terminal_settings(profile)` | The `terminal` section. |
| `egress_enforced(profile)` | Hermes egress proxy enabled with `enforce_on_docker` (refuses `--network=`)? |
| `container_label(profile, key)` | The `hermes-profile` label Hermes gives the profile's containers. |
| `firewall_arg(argument)` | Is it an own `--network=`/`--net=`/`--dns=` entry? Refuses split `--network VALUE`. |
| `hermes_info(profile)` | Checks (Docker backend, no shared sandbox), shared key and hints (incl. sandbox escapes). |
| `install_plugin(profile)` / `remove_plugin_files(target)` | Plugin into/out of a profile, own files only. |
| `hermes_attach(profile, dns)` / `hermes_detach(profile)` | Connect the profile to its firewall / leave it without network. |
| `mcp_servers(profile)` | The `mcp_servers` section (`--raw`); `{}` if there is none. |
| `config_file_text(profile)` | `config.yaml` as it is on disk, to tell literal values from expanded ones. |
| `own_mcp_args(arguments)` | `docker run` arguments -> own entries right after `run`, and the rest. |
| `mcp_state(profile, name, entry, config_text)` | How a server stands to the firewall: state and the message for the user. |
| `hermes_mcp_scan(profile)` | Report of all MCP servers of the profile. |
| `set_mcp_args(profile, server, wanted)` | Write the server's `args` and read them back. |
| `hermes_mcp_attach(profile, server)` / `hermes_mcp_detach(profile, server)` | Connect the server to its firewall / leave it without network. |
| `user_command(words)` | Internal `_hermes info|attach|detach|mcp-scan PROFILE`, `mcp-attach|mcp-detach PROFILE SERVER`; refuses root. |
| `hermes_user()` | The user behind sudo. |
| `printable(text)` | Strip terminal control characters from untrusted output. |
| `as_user(user, *arguments)` | Root runs `_hermes ...` as that user (`runuser -l`, new session, no stdin). |

## Sandboxes and sudoers

| Function | Job |
|---|---|
| `sandboxes(label)` | `docker inspect` of the profile's Hermes containers. |
| `kept_text(container)` | What a reset keeps and loses. |
| `protect_sandboxes(profile, record, conf, interactive, yes)` | Move sandboxes into the firewall; reset (asked) or report the rest. |
| `sudoers_text(data)` / `write_sudoers(data)` | Generate, validate (`visudo -cf`) and install the sudoers file. |

## MCP servers

| Function | Job |
|---|---|
| `mcp_report(user, profile)` | Report of `_hermes mcp-scan`, validated: its output is not trusted. |
| `mcp_warnings(profile, user)` | One line per Docker MCP server without a firewall. |
| `mcp_owners(data)` | `{profile: user}` of everything that can have MCP servers to check. |
| `allowed_text(conf, key)` | What an MCP server can reach, for the user. |
| `mcp_scan(profile, user)` / `mcp_add(data, profile, server, user)` / `mcp_remove(data, profile, server)` | The `mcp` commands. |

## Commands

| Function | Job |
|---|---|
| `record_of(data, profile)` | Registry entry or a "not protected" error; MCP firewalls have no leases. |
| `docker_nat66(daemon_json)` | Does Docker masquerade IPv6 (Docker >= 27 or `ip6tables` in daemon.json)? |
| `ipv6_enabled(conf)` | `ipv6` setting; `auto` = the host has an IPv6 default route and Docker NAT66. |
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
| `firewall(verb, profile, *words)` | `sudo -n hermes-firewall VERB PROFILE ...` with `LC_ALL=C`. |
| `handle(raw_args)` | `/firewall open|close|status ...` for this profile. |
| `network_failure(command, output, returncode)` | Did a command fail with a typical network error? |
| `lease_states(profile)` | Internet/LAN state from `status PROFILE`, or `None`. |
| `notice(states)` | The one line added for the model. |
| `make_output_hook(enabled)` | `transform_terminal_output` hook of the optional agent notice. |
| `lease_text(end, now)` | `closed` or `open for 41m` from an end time. |
| `status_line(profile)` | One line with the current state from the status file, or `None` if unknown. |
| `make_status_hook(enabled)` | `pre_llm_call` hook of the optional status line. |
| `register(ctx)` | Registers `/firewall`, the frozen rule (`RULE`) and the setting-gated hooks. |

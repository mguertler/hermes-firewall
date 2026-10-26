#!/usr/bin/python3 -I
"""Per-profile, boot-closed network leases for Hermes Agent Docker sandboxes.

Linux, systemd, nftables, rootful Docker; Python standard library only."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib

VERSION = "2.0.0"
CONF = Path("/etc/hermes-firewall")
REGISTRY = CONF / "profiles.json"
CONFIG = CONF / "config.toml"
EXE = Path("/usr/local/bin/hermes-firewall")
# Plugin source that `add` copies into a Hermes profile (as the Hermes user).
SHARE = Path("/usr/local/share/hermes-firewall")
PLUGIN = "hermes-firewall"
PLUGIN_FILES = ("plugin.yaml", "__init__.py")
UNIT = Path("/etc/systemd/system/hermes-firewall.service")
DROPIN = Path("/etc/systemd/system/docker.service.d/90-hermes-firewall.conf")
SERVICE = "hermes-firewall.service"
REFRESH_UNIT = Path("/etc/systemd/system/hermes-firewall-refresh.service")
REFRESH_TIMER = Path("/etc/systemd/system/hermes-firewall-refresh.timer")
SUDOERS = Path("/etc/sudoers.d/hermes-firewall")
LOCK = Path("/run/lock/hermes-firewall.lock")
KINDS = ("internet", "lan")
LABEL = "hermes-firewall.profile"
PROFILE_RE = r"[a-z0-9][a-z0-9_-]{0,63}"  # Hermes' own profile id rule
MAX_LEASE = 86400
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/root",
       "DOCKER_HOST": "unix:///var/run/docker.sock"}
NONPUBLIC_V4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
                "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
                "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
# 2002::/16 (6to4) and Teredo (in 2001::/23) can embed IPv4 addresses: blocked as a whole.
NONPUBLIC_V6 = ("::/127", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
                "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7",
                "fe80::/10", "fec0::/10", "ff00::/8")
# NAT64 well-known prefix; prefixes announced by DNS64 (RFC 7050) are added at runtime.
NAT64_WKP = "64:ff9b::/96"
# Interfaces whose networks never count as LAN for lan.networks = ["auto"].
VIRTUAL_INTERFACES = ("lo", "docker", "br-", "hfw", "veth", "virbr")

UNIT_TEXT = f"""[Unit]
Description=Hermes Agent sandbox firewall (closed on boot)
After=nftables.service firewalld.service ufw.service
Before=docker.service

[Service]
Type=oneshot
ExecStart={EXE} restore
RemainAfterExit=yes
# No ExecStop: stopping this service must not remove the rules.

[Install]
WantedBy=multi-user.target
"""
REFRESH_TEXT = f"""[Unit]
Description=Hermes Agent sandbox firewall: refresh addresses and protect sandboxes
After=hermes-firewall.service network-online.target
Requisite=hermes-firewall.service

[Service]
Type=oneshot
ExecStart={EXE} refresh
"""
TIMER_TEXT = """[Unit]
Description=Refresh the Hermes Agent sandbox firewall every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
"""
DROPIN_TEXT = """[Unit]
Requires=hermes-firewall.service
After=hermes-firewall.service
"""

# Address sets of every profile table: (name, nft type, flags). All are refreshed at runtime.
PREFIXES = " flags interval; auto-merge;"
SETS = (("lan_v4", "ipv4_addr", PREFIXES), ("lan_v6", "ipv6_addr", PREFIXES),
        ("dns_v4", "ipv4_addr", ""), ("dns_v6", "ipv6_addr", ""),
        ("allow_v4", "ipv4_addr", PREFIXES), ("allow_v6", "ipv6_addr", PREFIXES),
        ("allow_ports_v4", "ipv4_addr . inet_proto . inet_service", " flags interval;"),
        ("allow_ports_v6", "ipv6_addr . inet_proto . inet_service", " flags interval;"),
        ("non_public_v6", "ipv6_addr", PREFIXES),
        ("host_ports_v4", "ipv4_addr . inet_proto . inet_service", ""))


class FirewallError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise FirewallError(message)


def identity(profile):
    require(isinstance(profile, str) and re.fullmatch(PROFILE_RE, profile),
            f"Not a Hermes profile name: {profile!r} (lowercase letters, digits, '_' and '-').")
    digest = hashlib.sha256(profile.encode("ascii")).hexdigest()
    return {"bridge": "hfw" + digest[:12], "network": "hermes-fw-" + profile,
            "table": "hermes_fw_" + digest[:12],
            "subnet6": f"fd{digest[12:14]}:{digest[14:18]}:{digest[18:22]}::/64"}


DURATION_RE = r"([1-9][0-9]{0,4})(s|m|h)"


def duration(value):
    match = re.fullmatch(DURATION_RE, value)
    require(match, f"Not a duration: {value!r}. Use for example 30m or 2h.")
    seconds = int(match[1]) * {"s": 1, "m": 60, "h": 3600}[match[2]]
    require(seconds <= MAX_LEASE, "The longest lease is 24h.")
    return seconds


def lease_kinds(word):
    require(word in ("internet", "lan", "all"), f"Not a lease kind: {word!r}. Use internet, lan or all.")
    return KINDS if word == "all" else (word,)


def open_arguments(words, conf):
    """`[for] [internet|lan|all] [DURATION]` in any order -> (kinds, seconds)."""
    kinds = seconds = None
    for word in words:
        if word == "for":
            continue
        if word in ("internet", "lan", "all") and kinds is None:
            kinds = lease_kinds(word)
        elif re.fullmatch(DURATION_RE, word) and seconds is None:
            seconds = duration(word)
        else:
            raise FirewallError(f"Did not understand {word!r}. Example: hermes-firewall open PROFILE lan 30m")
    seconds = conf["lease_default"] if seconds is None else seconds
    require(seconds <= conf["lease_max"], f"The longest lease here is {left(conf['lease_max'])} "
                                          f"(lease.max in {CONFIG}).")
    return kinds or ("internet",), seconds


# --- configuration -------------------------------------------------------------------------

def lan_network(text):
    """A LAN network: private IPv4, or IPv6 ULA / global prefix of at least /48."""
    try:
        network = ipaddress.ip_network(text)
    except (ValueError, TypeError):
        raise FirewallError(f"Not a network in {CONFIG}: {text!r}") from None
    if network.version == 4:
        ok = network.is_private and not network.is_loopback and not network.is_link_local
    else:
        ok = network.subnet_of(ipaddress.ip_network("fc00::/7")) or (network.is_global and network.prefixlen >= 48)
    # A public range here would turn a "lan" lease into Internet access.
    require(ok, f"LAN network must be private (IPv6: ULA or a prefix of /48 or longer): {text}")
    return str(network)


def ports(entry, key):
    value = entry.get(key, [])
    require(type(value) is list and all(type(p) is int and 0 < p < 65536 for p in value),
            f"allow: {key} must be a list of port numbers: {entry}")
    return sorted(set(value))


def load_config(path=None):
    path = path or CONFIG
    require(path.exists(), f"Missing {path}; run install.sh again.")
    trusted(path)
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise FirewallError(f"{path}: {error}") from None
    known = {"ipv6": None, "docker_requires_firewall": None, "lease": {"default", "max"},
             "sandbox": {"dns"}, "lan": {"networks", "hosts"}, "hermes": {"egress_proxy"}, "allow": None}
    for key, value in data.items():
        require(key in known, f"Unknown setting in {path}: {key}")
        if known[key]:
            require(type(value) is dict and set(value) <= known[key], f"Unknown setting in {path}: [{key}] {value}")
    lease, sandbox, lan, hermes = (data.get(k, {}) for k in ("lease", "sandbox", "lan", "hermes"))
    require(all(type(v) is str for v in lease.values()), 'lease durations are text, for example default = "1h".')
    conf = {"ipv6": data.get("ipv6", "auto"), "docker_requires_firewall": data.get("docker_requires_firewall", True),
            "lease_default": duration(lease.get("default", "1h")), "lease_max": duration(lease.get("max", "24h")),
            "egress_proxy": hermes.get("egress_proxy", True)}
    require(conf["ipv6"] in ("auto", True, False), "ipv6 must be \"auto\", true or false.")
    require(type(conf["docker_requires_firewall"]) is bool and type(conf["egress_proxy"]) is bool,
            f"docker_requires_firewall and egress_proxy must be true or false in {path}.")
    require(conf["lease_default"] <= conf["lease_max"], "lease.default is longer than lease.max.")
    dns = sandbox.get("dns", [])
    require(type(dns) is list and dns, f"No DNS server for the sandboxes in {path} ([sandbox] dns).")
    conf["dns"] = []
    for server in dns:
        try:
            address = ipaddress.ip_address(server)
        except (ValueError, TypeError):
            raise FirewallError(f"Not an IP address in {path}: dns {server!r}") from None
        require(not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified),
                f"DNS server {server} cannot be reached from a sandbox.")
        conf["dns"].append(str(address))
    conf["dns"] = list(dict.fromkeys(conf["dns"]))
    networks = lan.get("networks", ["auto"])
    require(type(networks) is list, "lan.networks must be a list.")
    conf["lan_networks"] = list(dict.fromkeys(n if n == "auto" else lan_network(n) for n in networks))
    hosts = lan.get("hosts", [])
    require(type(hosts) is list and all(type(h) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", h)
                                        for h in hosts), f"lan.hosts must be a list of host names in {path}.")
    conf["lan_hosts"] = hosts
    allow = data.get("allow", [])
    require(type(allow) is list, "Use [[allow]] tables for the allow list.")
    conf["allow"] = []
    for entry in allow:
        require(type(entry) is dict and set(entry) <= {"net", "tcp", "udp"} and "net" in entry,
                f"allow entries take net and optional tcp/udp: {entry}")
        try:
            network = ipaddress.ip_network(entry["net"])
        except (ValueError, TypeError):
            raise FirewallError(f"Not an address or network in {path}: allow {entry['net']!r}") from None
        require(network.prefixlen > 0, "allow: a whole address family would disable the firewall.")
        conf["allow"].append({"net": str(network), "tcp": ports(entry, "tcp"), "udp": ports(entry, "udp")})
    return conf


def detected_dns(files=("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf")):
    """Upstream DNS servers of the host (behind systemd-resolved, if used)."""
    found = []
    for name in files:
        try:
            text = Path(name).read_text(encoding="utf-8")
        except OSError:
            continue
        for match in re.finditer(r"^\s*nameserver\s+(\S+)", text, re.M):
            try:
                address = ipaddress.ip_address(match[1].split("%")[0])
            except ValueError:
                continue
            if not (address.is_loopback or address.is_link_local or address.is_unspecified):
                found.append(str(address))
        if found:
            break
    return list(dict.fromkeys(found))


def config_text(example, dns):
    """The example configuration with the detected DNS servers."""
    if not dns:
        return example
    return re.sub(r"^dns = .*$", "dns = " + json.dumps(dns), example, count=1, flags=re.M)


# --- addresses -----------------------------------------------------------------------------

def family(address):
    return 6 if ":" in address else 4


def unique(items):
    return list(dict.fromkeys(items))


def nat64(prefixes, networks):
    """IPv4 networks as seen through NAT64 prefixes (/96), e.g. 192.168.0.0/16 -> 64:ff9b::c0a8:0/112."""
    result = []
    for prefix in prefixes:
        base = int(ipaddress.IPv6Network(prefix).network_address)
        for network in networks:
            v4 = ipaddress.IPv4Network(network)
            result.append(f"{ipaddress.IPv6Address(base | int(v4.network_address))}/{96 + v4.prefixlen}")
    return result


def dns_query(name, qtype=1):
    query_id = os.urandom(2)
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.rstrip(".").split("."))
    header = query_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    return query_id, header + labels + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"


def skip_name(data, offset):
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += length + 1


def dns_answer(query_id, data, qtype=1):
    """Addresses of type qtype (1 = A, 28 = AAAA), also behind CNAMEs, from a DNS response."""
    require(len(data) >= 12 and data[:2] == query_id, "DNS answer does not match the query.")
    flags, questions, answers = int.from_bytes(data[2:4], "big"), data[4:6], int.from_bytes(data[6:8], "big")
    require(flags & 0x8000 and not flags & 0x0200, "Invalid or truncated DNS answer.")
    require(flags & 0x000F == 0, f"DNS error code {flags & 0x000F}.")
    offset = 12
    for _ in range(int.from_bytes(questions, "big")):
        offset = skip_name(data, offset) + 4
    size, af = (4, socket.AF_INET) if qtype == 1 else (16, socket.AF_INET6)
    found = []
    for _ in range(answers):
        offset = skip_name(data, offset)
        kind, length = int.from_bytes(data[offset:offset + 2], "big"), int.from_bytes(data[offset + 8:offset + 10], "big")
        offset += 10
        if kind == qtype and length == size:
            found.append(socket.inet_ntop(af, data[offset:offset + size]))
        offset += length
    return found


def resolve(host, servers, qtype=1):
    """Ask the SANDBOX's resolvers (not the host's), so both see the same address."""
    errors = []
    for server in servers:
        query_id, packet = dns_query(host, qtype)
        with socket.socket(socket.AF_INET6 if family(server) == 6 else socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            try:
                sock.connect((server, 53))
                sock.send(packet)
                return dns_answer(query_id, sock.recv(4096), qtype)
            except (OSError, FirewallError, IndexError) as error:
                errors.append(f"{server}: {error}")
    raise OSError("; ".join(errors))


def resolve_host(host, servers):
    found, errors = [], []
    for qtype in (1, 28):
        try:
            found += resolve(host, servers, qtype)
        except OSError as error:
            errors.append(str(error))
    if not found:
        raise OSError("; ".join(errors) or "no address")
    return found


def nat64_prefixes(servers):
    """The well-known NAT64 prefix plus prefixes announced by DNS64 (ipv4only.arpa, RFC 7050)."""
    prefixes = [NAT64_WKP]
    try:
        answers = resolve("ipv4only.arpa", servers, 28)
    except OSError:
        answers = []
    for answer in answers:
        value = int(ipaddress.IPv6Address(answer))
        if value & 0xFFFFFFFF in (0xC00000AA, 0xC00000AB):  # 192.0.0.170 / .171
            prefixes.append(f"{ipaddress.IPv6Address(value & ~0xFFFFFFFF)}/96")
    return unique(prefixes)


def host_networks():
    """Networks the host is directly connected to, without Docker and other virtual bridges."""
    found = []
    for link in json.loads(run("ip", "-j", "addr", "show").stdout):
        if link.get("ifname", "").startswith(VIRTUAL_INTERFACES):
            continue
        for item in link.get("addr_info", []):
            if item.get("family") not in ("inet", "inet6") or item.get("scope") != "global":
                continue
            network = str(ipaddress.ip_interface(f"{item['local']}/{item['prefixlen']}").network)
            try:
                found.append(lan_network(network))
            except FirewallError:
                continue  # e.g. a public IPv4 address of the host: never LAN
    return found


def docker_gateway():
    """IPv4 address of docker0, which host.docker.internal (host-gateway) points to."""
    result = run("ip", "-j", "-4", "addr", "show", "dev", "docker0", check=False)
    if result.returncode:
        return None
    for link in json.loads(result.stdout or "[]"):
        for item in link.get("addr_info", []):
            return item.get("local")
    return None


def proxy_ports(conf):
    """{uid: [elements]}: Hermes egress proxies (iron-proxy) listening on the Docker bridge address."""
    gateway = docker_gateway() if conf["egress_proxy"] else None
    if not gateway:
        return {}
    result = {}
    for line in run("ss", "-H", "-ltnpe", check=False).stdout.splitlines():
        match = re.match(r"\S+\s+\d+\s+\d+\s+(\S+):(\d+)\s.*users:\(\(\"iron-proxy\",.*\buid:(\d+)", line)
        if match and match[1] == gateway:
            result.setdefault(int(match[3]), []).append(f"{gateway} . tcp . {match[2]}")
    return result


def common_sets(conf, strict=False):
    """Set elements shared by all profiles (everything except the per-user host ports)."""
    lan = []
    for network in conf["lan_networks"]:
        lan += host_networks() if network == "auto" else [network]
    for host in conf["lan_hosts"]:
        try:
            lan += resolve_host(host, conf["dns"])
        except OSError as error:
            require(not strict, f"Cannot resolve LAN host {host}: {error}; addresses left unchanged.")
            print(f"WARNING: cannot resolve LAN host {host} ({error}); it stays blocked until refresh.",
                  file=sys.stderr)
    lan4 = [a for a in lan if family(a) == 4]
    prefixes = nat64_prefixes(conf["dns"])
    whole = [e["net"] for e in conf["allow"] if not e["tcp"] and not e["udp"]]
    services = [f"{e['net']} . {proto} . {port}" for e in conf["allow"] for proto in ("tcp", "udp")
                for port in e[proto]]
    return {"lan_v4": unique(lan4), "lan_v6": unique([a for a in lan if family(a) == 6] + nat64(prefixes, lan4)),
            "dns_v4": [d for d in conf["dns"] if family(d) == 4], "dns_v6": [d for d in conf["dns"] if family(d) == 6],
            "allow_v4": [n for n in whole if family(n) == 4], "allow_v6": [n for n in whole if family(n) == 6],
            "allow_ports_v4": unique(s for s in services if family(s.split()[0]) == 4),
            "allow_ports_v6": unique(s for s in services if family(s.split()[0]) == 6),
            "non_public_v6": [*NONPUBLIC_V6, *nat64(prefixes, NONPUBLIC_V4)]}


def profile_sets(record, common, proxies):
    try:
        uid = pwd.getpwnam(record["user"]).pw_uid
    except KeyError:
        uid = None
    return {**common, "host_ports_v4": proxies.get(uid, [])}


# --- nftables ------------------------------------------------------------------------------

def elements(items):
    return f"elements = {{ {', '.join(items)} }}" if items else ""


def rules(profile, sets=None):
    sets = sets or {}
    item = identity(profile)
    table, bridge = item["table"], item["bridge"]
    declarations = "".join(f"    set {name} {{\n        type {kind};{flags}\n        {elements(sets.get(name, ()))}\n    }}\n"
                           for name, kind, flags in SETS)
    return f'''destroy table inet {table}
table inet {table} {{
    comment "hermes-firewall {VERSION}"
    set open_internet {{ type ifname; flags timeout; timeout 1h; size 1; }}
    set open_lan {{ type ifname; flags timeout; timeout 1h; size 1; }}
    set non_public_v4 {{
        type ipv4_addr; flags interval;
        {elements(NONPUBLIC_V4)}
    }}
{declarations}    chain outbound {{
        ip daddr @dns_v4 meta l4proto {{ tcp, udp }} th dport 53 counter return
        ip6 daddr @dns_v6 meta l4proto {{ tcp, udp }} th dport 53 counter return
        ip daddr @allow_v4 counter return
        ip6 daddr @allow_v6 counter return
        ip daddr . meta l4proto . th dport @allow_ports_v4 counter return
        ip6 daddr . meta l4proto . th dport @allow_ports_v6 counter return
        ip daddr @lan_v4 iifname @open_lan counter return
        ip6 daddr @lan_v6 iifname @open_lan counter return
        ip daddr @lan_v4 counter drop
        ip6 daddr @lan_v6 counter drop
        ip daddr @non_public_v4 counter drop
        ip6 daddr @non_public_v6 counter drop
        iifname @open_internet counter return
        counter drop
    }}
    chain forward_guard {{
        type filter hook forward priority -10; policy accept;
        iifname "{bridge}" jump outbound
        oifname "{bridge}" ip saddr @dns_v4 meta l4proto {{ tcp, udp }} th sport 53 ct state established,related counter return
        oifname "{bridge}" ip6 saddr @dns_v6 meta l4proto {{ tcp, udp }} th sport 53 ct state established,related counter return
        oifname "{bridge}" ip saddr @allow_v4 ct state established,related counter return
        oifname "{bridge}" ip6 saddr @allow_v6 ct state established,related counter return
        oifname "{bridge}" ip saddr . meta l4proto . th sport @allow_ports_v4 ct state established,related counter return
        oifname "{bridge}" ip6 saddr . meta l4proto . th sport @allow_ports_v6 ct state established,related counter return
        oifname "{bridge}" oifname @open_internet ct state established,related counter return
        oifname "{bridge}" oifname @open_lan ip saddr @lan_v4 ct state established,related counter return
        oifname "{bridge}" oifname @open_lan ip6 saddr @lan_v6 ct state established,related counter return
        oifname "{bridge}" counter drop
    }}
    chain host_input_guard {{
        type filter hook input priority -10; policy accept;
        iifname "{bridge}" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} counter return
        iifname "{bridge}" ip daddr . meta l4proto . th dport @host_ports_v4 counter return
        iifname "{bridge}" counter drop
    }}
    chain host_output_guard {{
        type filter hook output priority -10; policy accept;
        oifname "{bridge}" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, packet-too-big, destination-unreachable, time-exceeded }} counter return
        oifname "{bridge}" icmp type {{ destination-unreachable, time-exceeded }} counter return
        oifname "{bridge}" ip saddr . meta l4proto . th sport @host_ports_v4 ct state established counter return
        oifname "{bridge}" counter drop
    }}
}}
'''


def chain_rules(text):
    """{chain: [rules]} of a table in nft syntax."""
    chains, current = {}, None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("chain "):
            current = stripped.split()[1]
            chains[current] = []
        elif stripped == "}":
            current = None
        elif current and stripped and not stripped.startswith("type "):
            chains[current].append(stripped)
    return chains


def lease_transaction(profile, kinds=KINDS, seconds=None):
    """Replace the given leases; without seconds they are closed."""
    item = identity(profile)
    require(kinds and set(kinds) <= set(KINDS), "Lease kind: internet, lan or all.")
    text = ""
    for kind in kinds:
        text += f'flush set inet {item["table"]} open_{kind}\n'
        if seconds is not None:
            require(type(seconds) is int and 0 < seconds <= MAX_LEASE, "Invalid lease duration.")
            text += (f'add element inet {item["table"]} open_{kind} '
                     f'{{ "{item["bridge"]}" timeout {seconds}s }}\n')
    return text


def refresh_transaction(data, sets):
    """Replace all address sets of every table; leases stay untouched. sets: {profile: {set: [..]}}."""
    text = ""
    for profile in sorted(data["profiles"]):
        table = identity(profile)["table"]
        for name, _, _ in SETS:
            text += f"flush set inet {table} {name}\n"
            if sets[profile].get(name):
                text += f"add element inet {table} {name} {{ {', '.join(sets[profile][name])} }}\n"
    return text


def all_sets(data, strict=False):
    conf = load_config()
    if not data["profiles"]:
        return {}
    common, proxies = common_sets(conf, strict), proxy_ports(conf)
    return {p: profile_sets(r, common, proxies) for p, r in data["profiles"].items()}


def restore_transaction(data):
    sets = all_sets(data)
    return "".join(rules(profile, sets[profile]) for profile in sorted(data["profiles"]))


# --- state ---------------------------------------------------------------------------------

def trusted(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            f"Not root-owned / writable by others / symlink: {path}")


def validate_registry(data):
    require(type(data) is dict and data.get("version") == 2 and type(data.get("profiles")) is dict,
            f"Invalid {REGISTRY}; no automatic repair was attempted.")
    seen = set()
    for profile, record in data["profiles"].items():
        bridge = identity(profile)["bridge"]
        require(type(record) is dict and set(record) == {"user", "ipv6", "label", "dns"}
                and type(record["user"]) is str and type(record["ipv6"]) is bool
                and type(record["label"]) is str and type(record["dns"]) is list,
                f"Invalid registry entry for {profile}.")
        require(bridge not in seen, "Profile bridge collision.")
        seen.add(bridge)
    return data


def load_registry():
    trusted(CONF)
    trusted(REGISTRY)
    return validate_registry(json.loads(REGISTRY.read_text(encoding="utf-8")))


def atomic_write(path, data, mode=0o644):
    descriptor, name = tempfile.mkstemp(prefix=".hermes-fw-", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        folder = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_registry(data):
    validate_registry(data)
    atomic_write(REGISTRY, json.dumps(data, indent=2, sort_keys=True) + "\n")


def run(*arguments, input=None, check=True):
    executable = shutil.which(arguments[0], path=ENV["PATH"])
    require(executable, f"Missing command: {arguments[0]}")
    result = subprocess.run([executable, *arguments[1:]], input=input, text=True,
                            capture_output=True, env=ENV, timeout=90)
    if check and result.returncode:
        raise FirewallError(f"{' '.join(arguments)} failed ({result.returncode}):\n"
                            f"{result.stderr.strip() or result.stdout.strip()}")
    return result


def nft_apply(text):
    if text:
        run("nft", "--check", "--file", "-", input=text)
        run("nft", "--file", "-", input=text)


def docker_ready():
    info = json.loads(run("docker", "info", "--format", "{{json .}}").stdout)
    require(info.get("OSType") == "linux", "Linux Docker is required.")
    require(not any("rootless" in s for s in info.get("SecurityOptions") or []),
            "hermes-firewall needs the local rootful system Docker.")
    run("systemctl", "is-active", "--quiet", "docker.service")


def networks():
    return set(run("docker", "network", "ls", "--format", "{{.Name}}").stdout.splitlines())


def interface_exists(name):
    return any(item.get("ifname") == name for item in json.loads(run("ip", "-j", "link", "show").stdout))


def check_network(profile, record):
    item = identity(profile)
    data = json.loads(run("docker", "network", "inspect", item["network"]).stdout)[0]
    require(data.get("Driver") == "bridge" and not data.get("Internal")
            and bool(data.get("EnableIPv6")) == record["ipv6"],
            f"Unexpected network configuration: {item['network']}")
    require((data.get("Options") or {}).get("com.docker.network.bridge.name") == item["bridge"]
            and (data.get("Labels") or {}).get(LABEL) == profile,
            f"Network ownership/bridge mismatch: {item['network']}")


def table_names():
    data = json.loads(run("nft", "--json", "list", "tables").stdout)
    return {row["table"]["name"] for row in data["nftables"]
            if "table" in row and row["table"].get("family") == "inet"}


def health(profile):
    run("systemctl", "is-active", "--quiet", SERVICE)
    item = identity(profile)
    data = json.loads(run("nft", "--json", "list", "table", "inet", item["table"]).stdout)
    chains = {row["chain"]["name"]: row["chain"] for row in data["nftables"] if "chain" in row}
    for name, hook in (("forward_guard", "forward"), ("host_input_guard", "input"),
                       ("host_output_guard", "output")):
        require(chains.get(name, {}).get("hook") == hook
                and chains[name].get("prio") == -10, f"Firewall hook missing/changed: {name}")
    counts = {}
    for row in data["nftables"]:
        if "rule" in row:
            chain = row["rule"]["chain"]
            counts[chain] = counts.get(chain, 0) + 1
    expected = {chain: len(lines) for chain, lines in chain_rules(rules(profile)).items()}
    require(counts == expected, "Firewall rule structure differs; refusing to claim protection.")


def set_elements(profile, name):
    """What the kernel currently has in a set of this profile."""
    data = json.loads(run("nft", "--json", "list", "set", "inet", identity(profile)["table"], name).stdout)
    result = []
    for row in data["nftables"]:
        for element in row.get("set", {}).get("elem", []):
            if isinstance(element, dict) and "elem" in element:
                element = element["elem"].get("val")
            if isinstance(element, dict) and "prefix" in element:
                result.append(f"{element['prefix']['addr']}/{element['prefix']['len']}")
            elif isinstance(element, dict) and "range" in element:
                result.append("-".join(element["range"]))
            else:
                result.append(str(element))
    return result


def lease_remaining(profile, kind="internet"):
    """None = closed, otherwise seconds until the kernel closes the lease."""
    data = json.loads(run("nft", "--json", "list", "set", "inet", identity(profile)["table"],
                          f"open_{kind}").stdout)
    for row in data["nftables"]:
        if "set" in row:
            elements = row["set"].get("elem", [])
            if not elements:
                return None
            element = elements[0]
            return element["elem"].get("expires", 0) if isinstance(element, dict) else 0
    raise FirewallError(f"Lease set missing for {profile}.")


# --- wording -------------------------------------------------------------------------------

def left(seconds):
    if seconds >= 3600:
        hours, minutes = divmod(seconds // 60, 60)
        return f"{hours}h {minutes:02d}m" if minutes else f"{hours}h"
    return f"{seconds // 60}m" if seconds >= 60 else f"{seconds}s"


def lease_state(seconds, now=None):
    if seconds is None:
        return "closed"
    until = time.strftime("%H:%M", time.localtime((now or time.time()) + seconds))
    return f"open for {left(seconds)} (until {until})"


def profile_line(profile):
    internet, lan = (lease_state(lease_remaining(profile, kind)) for kind in KINDS)
    return f"{profile}: firewall active, Internet {internet}, LAN {lan}"


def always_text(conf):
    services = [f"{e['net']}" + "".join(f" {p} {','.join(map(str, e[p]))}" for p in ("tcp", "udp") if e[p])
                for e in conf["allow"]]
    text = "; ".join([f"DNS {', '.join(conf['dns'])}", *services])
    return text + ("; Hermes egress proxy" if conf["egress_proxy"] else "")


# --- Hermes (runs as the Hermes user, never as root) ---------------------------------------

def hermes_home(home, profile):
    base = Path(home) / ".hermes"
    return base if profile == "default" else base / "profiles" / profile


def hermes_profiles(user):
    base = Path(user.pw_dir) / ".hermes"
    found = {"default"} if base.is_dir() else set()
    folder = base / "profiles"
    if folder.is_dir():
        found |= {p.name for p in folder.iterdir() if p.is_dir() and re.fullmatch(PROFILE_RE, p.name)}
    return found


def hermes(*arguments):
    executable = shutil.which("hermes")
    require(executable, "The Hermes command 'hermes' is not in your PATH.")
    result = subprocess.run([executable, *arguments], capture_output=True, text=True, timeout=120)
    require(result.returncode == 0, f"hermes {' '.join(arguments)} failed:\n{(result.stderr or result.stdout).strip()}")
    return result.stdout


def terminal_settings(profile):
    output = hermes("-p", profile, "config", "get", "terminal", "--json")
    try:
        settings = json.loads(output)
    except ValueError:
        raise FirewallError(f"Unexpected output of 'hermes -p {profile} config get terminal --json'.") from None
    require(type(settings) is dict, f"Unexpected terminal settings of Hermes profile {profile}.")
    return settings


def container_label(profile, settings):
    """The hermes-profile label Hermes puts on this profile's sandboxes."""
    key = settings.get("docker_shared_container_key") or ""
    if not key:
        return re.sub(r"[^A-Za-z0-9_.-]", "_", profile)[:63]
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"{re.sub(r'[^A-Za-z0-9_.-]', '_', key)[:50]}-{digest}"


def firewall_arg(argument):
    for flag in ("--network", "--net", "--dns"):
        require(argument != flag, f"docker_extra_args uses '{flag} VALUE'; write {flag}=VALUE instead.")
        if argument.startswith(flag + "="):
            return True
    return False


def hermes_info(profile):
    """Checks before protecting a profile; returns the sandbox label and hints for the user."""
    settings = terminal_settings(profile)
    backend = settings.get("backend") or "local"
    require(backend == "docker",
            f"Hermes profile {profile} does not use a Docker sandbox (terminal.backend: {backend}), "
            f"so there is nothing to protect.\nTo use one: hermes -p {profile} config set terminal.backend docker")
    key = settings.get("docker_shared_container_key") or ""
    if key:
        user = pwd.getpwuid(os.geteuid())
        others = [p for p in sorted(hermes_profiles(user) - {profile})
                  if (terminal_settings(p).get("docker_shared_container_key") or "") == key]
        require(not others, f"Profiles {profile} and {', '.join(others)} share one sandbox "
                            "(terminal.docker_shared_container_key). hermes-firewall cannot protect a shared "
                            "sandbox; give each profile its own key or none.")
    hints = []
    if settings.get("docker_mount_cwd_to_workspace"):
        hints.append("Hint: this profile shows your host working directory in the sandbox "
                     "(docker_mount_cwd_to_workspace); with an open lease the agent could send those files out.")
    for argument in settings.get("docker_extra_args") or []:
        firewall_arg(str(argument))
    return {"label": container_label(profile, settings), "hints": hints}


def install_plugin(profile):
    target = hermes_home(Path.home(), profile) / "plugins" / PLUGIN
    remove_plugin_files(target)
    target.mkdir(parents=True)
    for name in PLUGIN_FILES:
        shutil.copyfile(SHARE / "plugin" / name, target / name)
    hermes("-p", profile, "plugins", "enable", PLUGIN)


def remove_plugin_files(target):
    """Remove ONLY the plugin's own files; refuse anything else."""
    if not target.exists():
        return
    cache = target / "__pycache__"
    require({p.name for p in target.iterdir()} <= {*PLUGIN_FILES, "__pycache__"}
            and (not cache.exists() or all(p.suffix == ".pyc" for p in cache.iterdir())),
            f"{target} contains files that do not belong to hermes-firewall; remove it manually.")
    if cache.exists():
        for item in cache.iterdir():
            item.unlink()
        cache.rmdir()
    for name in PLUGIN_FILES:
        (target / name).unlink(missing_ok=True)
    target.rmdir()


def hermes_attach(profile, dns):
    """Point the profile's sandbox at its firewall network and install the /firewall plugin."""
    settings = terminal_settings(profile)
    current = [str(a) for a in settings.get("docker_extra_args") or []]
    wanted = [a for a in current if not firewall_arg(a)]
    wanted += [f"--network={identity(profile)['network']}", *(f"--dns={server}" for server in dns)]
    if settings.get("docker_network") is not True:
        hermes("-p", profile, "config", "set", "terminal.docker_network", "true")
    if wanted != current:
        hermes("-p", profile, "config", "set", "terminal.docker_extra_args", json.dumps(wanted))
    install_plugin(profile)


def hermes_detach(profile):
    """The sandbox gets NO network (docker_network: false = --network=none), never an unfiltered one."""
    settings = terminal_settings(profile)
    current = [str(a) for a in settings.get("docker_extra_args") or []]
    wanted = [a for a in current if not firewall_arg(a)]
    hermes("-p", profile, "config", "set", "terminal.docker_network", "false")
    if wanted != current:
        hermes("-p", profile, "config", "set", "terminal.docker_extra_args", json.dumps(wanted))
    target = hermes_home(Path.home(), profile) / "plugins" / PLUGIN
    if target.exists():
        subprocess.run([shutil.which("hermes") or "hermes", "-p", profile, "plugins", "disable", PLUGIN],
                       capture_output=True, timeout=120)
        remove_plugin_files(target)


def user_command(words):
    """`_hermes info|attach|detach PROFILE`: called by root via runuser as the Hermes user."""
    require(os.geteuid() != 0, "Internal command; it runs as the Hermes user, not as root.")
    require(len(words) == 3 and words[1] in ("info", "attach", "detach"), "Unknown internal command.")
    action, profile = words[1], words[2]
    identity(profile)
    if action == "info":
        print(json.dumps(hermes_info(profile)))
    elif action == "attach":
        hermes_attach(profile, load_config()["dns"])
    else:
        hermes_detach(profile)


def hermes_user():
    name = os.environ.get("SUDO_USER", "")
    require(name and name != "root", "Run this with sudo from the account that runs Hermes.")
    return pwd.getpwnam(name)


def as_user(user, *arguments):
    """Hermes files are changed by the user's own process, never by root."""
    command = shlex.join([str(EXE), "_hermes", *arguments])
    result = run("runuser", "-l", user.pw_name, "-c", command, check=False)
    message = result.stderr.strip().removeprefix("ERROR: ")
    require(result.returncode == 0, message or f"{command} failed as {user.pw_name}.")
    return result.stdout


# --- sandboxes -----------------------------------------------------------------------------

def sandboxes(label):
    ids = run("docker", "ps", "-aq", "--filter", "label=hermes-agent=1",
              "--filter", f"label=hermes-profile={label}").stdout.split()
    return json.loads(run("docker", "inspect", *ids).stdout) if ids else []


def kept_text(container):
    folders = sorted({m["Destination"] for m in container.get("Mounts") or []
                      if m.get("Type") in ("bind", "volume") and m.get("RW", True)})
    files = f"your files in {', '.join(folders)}; " if folders else ""
    return f"  Kept:  {files}chats, memory, skills, settings\n" \
           "  Lost:  programs installed inside the sandbox and files stored elsewhere in it"


def protect_sandboxes(profile, record, conf, interactive=False, yes=False):
    """Move sandboxes of this profile into its firewall; returns messages for the user.

    Moving only ever restricts access, so it happens without asking. A sandbox that
    cannot be moved (host or no network) or keeps old DNS servers needs a reset."""
    network, messages = identity(profile)["network"], []
    for container in sandboxes(record["label"]):
        mode = (container.get("HostConfig") or {}).get("NetworkMode") or ""
        attached = set((container.get("NetworkSettings") or {}).get("Networks") or {})
        reason = None
        if mode == "host" or mode == "none" or mode.startswith("container:"):
            reason = "it has no network at all" if mode == "none" else "it uses the host's network"
        elif attached != {network}:
            for other in sorted(attached - {network}):
                run("docker", "network", "disconnect", "-f", other, container["Id"])
            if network not in attached:
                run("docker", "network", "connect", network, container["Id"])
            messages.append(f"{profile}: an older sandbox was running without the firewall; it is protected now. "
                            "A download running at that moment may have been interrupted.")
        if reason is None and ((container.get("HostConfig") or {}).get("Dns") or []) != conf["dns"]:
            reason = "it still uses old DNS settings, so name lookups there may fail"
        if reason is None:
            continue
        if interactive and (yes or sys.stdin.isatty()):
            print(f"The sandbox of {profile} has to be reset: {reason}.\n"
                  f"Hermes creates a fresh one automatically on next use.\n{kept_text(container)}")
            if yes or input("Reset the sandbox now? [y/N] ").strip().lower() in ("y", "yes"):
                run("docker", "rm", "-f", container["Id"])
                messages.append(f"{profile}: the sandbox was reset.")
                continue
        if mode == "host" or mode.startswith("container:"):
            messages.append(f"{profile}: WARNING - a sandbox of this profile is NOT protected ({reason}). "
                            f"Fix: sudo hermes-firewall add {profile}")
        else:
            messages.append(f"{profile}: a sandbox of this profile needs a reset ({reason}). "
                            f"Fix: sudo hermes-firewall add {profile}")
    return messages


# --- sudoers -------------------------------------------------------------------------------

def sudoers_text(data):
    lines = []
    for profile, record in sorted(data["profiles"].items()):
        commands = [f"{EXE} open {profile}", f"{EXE} open {profile} *", f"{EXE} close {profile}",
                    f"{EXE} close {profile} *", f"{EXE} status {profile}"]
        lines.append(f"{record['user']} ALL=(root) NOPASSWD: {', '.join(commands)}\n")
    if not lines:
        return ""
    return ("# Generated by hermes-firewall; changed by 'hermes-firewall add/remove'. Do not edit.\n"
            "# Lets the Hermes plugin /firewall open, close and show the leases of protected profiles.\n"
            f"Defaults!{EXE} !requiretty\n" + "".join(lines))


def write_sudoers(data):
    text = sudoers_text(data)
    if not text:
        SUDOERS.unlink(missing_ok=True)
        return
    with tempfile.NamedTemporaryFile("w", prefix=".hermes-fw-", dir=SUDOERS.parent, delete=False) as check:
        check.write(text)
    try:
        run("visudo", "-cf", check.name)
    finally:
        os.unlink(check.name)
    atomic_write(SUDOERS, text, 0o440)


# --- commands ------------------------------------------------------------------------------

def record_of(data, profile):
    identity(profile)
    require(profile in data["profiles"], f"{profile} is not protected. To protect it: sudo hermes-firewall add {profile}")
    return data["profiles"][profile]


def ipv6_enabled(conf):
    if conf["ipv6"] != "auto":
        return conf["ipv6"]
    return bool(json.loads(run("ip", "-j", "-6", "route", "show", "default").stdout or "[]"))


def create_firewall(data, profile, record, conf):
    item = identity(profile)
    require(all(item["bridge"] != identity(p)["bridge"] for p in data["profiles"]), "Bridge collision.")
    docker_ready()
    run("systemctl", "is-active", "--quiet", SERVICE)
    require(item["network"] not in networks(), f"Network already exists: {item['network']}")
    require(item["table"] not in table_names(), f"Firewall table already exists: {item['table']}")
    require(not interface_exists(item["bridge"]), f"Interface already exists: {item['bridge']}")
    text = rules(profile, profile_sets(record, common_sets(conf), proxy_ports(conf)))
    run("nft", "--check", "--file", "-", input=text)
    data["profiles"][profile] = record
    # Persist protection BEFORE making a network available; partial failure stays closed.
    save_registry(data)
    nft_apply(text)
    create_network(profile, record)


def create_network(profile, record):
    item = identity(profile)
    ipv6 = ["--ipv6", "--subnet", item["subnet6"]] if record["ipv6"] else ["--ipv6=false"]
    run("docker", "network", "create", "--driver", "bridge", *ipv6,
        "--opt", f"com.docker.network.bridge.name={item['bridge']}",
        "--opt", "com.docker.network.bridge.enable_icc=false",
        "--label", f"{LABEL}={profile}", item["network"])


def add_profile(data, profile, user, yes=False):
    identity(profile)
    require(hermes_home(user.pw_dir, profile).is_dir(),
            f"No Hermes profile {profile} for {user.pw_name} ({hermes_home(user.pw_dir, profile)} missing).")
    existing = data["profiles"].get(profile)
    require(not existing or existing["user"] == user.pw_name,
            f"{profile} is protected for user {existing and existing['user']}; run add as that user.")
    conf = load_config()
    # The last line: login shells may print their own greetings first.
    info = json.loads((as_user(user, "info", profile).strip().splitlines() or ["{}"])[-1])
    if existing:
        health(profile)  # Re-running add repairs the network, the Hermes side and the sandboxes.
        existing["label"] = info["label"]
        docker_ready()
        if identity(profile)["network"] not in networks():
            create_network(profile, existing)
    else:
        record = {"user": user.pw_name, "ipv6": ipv6_enabled(conf), "label": info["label"], "dns": []}
        create_firewall(data, profile, record, conf)
    as_user(user, "attach", profile)
    data["profiles"][profile]["dns"] = conf["dns"]
    save_registry(data)
    write_sudoers(data)
    for message in [*info["hints"], *protect_sandboxes(profile, data["profiles"][profile], conf, True, yes)]:
        print(message)
    print(profile_line(profile))
    print(f"Restart the Hermes gateway (if used: hermes -p {profile} gateway restart) and start a new session.\n"
          "In the chat: /firewall open, /firewall open lan 30m, /firewall close, /firewall status")


def remove_profile(data, profile):
    record = record_of(data, profile)
    item = identity(profile)
    docker_ready()
    exists = item["network"] in networks()
    if exists:
        check_network(profile, record)
    # Detach first: new sessions get NO network instead of a vanished one.
    if hermes_home(pwd.getpwnam(record["user"]).pw_dir, profile).is_dir():
        as_user(pwd.getpwnam(record["user"]), "detach", profile)
    if exists:
        for container in run("docker", "ps", "-aq", "--filter", f"network={item['network']}").stdout.split():
            run("docker", "network", "disconnect", "-f", item["network"], container)
        # Never delete protection until the associated network is gone.
        run("docker", "network", "rm", item["network"])
    require(not interface_exists(item["bridge"]), f"Bridge still exists: {item['bridge']}; protection kept.")
    nft_apply(f"destroy table inet {item['table']}\n")
    del data["profiles"][profile]
    save_registry(data)
    write_sudoers(data)
    print(f"{profile}: firewall removed. Its sandbox now has no network at all.")
    print(f"Restart the Hermes gateway (if used: hermes -p {profile} gateway restart) and start a new session.")


def open_lease(data, profile, words):
    record = record_of(data, profile)
    conf = load_config()
    kinds, seconds = open_arguments(words, conf)
    health(profile)
    docker_ready()
    check_network(profile, record)
    nft_apply(lease_transaction(profile, kinds, seconds))
    print(profile_line(profile))


def close_lease(data, profile, words):
    record_of(data, profile)
    require(len(words) <= 1, "Usage: hermes-firewall close PROFILE [internet|lan|all]")
    nft_apply(lease_transaction(profile, lease_kinds(words[0] if words else "all")))
    print(profile_line(profile))


def status(data, user=None, selected=None, verbose=False):
    if selected:
        record_of(data, selected)
        profiles = [selected]
    else:
        profiles = sorted(set(data["profiles"]) | (hermes_profiles(user) if user else set()))
    if not profiles:
        print("No Hermes profiles found.")
    conf = load_config() if data["profiles"] else None
    problems = []
    for profile in profiles:
        if profile not in data["profiles"]:
            print(f"{profile}: NOT protected (to protect it: sudo hermes-firewall add {profile})")
            continue
        try:
            health(profile)
            messages = protect_sandboxes(profile, data["profiles"][profile], conf)
            print(profile_line(profile))
            for message in messages:
                print(message)
        except FirewallError as error:
            problems.append(profile)
            print(f"{profile}: ERROR - the firewall is not working: {error}")
            continue
        if verbose:
            item = identity(profile)
            print(f"  network {item['network']}, bridge {item['bridge']}, table inet {item['table']}, "
                  f"IPv6 {'on ' + item['subnet6'] if data['profiles'][profile]['ipv6'] else 'off'}")
            print(f"  LAN: {', '.join(set_elements(profile, 'lan_v4') + set_elements(profile, 'lan_v6')) or 'nothing'}")
            for container in sandboxes(data["profiles"][profile]["label"]):
                print(f"  sandbox {container['Name'].lstrip('/')}: {container['State']['Status']}, networks "
                      f"{', '.join((container.get('NetworkSettings') or {}).get('Networks') or {}) or 'none'}")
    if conf and not selected:
        print(f"Always reachable from protected sandboxes: {always_text(conf)}")
    require(not problems, f"Firewall problem for: {', '.join(problems)}. "
                          "Fix: sudo hermes-firewall restore (closes all leases)")


def refresh(data):
    """Timer job: heal missing tables (closed), refresh addresses, follow DNS changes, protect sandboxes."""
    missing = [p for p in sorted(data["profiles"]) if identity(p)["table"] not in table_names()]
    if missing:
        sets = all_sets(data)
        nft_apply("".join(rules(p, sets[p]) for p in missing))
        print(f"Firewall restored (closed) for: {', '.join(missing)}", file=sys.stderr)
    # Strict: on a resolution failure the current addresses stay in place.
    nft_apply(refresh_transaction(data, all_sets(data, strict=True)))
    conf = load_config()
    for profile, record in sorted(data["profiles"].items()):
        if record["dns"] != conf["dns"]:
            as_user(pwd.getpwnam(record["user"]), "attach", profile)
            record["dns"] = conf["dns"]
            save_registry(data)
        for message in protect_sandboxes(profile, record, conf):
            print(message)


# --- installation --------------------------------------------------------------------------

def flush_warnings():
    found = []
    for name in ("/etc/nftables.conf", "/etc/sysconfig/nftables.conf"):
        try:
            if re.search(r"^\s*flush\s+ruleset", Path(name).read_text(encoding="utf-8"), re.M):
                found.append(f"WARNING: {name} contains 'flush ruleset'. Restarting nftables.service removes "
                             "this firewall until the next refresh (at most 5 minutes, then closed).")
        except OSError:
            continue
    try:
        sudoers = Path("/etc/sudoers").read_text(encoding="utf-8")
        if not re.search(r"^[@#]includedir\s+/etc/sudoers\.d", sudoers, re.M):
            found.append("WARNING: /etc/sudoers does not include /etc/sudoers.d; /firewall in Hermes will not work.")
    except OSError:
        pass
    return found


def write_program(bundle):
    atomic_write(EXE, (bundle / "hermes_firewall.py").read_text(encoding="utf-8"), 0o755)
    target = SHARE / "plugin"
    target.mkdir(parents=True, exist_ok=True, mode=0o755)
    for name in PLUGIN_FILES:
        atomic_write(target / name, (bundle / "plugin" / PLUGIN / name).read_text(encoding="utf-8"))


def write_units(conf):
    """Units and the Docker drop-in as configured; returns True when something changed."""
    changed = False
    for path, text in ((UNIT, UNIT_TEXT), (REFRESH_UNIT, REFRESH_TEXT), (REFRESH_TIMER, TIMER_TEXT)):
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            atomic_write(path, text)
            changed = True
    if conf["docker_requires_firewall"] and not DROPIN.exists():
        DROPIN.parent.mkdir(mode=0o755, exist_ok=True)
        atomic_write(DROPIN, DROPIN_TEXT)
        changed = True
    elif not conf["docker_requires_firewall"] and DROPIN.exists():
        DROPIN.unlink()
        changed = True
    return changed


def install(bundle):
    present = [str(p) for p in (REGISTRY, EXE, UNIT, DROPIN, REFRESH_UNIT, REFRESH_TIMER, SUDOERS)
               if p.exists() or p.is_symlink()]
    require(not present, f"hermes-firewall is already/partially installed: {', '.join(present)}. "
                         "Run install.sh to upgrade.")
    require(not CONF.exists() or {p.name for p in CONF.iterdir()} <= {"config.toml"},
            f"{CONF} contains unknown files; refusing installation.")
    for command in ("nft", "docker", "systemctl", "ip", "ss", "runuser", "visudo"):
        require(shutil.which(command, path=ENV["PATH"]), f"Missing program: {command}")
    docker_ready()
    require(not re.search(r"\bflowtable\b|\bflow\s+add\b", run("nft", "list", "ruleset").stdout),
            "Flow offload detected; it can bypass ordinary forwarding hooks. Review first.")
    run("nft", "--check", "--file", "-", input=rules("installation-check"))
    dns = detected_dns()
    CONF.mkdir(mode=0o755, exist_ok=True)
    kept = CONFIG.exists()  # kept by "uninstall" without --purge
    if not kept:
        atomic_write(CONFIG, config_text((bundle / "config.example.toml").read_text(encoding="utf-8"), dns))
    conf = load_config()
    atomic_write(REGISTRY, '{"profiles": {}, "version": 2}\n')
    write_program(bundle)
    write_units(conf)
    run("systemctl", "daemon-reload")
    # install.sh starts service and timer AFTER this process releases its lock.
    # Starting the service here would deadlock its ExecStart=... restore on the same lock.
    run("systemctl", "enable", SERVICE, REFRESH_TIMER.name)
    for warning in flush_warnings():
        print(warning)
    origin = "kept from before" if kept else ("detected" if dns else "default, no host DNS detected")
    print(f"Installed. Settings: {CONFIG} (sandbox DNS {', '.join(conf['dns'])}: {origin}).\n"
          "Next, as the user running Hermes: sudo hermes-firewall add PROFILE  (for example: default)")


def upgrade(bundle):
    missing = [str(p) for p in (CONF, REGISTRY, CONFIG, UNIT) if not p.exists()]
    require(not missing, f"hermes-firewall is not (completely) installed, missing: {', '.join(missing)}.")
    for path in (EXE, UNIT, REFRESH_UNIT, REFRESH_TIMER, DROPIN, SUDOERS):
        if path.exists() or path.is_symlink():
            trusted(path)
    data = load_registry()
    conf = load_config()  # an invalid configuration stops the upgrade before anything changes
    write_program(bundle)
    if write_units(conf):
        run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", REFRESH_TIMER.name)
    write_sudoers(data)
    outdated = []
    for profile in sorted(data["profiles"]):
        try:
            health(profile)
        except FirewallError:
            outdated.append(profile)
    if outdated:
        # The rule layout changed: reload all tables in one transaction (closes all leases).
        nft_apply(restore_transaction(data))
    elif data["profiles"]:
        try:
            nft_apply(refresh_transaction(data, all_sets(data, strict=True)))
        except FirewallError as error:
            print(f"WARNING: {error}", file=sys.stderr)
    for profile, record in sorted(data["profiles"].items()):
        try:
            as_user(pwd.getpwnam(record["user"]), "attach", profile)
            record["dns"] = conf["dns"]
        except (FirewallError, KeyError) as error:
            print(f"WARNING: Hermes profile {profile} not updated: {error}", file=sys.stderr)
    save_registry(data)
    for warning in flush_warnings():
        print(warning)
    print(f"Upgraded to {VERSION}." + (" The firewall rules changed: ALL leases are now closed." if outdated else ""))


def uninstall(data, purge=False):
    require(not data["profiles"], "Remove the protected profiles first: sudo hermes-firewall remove PROFILE")
    docker_ready()
    require(not run("docker", "network", "ls", "-q", "--filter", f"label={LABEL}").stdout.strip(),
            "Docker networks of hermes-firewall remain; refusing uninstall.")
    require(not any(name.startswith("hermes_fw_") for name in table_names()),
            "Firewall tables of hermes-firewall remain; refusing uninstall.")
    names = {p.name for p in CONF.iterdir()}
    require(names <= {"profiles.json", "config.toml"}, f"{CONF} contains unknown files; refusing uninstall.")
    # Detach the dependency BEFORE disabling the guard; never restart/stop Docker.
    if DROPIN.exists():
        DROPIN.unlink()
        run("systemctl", "daemon-reload")
    dependencies = run("systemctl", "show", "docker.service", "-p", "Requires", "--value").stdout.split()
    require(SERVICE not in dependencies, "Docker still requires this firewall through another configuration.")
    run("systemctl", "disable", "--now", REFRESH_TIMER.name, check=False)
    run("systemctl", "stop", SERVICE)
    run("systemctl", "disable", SERVICE)
    for path in (UNIT, REFRESH_UNIT, REFRESH_TIMER, SUDOERS, REGISTRY, EXE,
                 *(SHARE / "plugin" / name for name in PLUGIN_FILES)):
        path.unlink(missing_ok=True)
    for folder in (SHARE / "plugin", SHARE):
        if folder.exists():
            folder.rmdir()
    if purge:
        CONFIG.unlink(missing_ok=True)
        CONF.rmdir()
    run("systemctl", "daemon-reload")
    print("hermes-firewall removed. Docker was not restarted."
          + ("" if purge else f" Settings kept in {CONFIG} (remove with: uninstall --purge)."))


USAGE = """usage:
  hermes-firewall add PROFILE                     protect a Hermes profile (everything closed)
  hermes-firewall open PROFILE [for] [internet|lan|all] [DURATION]
  hermes-firewall close PROFILE [internet|lan|all]
  hermes-firewall status [PROFILE] [--verbose]
  hermes-firewall remove PROFILE                  remove the firewall; the sandbox then has no network
  hermes-firewall refresh | restore | uninstall [--purge]

examples (as the user running Hermes):
  sudo hermes-firewall add default                protect the default profile
  sudo hermes-firewall open default               Internet for 1 hour
  sudo hermes-firewall open default for lan 30m   LAN for 30 minutes, no Internet
  sudo hermes-firewall open default all 2h        Internet and LAN for 2 hours
  sudo hermes-firewall close default              close everything
  sudo hermes-firewall status                     all profiles: protected? open? time left

In a Hermes chat of a protected profile: /firewall open, /firewall open lan 30m,
/firewall close, /firewall status

DURATION: 30s, 10m, 2h, ... (default and maximum: /etc/hermes-firewall/config.toml).
Reopening restarts the time. A reboot closes everything. The host itself, other
private networks and everything not opened stay blocked."""


def parse(argv):
    """-> (words, options). Options are only accepted where they are listed."""
    words = [a for a in argv if not a.startswith("-")]
    options = {a.split("=", 1)[0]: a.split("=", 1)[1] if "=" in a else True for a in argv if a.startswith("-")}
    allowed = {"add": {"--yes"}, "status": {"--verbose"}, "uninstall": {"--purge"},
               "install": {"--bundle"}, "upgrade": {"--bundle"}}
    verb = words[0] if words else "status"
    # open/close are allowed via sudoers with any arguments: they take no options at all.
    unknown = set(options) - allowed.get(verb, set())
    require(not unknown, f"Unknown option for {verb}: {', '.join(sorted(unknown))}. See: hermes-firewall --help")
    return words or ["status"], options


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return
    if argv == ["--version"]:
        print(VERSION)
        return
    if argv[:1] == ["_hermes"]:
        user_command(argv)
        return
    words, options = parse(argv)
    require(sys.platform == "linux" and os.geteuid() == 0, "Run with sudo. --help works without.")
    import fcntl
    descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022, "Unsafe lock file; refusing concurrent state changes.")
        fcntl.flock(lock, fcntl.LOCK_EX)
        verb, rest = words[0], words[1:]
        if verb in ("install", "upgrade"):
            require(not rest and type(options.get("--bundle")) is str, "Use install.sh.")
            (install if verb == "install" else upgrade)(Path(options["--bundle"]).resolve())
            return
        data = load_registry()
        if verb == "restore" and not rest:
            # One atomic transaction; all leases intentionally reset on boot/restore.
            nft_apply(restore_transaction(data))
            print("All leases of all protected profiles are closed.")
        elif verb == "refresh" and not rest:
            refresh(data)
        elif verb == "uninstall" and not rest:
            uninstall(data, "--purge" in options)
        elif verb == "status" and len(rest) <= 1:
            user = hermes_user() if os.environ.get("SUDO_USER") and not rest else None
            status(data, user, rest[0] if rest else None, "--verbose" in options)
        elif verb == "add" and len(rest) == 1:
            add_profile(data, rest[0], hermes_user(), "--yes" in options)
        elif verb == "remove" and len(rest) == 1:
            remove_profile(data, rest[0])
        elif verb == "open" and rest:
            open_lease(data, rest[0], rest[1:])
        elif verb == "close" and rest:
            close_lease(data, rest[0], rest[1:])
        else:
            raise FirewallError("Did not understand that. See: hermes-firewall --help")


if __name__ == "__main__":
    try:
        main()
    except (FirewallError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)

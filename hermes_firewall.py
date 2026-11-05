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
# Last addresses of lan.hosts and DNS64 prefixes that resolved: used at boot when DNS is not up yet.
CACHE = CONF / "resolved.json"
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
STATE = Path("/run/hermes-firewall")
KINDS = ("internet", "lan")
LABEL = "hermes-firewall.profile"
PROFILE_RE = r"[a-z0-9][a-z0-9_-]{0,63}"  # Hermes' own profile id rule
SERVER_RE = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"  # MCP server names the Hermes CLI can address (no dots)
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
# MCP firewalls get a /28 from this range, because Docker's own pools only last for about 30 networks.
MCP_SUBNET = "172.31.240.0/20"
# DNS of an MCP container without names in its allow list: a documentation address nothing answers on.
# Without it, Docker's own resolver could still ask the host's DNS server for the container.
NO_DNS = "192.0.2.1"
# A name stays allowed this long after it last resolved to an address (services rotate their addresses).
MCP_ADDRESS_KEEP = 86400
# status --proof: public addresses to try. Blocked attempts never leave the host; allowed ones really connect.
PROOF_PUBLIC = {4: ("1.1.1.1", "9.9.9.9", "8.8.8.8"), 6: ("2606:4700:4700::1111", "2620:fe::fe", "2001:4860:4860::8888")}
# One connection attempt from the test endpoint; prints open, refused or timeout.
PROOF_PROBE = """import socket, sys
kind, host, port = sys.argv[1:]
family = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.connect((host, int(port)))
    if kind == "udp":
        s.send(bytes.fromhex("000101000001000000000000000001" "0001"))
        s.recv(512)
    print("open")
except socket.timeout:
    print("timeout")
except OSError:
    print("refused")
"""
# Docker options that let code leave any container, whatever its network.
ESCAPES = r"--privileged\S*|\S*docker\.sock\S*|--pid[= ]host|--userns[= ]host|--cap-add[= ](?:ALL|SYS_ADMIN)"
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


def identity(name):
    """The names of a firewall: of a profile, or of an MCP server ("PROFILE/SERVER")."""
    require(isinstance(name, str) and re.fullmatch(f"{PROFILE_RE}(/{SERVER_RE})?", name),
            f"Not a Hermes profile name: {name!r} (lowercase letters, digits, '_' and '-').")
    digest = hashlib.sha256(name.encode("ascii")).hexdigest()
    return {"bridge": "hfw" + digest[:12],
            "network": "hermes-mcp-" + name.replace("/", "-") if "/" in name else "hermes-fw-" + name,
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
    known = {"ipv6": None, "docker_requires_firewall": None, "mcp_subnet": None, "lease": {"default", "max"},
             "sandbox": {"dns"}, "lan": {"networks", "hosts"}, "hermes": {"egress_proxy"}, "allow": None, "mcp": None}
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
    conf["mcp_subnet"] = mcp_subnet(data.get("mcp_subnet", MCP_SUBNET))
    conf["mcp"] = mcp_servers_config(data.get("mcp", []), path)
    return conf


def mcp_subnet(text):
    try:
        network = ipaddress.ip_network(text)
    except (ValueError, TypeError):
        raise FirewallError(f"mcp_subnet is not a network: {text!r}") from None
    require(network.version == 4 and network.is_private and network.prefixlen <= 28,
            "mcp_subnet must be a private IPv4 network of /28 or larger.")
    return str(network)


def mcp_servers_config(entries, path):
    """[[mcp]] tables -> {"PROFILE/SERVER": allow list}. Every allowed target names its ports."""
    require(type(entries) is list, "Use [[mcp]] tables for the MCP servers.")
    servers = {}
    for entry in entries:
        require(type(entry) is dict and set(entry) <= {"profile", "server", "allow"} and {"profile", "server"} <= set(entry),
                f"mcp entries take profile, server and allow: {entry}")
        key = f"{entry['profile']}/{entry['server']}"
        identity(key)
        require(key not in servers, f"Two [[mcp]] entries for {key} in {path}.")
        allow = entry.get("allow", [])
        require(type(allow) is list, f"mcp {key}: allow must be a list.")
        servers[key] = []
        for target in allow:
            require(type(target) is dict and set(target) <= {"net", "host", "tcp", "udp"}
                    and len(set(target) & {"net", "host"}) == 1,
                    f"mcp {key}: allow entries take net or host, and tcp/udp: {target}")
            item = {"tcp": ports(target, "tcp"), "udp": ports(target, "udp")}
            require(item["tcp"] or item["udp"], f"mcp {key}: name the allowed ports (tcp, udp) of {target}.")
            if "host" in target:
                require(type(target["host"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", target["host"]),
                        f"mcp {key}: not a host name: {target['host']!r}")
                item["host"] = target["host"]
            else:
                try:
                    item["net"] = str(ipaddress.ip_network(target["net"]))
                except (ValueError, TypeError):
                    raise FirewallError(f"mcp {key}: not an address or network: {target['net']!r}") from None
                require(ipaddress.ip_network(item["net"]).prefixlen > 0,
                        f"mcp {key}: a whole address family would disable the firewall.")
            servers[key].append(item)
    return servers


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
        require(offset + length <= len(data), "Truncated DNS record.")
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
            except (OSError, FirewallError, IndexError, ValueError) as error:
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
    """The well-known NAT64 prefix plus /96 prefixes announced by DNS64 (ipv4only.arpa, RFC 7050).

    Raises OSError if the DNS servers do not answer."""
    prefixes = [NAT64_WKP]
    for answer in resolve("ipv4only.arpa", servers, 28):
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
            found.append(f"{item['local']}/{item['prefixlen']}")
    # On-link routes cover e.g. the /64 behind a DHCPv6 /128 address.
    for version in ("-4", "-6"):
        for route in json.loads(run("ip", "-j", version, "route", "show", "table", "main").stdout or "[]"):
            if not route.get("gateway") and route.get("dst", "default") != "default" \
                    and route.get("type", "unicast") == "unicast" \
                    and not route.get("dev", "").startswith(VIRTUAL_INTERFACES):
                found.append(route["dst"])
    networks = []
    for item in found:
        try:
            networks.append(lan_network(str(ipaddress.ip_network(item, strict=False))))
        except (FirewallError, ValueError):
            continue  # e.g. a public IPv4 address of the host: never LAN
    return unique(networks)


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


def load_cache():
    if not CACHE.exists():
        return {"hosts": {}, "nat64": []}
    trusted(CACHE)
    data = json.loads(CACHE.read_text(encoding="utf-8"))
    require(type(data) is dict and type(data.get("hosts")) is dict and type(data.get("nat64")) is list,
            f"Invalid {CACHE}; delete it.")
    return data


def common_sets(conf, strict=False):
    """Set elements shared by all profiles (everything except the per-user host ports).

    strict: fail if a name does not resolve (refresh keeps the current sets). Otherwise
    (boot, before DNS works) use the last addresses that resolved."""
    cache = load_cache()
    old = json.dumps(cache, sort_keys=True)
    lan = []
    for network in conf["lan_networks"]:
        lan += host_networks() if network == "auto" else [network]
    for host in conf["lan_hosts"]:
        try:
            cache["hosts"][host] = resolve_host(host, conf["dns"])
        except OSError as error:
            require(not strict, f"Cannot resolve LAN host {host}: {error}; addresses left unchanged.")
            print(f"WARNING: cannot resolve LAN host {host} ({error}); using its last known addresses "
                  f"{cache['hosts'].get(host) or '(none)'}.", file=sys.stderr)
        lan += cache["hosts"].get(host, [])
    try:
        cache["nat64"] = nat64_prefixes(conf["dns"])
    except OSError as error:
        require(not strict, f"DNS64 lookup failed: {error}; addresses left unchanged.")
    prefixes = unique([NAT64_WKP, *cache["nat64"]])
    if json.dumps(cache, sort_keys=True) != old:
        atomic_write(CACHE, json.dumps(cache, indent=2, sort_keys=True) + "\n")
    lan4 = [a for a in lan if family(a) == 4]
    whole = [e["net"] for e in conf["allow"] if not e["tcp"] and not e["udp"]]
    return {"lan_v4": unique(lan4), "lan_v6": unique([a for a in lan if family(a) == 6] + nat64(prefixes, lan4)),
            "dns_v4": [d for d in conf["dns"] if family(d) == 4], "dns_v6": [d for d in conf["dns"] if family(d) == 6],
            "allow_v4": [n for n in whole if family(n) == 4], "allow_v6": [n for n in whole if family(n) == 6],
            **service_sets(conf["allow"]),
            "non_public_v6": [*NONPUBLIC_V6, *nat64(prefixes, NONPUBLIC_V4)]}


def service_sets(allow):
    """allow_ports_v4/v6 of allow entries with ports. Overlapping networks for the same port would
    make nft refuse the whole table, so they are collapsed."""
    groups = {}
    for entry in allow:
        for proto in ("tcp", "udp"):
            for port in entry[proto]:
                network = ipaddress.ip_network(entry["net"])
                groups.setdefault((network.version, proto, port), []).append(network)
    services = [f"{network} . {proto} . {port}" for (_, proto, port), items in sorted(groups.items())
                for network in ipaddress.collapse_addresses(items)]
    return {"allow_ports_v4": unique(s for s in services if family(s.split()[0]) == 4),
            "allow_ports_v6": unique(s for s in services if family(s.split()[0]) == 6)}


def mcp_dns(conf, key):
    """DNS servers of an MCP container: only a server with names in its allow list needs real ones."""
    return conf["dns"] if any("host" in target for target in conf["mcp"].get(key, [])) else [NO_DNS]


def mcp_addresses(conf):
    """{host: [addresses]} of the names in MCP allow lists: all seen recently, because services rotate
    their addresses and the container may get another answer than the firewall. A failed lookup keeps
    the known addresses; a name that never resolved allows nothing."""
    cache = load_cache()
    old = json.dumps(cache, sort_keys=True)
    seen, now = cache.setdefault("mcp_hosts", {}), int(time.time())
    hosts = {target["host"] for allow in conf["mcp"].values() for target in allow if "host" in target}
    for host in sorted(hosts):
        try:
            seen.setdefault(host, {}).update(dict.fromkeys(resolve_host(host, conf["dns"]), now))
        except OSError as error:
            print(f"WARNING: cannot resolve MCP allow-list name {host} ({error}); using its known addresses "
                  f"{sorted(seen.get(host, {})) or '(none)'}.", file=sys.stderr)
    cache["mcp_hosts"] = {host: fresh for host in sorted(hosts)
                          if (fresh := {a: when for a, when in seen.get(host, {}).items() if now - when < MCP_ADDRESS_KEEP})}
    if json.dumps(cache, sort_keys=True) != old:
        atomic_write(CACHE, json.dumps(cache, indent=2, sort_keys=True) + "\n")
    return {host: sorted(addresses) for host, addresses in cache["mcp_hosts"].items()}


def mcp_sets(conf, key, addresses):
    """Set elements of an MCP firewall: only its allow list, and DNS only if that list has names."""
    allow = []
    for target in conf["mcp"].get(key, []):
        nets = [target["net"]] if "net" in target else addresses.get(target["host"], [])
        allow += [{"net": str(ipaddress.ip_network(net)), "tcp": target["tcp"], "udp": target["udp"]} for net in nets]
    dns = [] if mcp_dns(conf, key) == [NO_DNS] else conf["dns"]
    return {"dns_v4": [d for d in dns if family(d) == 4], "dns_v6": [d for d in dns if family(d) == 6],
            **service_sets(allow)}


def free_subnet(data, conf):
    """The first /28 of mcp_subnet that no MCP firewall, Docker network or route of this host uses."""
    used = [r["subnet"] for r in data.get("mcp", {}).values()]
    ids = run("docker", "network", "ls", "-q").stdout.split()
    for network in json.loads(run("docker", "network", "inspect", *ids).stdout) if ids else []:
        used += [c["Subnet"] for c in (network.get("IPAM") or {}).get("Config") or [] if c.get("Subnet")]
    used += [r["dst"] for r in json.loads(run("ip", "-j", "-4", "route", "show", "table", "main").stdout or "[]")
             if r.get("dst", "default") != "default"]
    taken = [ipaddress.ip_network(u, strict=False) for u in used if family(u) == 4]
    for candidate in ipaddress.ip_network(conf["mcp_subnet"]).subnets(new_prefix=28):
        if not any(candidate.overlaps(u) for u in taken):
            return str(candidate)
    raise FirewallError(f"No free network left in mcp_subnet {conf['mcp_subnet']}; set a larger one in {CONFIG}.")


def profile_sets(record, common, proxies):
    try:
        uid = pwd.getpwnam(record["user"]).pw_uid
    except KeyError:
        uid = None
    return {**common, "host_ports_v4": proxies.get(uid, [])}


# --- nftables ------------------------------------------------------------------------------

def drop_table(table):
    """Delete a table if it exists, in any nft version ("destroy table" needs nft >= 1.0.8)."""
    return f"table inet {table}\ndelete table inet {table}\n"


def elements(items):
    return f"elements = {{ {', '.join(items)} }}" if items else ""


# Blocked connections from a sandbox fail at once instead of timing out: TCP gets a reset ("Connection
# refused"; not subject to the kernel's ICMP rate limit, so many parallel connects all fail fast),
# everything else ICMP "administratively prohibited". host_output_guard lets exactly these errors from
# the host reach the sandbox. Traffic from outside to a sandbox is still dropped silently.
#
# Lookups with ports use ip protocol / ip6 nexthdr, never meta l4proto: nft before 1.1.0 adds a byteorder
# step for it in interval sets, and kernels since 6.12.115, 6.18.59 and 7.1 refuse the whole table for that.


def chains(bridge):
    """The four chains of a profile table (the rule layout without set contents)."""
    return f'''    chain outbound {{
        ip daddr @dns_v4 meta l4proto {{ tcp, udp }} th dport 53 counter return
        ip6 daddr @dns_v6 meta l4proto {{ tcp, udp }} th dport 53 counter return
        ip daddr @allow_v4 counter return
        ip6 daddr @allow_v6 counter return
        ip daddr . ip protocol . th dport @allow_ports_v4 counter return
        ip6 daddr . ip6 nexthdr . th dport @allow_ports_v6 counter return
        ip daddr @lan_v4 iifname @open_lan counter return
        ip6 daddr @lan_v6 iifname @open_lan counter return
        ip daddr @lan_v4 meta l4proto tcp counter reject with tcp reset
        ip daddr @lan_v4 counter reject with icmpx type admin-prohibited
        ip6 daddr @lan_v6 meta l4proto tcp counter reject with tcp reset
        ip6 daddr @lan_v6 counter reject with icmpx type admin-prohibited
        ip daddr @non_public_v4 meta l4proto tcp counter reject with tcp reset
        ip daddr @non_public_v4 counter reject with icmpx type admin-prohibited
        ip6 daddr @non_public_v6 meta l4proto tcp counter reject with tcp reset
        ip6 daddr @non_public_v6 counter reject with icmpx type admin-prohibited
        iifname @open_internet counter return
        meta l4proto tcp counter reject with tcp reset
        counter reject with icmpx type admin-prohibited
    }}
    chain forward_guard {{
        type filter hook forward priority -10; policy accept;
        iifname "{bridge}" jump outbound
        oifname "{bridge}" ip saddr @dns_v4 meta l4proto {{ tcp, udp }} th sport 53 ct state established,related counter return
        oifname "{bridge}" ip6 saddr @dns_v6 meta l4proto {{ tcp, udp }} th sport 53 ct state established,related counter return
        oifname "{bridge}" ip saddr @allow_v4 ct state established,related counter return
        oifname "{bridge}" ip6 saddr @allow_v6 ct state established,related counter return
        oifname "{bridge}" ip saddr . ip protocol . th sport @allow_ports_v4 ct state established,related counter return
        oifname "{bridge}" ip6 saddr . ip6 nexthdr . th sport @allow_ports_v6 ct state established,related counter return
        oifname "{bridge}" oifname @open_internet ct state established,related counter return
        oifname "{bridge}" oifname @open_lan ip saddr @lan_v4 ct state established,related counter return
        oifname "{bridge}" oifname @open_lan ip6 saddr @lan_v6 ct state established,related counter return
        oifname "{bridge}" counter drop
    }}
    chain host_input_guard {{
        type filter hook input priority -10; policy accept;
        iifname "{bridge}" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} counter return
        iifname "{bridge}" ip daddr . ip protocol . th dport @host_ports_v4 counter return
        iifname "{bridge}" meta l4proto tcp counter reject with tcp reset
        iifname "{bridge}" counter reject with icmpx type admin-prohibited
    }}
    chain host_output_guard {{
        type filter hook output priority -10; policy accept;
        oifname "{bridge}" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, packet-too-big, destination-unreachable, time-exceeded }} counter return
        oifname "{bridge}" icmp type {{ destination-unreachable, time-exceeded }} counter return
        oifname "{bridge}" tcp flags rst counter return
        oifname "{bridge}" ip saddr . ip protocol . th sport @host_ports_v4 ct state established counter return
        oifname "{bridge}" counter drop
    }}
'''


def layout(bridge):
    """Fingerprint of the rule layout: health() reloads tables whose rules differ, not only in number."""
    return hashlib.sha256(chains(bridge).encode()).hexdigest()[:12]


def rules(profile, sets=None):
    sets = sets or {}
    item = identity(profile)
    table, bridge = item["table"], item["bridge"]
    declarations = "".join(f"    set {name} {{\n        type {kind};{flags}\n        {elements(sets.get(name, ()))}\n    }}\n"
                           for name, kind, flags in SETS)
    return drop_table(table) + f'''table inet {table} {{
    comment "hermes-firewall {VERSION} layout {layout(bridge)}"
    set open_internet {{ type ifname; flags timeout; timeout 1h; size 1; }}
    set open_lan {{ type ifname; flags timeout; timeout 1h; size 1; }}
    set non_public_v4 {{
        type ipv4_addr; flags interval;
        {elements(NONPUBLIC_V4)}
    }}
{declarations}{chains(bridge)}}}
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


def targets(data):
    """All firewalls: protected profiles and MCP servers ("PROFILE/SERVER")."""
    return sorted([*data["profiles"], *data.get("mcp", {})])


def refresh_transaction(data, sets):
    """Replace all address sets of every table; leases stay untouched. sets: {name: {set: [..]}}."""
    text = ""
    for profile in targets(data):
        table = identity(profile)["table"]
        for name, _, _ in SETS:
            text += f"flush set inet {table} {name}\n"
            if sets[profile].get(name):
                text += f"add element inet {table} {name} {{ {', '.join(sets[profile][name])} }}\n"
    return text


def all_sets(data, strict=False):
    conf = load_config()
    result = {}
    if data["profiles"]:
        common, proxies = common_sets(conf, strict), proxy_ports(conf)
        result = {p: profile_sets(r, common, proxies) for p, r in data["profiles"].items()}
    if data.get("mcp"):
        addresses = mcp_addresses(conf)
        result.update({key: mcp_sets(conf, key, addresses) for key in data["mcp"]})
    return result


def restore_transaction(data):
    sets = all_sets(data)
    return "".join(rules(name, sets[name]) for name in targets(data))


# --- state ---------------------------------------------------------------------------------

def trusted(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            f"Not root-owned / writable by others / symlink: {path}")


def replaceable_by_others(path):
    """Path and every directory above it that a non-root user could change: not owned by root,
    or writable by others (group-writable only for group root). sudo runs EXE without a password,
    so nobody but root may be able to replace it."""
    found = []
    for item in [Path(path), *Path(path).parents]:
        try:
            info = os.lstat(item) if item == Path(path) else os.stat(item)
        except FileNotFoundError:
            continue  # not installed yet: the directories above still count
        group_writable = info.st_mode & 0o020 and info.st_gid != 0
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o002 or group_writable:
            found.append(str(item))
    return found


def require_safe_program():
    unsafe = replaceable_by_others(EXE)
    require(not unsafe, f"{', '.join(unsafe)}: not owned by root or writable by others, so the program that "
                        f"sudo runs without a password could be replaced. Fix: chown root and chmod go-w.")


def validate_registry(data):
    require(type(data) is dict and data.get("version") == 2 and type(data.get("profiles")) is dict,
            f"Invalid {REGISTRY}; no automatic repair was attempted.")
    seen = set()
    require(type(data.get("mcp", {})) is dict, f"Invalid {REGISTRY}; no automatic repair was attempted.")
    for name, record in [*data["profiles"].items(), *data.get("mcp", {}).items()]:
        bridge = identity(name)["bridge"]
        fields = {"user", "ipv6", "subnet", "dns"} if "/" in name else {"user", "ipv6", "label", "dns"}
        require(type(record) is dict and set(record) == fields
                and type(record["user"]) is str and type(record["ipv6"]) is bool
                and type(record.get("label", "")) is str and type(record.get("subnet", "")) is str
                and type(record["dns"]) is list
                and ("/" in name) == (name in data.get("mcp", {})),
                f"Invalid registry entry for {name}.")
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


def run(*arguments, input=None, check=True, session=False):
    executable = shutil.which(arguments[0], path=ENV["PATH"])
    require(executable, f"Missing command: {arguments[0]}")
    # Children never get the admin's terminal: no stdin, and a new session on request.
    stdin = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
    result = subprocess.run([executable, *arguments[1:]], **stdin, text=True, capture_output=True,
                            env=ENV, timeout=90, start_new_session=session)
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
    # From the text output: nft < 1.1 leaves table comments out of its JSON.
    comment = re.search(r'^\s*comment "([^"]*)"', run("nft", "list", "table", "inet", item["table"]).stdout, re.M)
    require(comment and comment[1].endswith(f"layout {layout(item['bridge'])}"),
            "Firewall rules are from another version; sudo hermes-firewall restore loads the current ones.")


def set_elements(profile, name):
    """What the kernel currently has in a set of this profile."""
    data = json.loads(run("nft", "--json", "list", "set", "inet", identity(profile)["table"], name).stdout)
    result = []
    for row in data["nftables"]:
        for element in row.get("set", {}).get("elem", []):
            if isinstance(element, dict) and "elem" in element:
                element = element["elem"].get("val")
            if isinstance(element, dict) and "concat" in element:
                result.append(" ".join(f"{p['prefix']['addr']}/{p['prefix']['len']}" if isinstance(p, dict) and "prefix" in p
                                       else str(p) for p in element["concat"]))
            elif isinstance(element, dict) and "prefix" in element:
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


def write_state(profile):
    """Lease end times for the plugin's status line, readable without sudo. The kernel decides, this
    only reports: a failure just warns, and the next refresh writes the file again."""
    try:
        now = int(time.time())
        remaining = {kind: lease_remaining(profile, kind) for kind in KINDS}
        STATE.mkdir(exist_ok=True)
        STATE.chmod(0o755)
        atomic_write(STATE / f"{profile}.json",
                     json.dumps({k: None if s is None else now + s for k, s in remaining.items()}) + "\n")
    except (FirewallError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"WARNING: status file of {profile} not written: {error}", file=sys.stderr)


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


def config_section(profile, section, *options):
    output = hermes("-p", profile, "config", "get", section, "--json", *options)
    try:
        settings = json.loads(output)
    except ValueError:
        raise FirewallError(f"Unexpected output of 'hermes -p {profile} config get {section} --json'.") from None
    require(type(settings) is dict, f"Unexpected {section} settings of Hermes profile {profile}.")
    return settings


def terminal_settings(profile):
    return config_section(profile, "terminal")


def egress_enforced(profile):
    """Hermes' egress proxy with enforce_on_docker refuses any --network= in docker_extra_args."""
    try:
        proxy = config_section(profile, "proxy")
    except FirewallError:
        return False  # no proxy section: proxy not configured
    return bool(proxy.get("enabled")) and proxy.get("enforce_on_docker", True) is not False


def container_label(profile, key=""):
    """The hermes-profile label Hermes puts on this profile's sandboxes."""
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
    require(not egress_enforced(profile),
            f"The Hermes egress proxy of {profile} refuses sandbox networks (proxy.enforce_on_docker), so its "
            "sandbox would not start behind hermes-firewall. The proxy keeps protecting your API keys without it.\n"
            f"To use both: hermes -p {profile} config set proxy.enforce_on_docker false")
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
    arguments = [str(a) for a in settings.get("docker_extra_args") or []]
    for argument in arguments:
        firewall_arg(argument)
    escapes = re.findall(ESCAPES, " ".join(arguments + [str(v) for v in settings.get("docker_volumes") or []]))
    if escapes:
        hints.append(f"Warning: {', '.join(escapes)} lets code escape the sandbox; no firewall can contain it then.")
    return {"key": key, "hints": hints}


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


def mcp_servers(profile):
    """The mcp_servers section as Hermes resolves it (${VAR} expanded), not masked; {} if there is none."""
    try:
        return config_section(profile, "mcp_servers", "--raw")
    except FirewallError as error:
        if "not set" in str(error):
            return {}
        raise


def config_file_text(profile):
    """The profile's config.yaml as it is on disk; "" if unreadable."""
    try:
        return (hermes_home(Path.home(), profile) / "config.yaml").read_text(encoding="utf-8")
    except (OSError, ValueError):
        return ""


def own_mcp_args(arguments):
    """`docker run` arguments -> (what the firewall put right after `run`, everything else)."""
    own = []
    for argument in arguments[1:]:
        if not re.fullmatch(r"--network=(none|hermes-mcp-\S+)|--dns=\S+", argument):
            break
        own.append(argument)
    return own, arguments[len(own) + 1:]


def mcp_state(profile, name, entry, config_text):
    """How an mcp_servers entry stands to the firewall: (state, what to tell the user). The states:
    protected, isolated (no network), ready (can be written), manual (a hint only), refused, url, host, off.

    Only a plain `docker run` whose arguments are literally in config.yaml is ever changed: Hermes hands
    out values with ${VAR} already expanded, and writing those back would put secrets into the file."""
    fix = f"sudo hermes-firewall mcp add {profile} {name}"
    if entry.get("enabled") is False:
        return "off", "is switched off."
    if entry.get("url"):
        return "url", "is reached over HTTP (url); Hermes does not start it, so no firewall is set up for it."
    command = str(entry.get("command") or "")
    arguments = [str(a) for a in entry.get("args") or []] if type(entry.get("args") or []) is list else []
    everything = " ".join([command, *arguments])
    docker = Path(command).name == "docker"
    if not docker and not re.search(r"\b(docker|podman)\b", everything):
        return "host", f"runs directly on the host ({Path(command).name}), not in a container: no firewall possible."
    if not re.fullmatch(SERVER_RE, name):
        return "refused", "has a name the Hermes CLI cannot address (use letters, digits, '_' and '-'); rename it first."
    escapes = re.findall(ESCAPES, everything)
    if escapes:
        return "refused", f"uses {', '.join(escapes)}, so code can leave the container; no firewall can contain it."
    if type(entry.get("env")) is dict and {"DOCKER_HOST", "DOCKER_CONTEXT"} & set(entry["env"]):
        return "refused", "sets DOCKER_HOST or DOCKER_CONTEXT in its env, so it may start on a Docker this firewall does not protect."
    network = identity(f"{profile}/{name}")["network"]
    manual = (f"starts Docker in a way hermes-firewall does not change by itself ({{}}). {fix} creates its network; "
              f"then add --network={network} to its command yourself.")
    if not docker or arguments[:1] != ["run"]:
        if network in everything:
            return "protected", "runs in Docker behind its firewall (set up by hand)."
        return "manual", manual.format("no plain docker run")
    own, rest = own_mcp_args(arguments)
    foreign = [a for a in rest if re.fullmatch(r"--(network|net|dns)(=.*)?", a)]
    if foreign:
        return "refused", f"sets {foreign[0]} itself; remove that from its args first, then: {fix}"
    if f"--network={network}" in own:
        return "protected", "runs in Docker behind its firewall."
    if "--network=none" in own:
        return "isolated", "runs in Docker without any network."
    if any(a.startswith("--network=") for a in own):
        return "refused", f"uses the firewall network of another MCP server; remove that from its args first, then: {fix}"
    if not all(a in config_text for a in arguments):
        return "manual", manual.format("its args use ${VAR} or special quoting")
    return "ready", f"runs in Docker WITHOUT a firewall. Fix: add an [[mcp]] entry to {CONFIG}, then: {fix}"


def hermes_mcp_scan(profile):
    text = config_file_text(profile)
    report = []
    for name, entry in sorted(mcp_servers(profile).items()):
        state, message = mcp_state(profile, name, entry, text) if type(entry) is dict else ("off", "is not a valid entry.")
        report.append({"name": name, "state": state, "text": message})
    print(json.dumps(report))


def set_mcp_args(profile, server, wanted):
    hermes("-p", profile, "config", "set", f"mcp_servers.{server}.args", json.dumps(wanted))
    require(mcp_servers(profile).get(server, {}).get("args") == wanted,
            f"Hermes did not take the new arguments of MCP server {server}; check {server} in its config.yaml.")


def hermes_mcp_attach(profile, server):
    """Put the server's firewall network right after `docker run`; the rest stays as it is."""
    key, conf = f"{profile}/{server}", load_config()
    entry = mcp_servers(profile).get(server)
    require(type(entry) is dict, f"{profile} has no MCP server {server}.")
    # A server that is switched off counts as it is: the firewall can be set up before it runs.
    state, message = mcp_state(profile, server, {**entry, "enabled": True}, config_file_text(profile))
    require(state in ("ready", "isolated", "protected", "manual"), f"MCP server {server} {message}")
    arguments = [str(a) for a in entry.get("args") or []]
    if state == "manual" or arguments[:1] != ["run"]:
        return  # the user set it up by hand, or will
    wanted = ["run", f"--network={identity(key)['network']}", *(f"--dns={s}" for s in mcp_dns(conf, key)),
              *own_mcp_args(arguments)[1]]
    if wanted != arguments:
        require(all(a in config_file_text(profile) for a in arguments),
                f"The args of MCP server {server} use ${{VAR}} or special quoting: change them yourself: {' '.join(wanted[:-1])}")
        set_mcp_args(profile, server, wanted)


def hermes_mcp_detach(profile, server):
    """Without its firewall the server gets NO network, never an unfiltered one."""
    entry = mcp_servers(profile).get(server)
    if type(entry) is not dict:
        return
    arguments = [str(a) for a in entry.get("args") or []]
    if Path(str(entry.get("command") or "")).name == "docker" and arguments[:1] == ["run"] \
            and all(a in config_file_text(profile) for a in arguments):
        set_mcp_args(profile, server, ["run", "--network=none", *own_mcp_args(arguments)[1]])
        print("It runs without any network now.")
    else:
        print(f"Its command still names the removed network, so it will not start: change it in the args of {server}.")


def user_command(words):
    """`_hermes info|attach|detach PROFILE` and `_hermes mcp-scan PROFILE`, `_hermes mcp-attach|mcp-detach
    PROFILE SERVER`: called by root via runuser as the Hermes user."""
    require(os.geteuid() != 0, "Internal command; it runs as the Hermes user, not as root.")
    action = words[1] if len(words) > 1 else ""
    if action in ("mcp-attach", "mcp-detach"):
        require(len(words) == 4, "Unknown internal command.")
        identity(f"{words[2]}/{words[3]}")
        (hermes_mcp_attach if action == "mcp-attach" else hermes_mcp_detach)(words[2], words[3])
        return
    require(len(words) == 3 and action in ("info", "attach", "detach", "mcp-scan"), "Unknown internal command.")
    profile = words[2]
    require(re.fullmatch(PROFILE_RE, profile), f"Not a Hermes profile name: {profile!r}")
    if action == "info":
        print(json.dumps(hermes_info(profile)))
    elif action == "attach":
        hermes_attach(profile, load_config()["dns"])
    elif action == "mcp-scan":
        hermes_mcp_scan(profile)
    else:
        hermes_detach(profile)


def hermes_user():
    name = os.environ.get("SUDO_USER", "")
    require(name and name != "root", "Run this with sudo from the account that runs Hermes.")
    return pwd.getpwnam(name)


def printable(text):
    """Output of user-controlled processes without terminal control sequences."""
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text)


def as_user(user, *arguments):
    """Hermes files are changed by the user's own process, never by root.

    Its output is not trusted: login shells may print anything."""
    command = shlex.join([str(EXE), "_hermes", *arguments])
    result = run("runuser", "-l", user.pw_name, "-c", command, check=False, session=True)
    message = printable(result.stderr.strip()).removeprefix("ERROR: ")
    require(result.returncode == 0, message or f"{command} failed as {user.pw_name}.")
    return printable(result.stdout)


# --- sandboxes -----------------------------------------------------------------------------

def sandboxes(label):
    ids = run("docker", "ps", "-aq", "--filter", "label=hermes-agent=1",
              "--filter", f"label=hermes-profile={label}").stdout.split()
    return json.loads(run("docker", "inspect", *ids).stdout) if ids else []


def kept_text(container):
    folders = sorted({m["Destination"] for m in container.get("Mounts") or []
                      if m.get("Type") in ("bind", "volume") and m.get("RW", True)})
    if not folders:
        return "  Kept:  chats, memory, skills, settings\n" \
               "  Lost:  everything inside the sandbox (files and installed programs)"
    return f"  Kept:  your files in {', '.join(folders)}; chats, memory, skills, settings\n" \
           "  Lost:  programs installed inside the sandbox and files stored elsewhere in it"


def protect_sandboxes(profile, record, conf, interactive=False, yes=False):
    """Move sandboxes of this profile into its firewall; returns messages for the user.

    Moving only ever restricts access, so it happens without asking. A sandbox that
    cannot be moved (host or no network) or keeps old DNS servers needs a reset."""
    network, messages = identity(profile)["network"], []
    for container in sandboxes(record["label"]):
        mode = (container.get("HostConfig") or {}).get("NetworkMode") or ""
        attached = set((container.get("NetworkSettings") or {}).get("Networks") or {})
        if any(name.startswith("hermes-fw-") and name != network for name in attached):
            continue  # protected by another profile's firewall: not ours to move
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
        # add without a terminal cannot ask: then the fix is add --yes, not the same command again.
        fix = f"sudo hermes-firewall add {profile}" + (" --yes" if interactive and not sys.stdin.isatty() else "")
        if mode == "host" or mode.startswith("container:"):
            messages.append(f"{profile}: WARNING - a sandbox of this profile is NOT protected ({reason}). Fix: {fix}")
        else:
            messages.append(f"{profile}: a sandbox of this profile needs a reset ({reason}). Fix: {fix}")
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
    require("/" not in profile, f"{profile} is an MCP firewall: it never opens. Its allow list is in {CONFIG}.")
    require(profile in data["profiles"], f"{profile} is not protected. To protect it: sudo hermes-firewall add {profile}")
    return data["profiles"][profile]


def docker_nat66(daemon_json=Path("/etc/docker/daemon.json")):
    """Does Docker masquerade IPv6 of bridge networks? Default since Docker 27 ("ip6tables")."""
    version = run("docker", "info", "--format", "{{.ServerVersion}}").stdout.strip()
    major = int(re.match(r"(\d+)", version)[1]) if re.match(r"\d+", version) else 0
    try:
        daemon = json.loads(daemon_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        daemon = {}
    if "ip6tables" in daemon:
        return bool(daemon["ip6tables"]) and (major >= 27 or bool(daemon.get("experimental")))
    return major >= 27


def ipv6_enabled(conf):
    """ipv6 = "auto": only if the host has IPv6 Internet AND Docker translates it (else it never arrives)."""
    if conf["ipv6"] != "auto":
        return conf["ipv6"]
    return bool(json.loads(run("ip", "-j", "-6", "route", "show", "default").stdout or "[]")) and docker_nat66()


def create_firewall(data, profile, record, conf):
    item = identity(profile)
    require(all(item["bridge"] != identity(p)["bridge"] for p in targets(data)), "Bridge collision.")
    docker_ready()
    run("systemctl", "is-active", "--quiet", SERVICE)
    require(item["network"] not in networks(), f"Network already exists: {item['network']}")
    require(item["table"] not in table_names(), f"Firewall table already exists: {item['table']}")
    require(not interface_exists(item["bridge"]), f"Interface already exists: {item['bridge']}")
    if "/" in profile:
        sets = mcp_sets(conf, profile, mcp_addresses(conf))
    else:
        sets = profile_sets(record, common_sets(conf, strict=True), proxy_ports(conf))
    text = rules(profile, sets)
    run("nft", "--check", "--file", "-", input=text)
    (data.setdefault("mcp", {}) if "/" in profile else data["profiles"])[profile] = record
    # Persist protection BEFORE making a network available; partial failure stays closed.
    save_registry(data)
    nft_apply(text)
    create_network(profile, record)


def create_network(profile, record):
    item = identity(profile)
    ipv6 = ["--ipv6", "--subnet", item["subnet6"]] if record["ipv6"] else ["--ipv6=false"]
    subnet = ["--subnet", record["subnet"]] if record.get("subnet") else []
    run("docker", "network", "create", "--driver", "bridge", *ipv6, *subnet,
        "--opt", f"com.docker.network.bridge.name={item['bridge']}",
        "--opt", "com.docker.network.bridge.enable_icc=false",
        "--label", f"{LABEL}={profile}", item["network"])


def restart_hint(profile):
    """Running Hermes processes load plugins and settings only when they start."""
    return (f"Restart what runs Hermes for {profile}: the gateway (hermes -p {profile} gateway restart) and the\n"
            f"backend of the desktop app (hermes -p {profile} dashboard --stop, then start it again); then start a new chat.")


def add_profile(data, profile, user, yes=False):
    require(re.fullmatch(PROFILE_RE, profile), f"Not a Hermes profile name: {profile!r}")
    require(hermes_home(user.pw_dir, profile).is_dir(),
            f"No Hermes profile {profile} for {user.pw_name} ({hermes_home(user.pw_dir, profile)} missing).")
    existing = data["profiles"].get(profile)
    require(not existing or existing["user"] == user.pw_name,
            f"{profile} is protected for user {existing and existing['user']}; run add as that user.")
    conf = load_config()
    # The last line: login shells may print their own greetings first.
    answer = as_user(user, "info", profile)  # its own errors (e.g. no Docker backend) pass through
    try:
        info = json.loads((answer.strip().splitlines() or [""])[-1])
        require(type(info) is dict and type(info.get("key")) is str and len(info["key"]) <= 256
                and type(info.get("hints")) is list and all(type(h) is str for h in info["hints"]), "")
    except (ValueError, FirewallError):
        raise FirewallError(f"Unexpected answer when checking Hermes profile {profile}.") from None
    label = container_label(profile, info["key"])
    clash = [p for p, r in data["profiles"].items() if p != profile and r["label"] == label]
    if clash:
        raise FirewallError(f"The sandboxes of {profile} would be mixed up with those of {clash[0]}; "
                            "check terminal.docker_shared_container_key.")
    if existing:
        health(profile)  # Re-running add repairs the network, the Hermes side and the sandboxes.
        existing["label"] = label
        docker_ready()
        if identity(profile)["network"] not in networks():
            create_network(profile, existing)
        check_network(profile, existing)
    else:
        record = {"user": user.pw_name, "ipv6": ipv6_enabled(conf), "label": label, "dns": []}
        create_firewall(data, profile, record, conf)
    as_user(user, "attach", profile)
    data["profiles"][profile]["dns"] = conf["dns"]
    save_registry(data)
    write_sudoers(data)
    for message in [*info["hints"], *protect_sandboxes(profile, data["profiles"][profile], conf, True, yes),
                    *mcp_warnings(profile, user)]:
        print(message)
    write_state(profile)
    print(profile_line(profile))
    print(restart_hint(profile) + "\n"
          "In the chat: /firewall open, /firewall open lan 30m, /firewall close, /firewall status")


def remove_profile(data, profile):
    record = record_of(data, profile)
    item = identity(profile)
    servers = [key.split("/")[1] for key in data.get("mcp", {}) if key.startswith(f"{profile}/")]
    require(not servers, f"First remove the MCP firewalls of {profile}: sudo hermes-firewall mcp remove {profile} {servers[0] if servers else ''}")
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
    nft_apply(drop_table(item["table"]))
    (STATE / f"{profile}.json").unlink(missing_ok=True)
    del data["profiles"][profile]
    save_registry(data)
    write_sudoers(data)
    print(f"{profile}: firewall removed. Its sandbox now has no network at all.")
    print(restart_hint(profile))


def open_lease(data, profile, words):
    record = record_of(data, profile)
    conf = load_config()
    kinds, seconds = open_arguments(words, conf)
    health(profile)
    docker_ready()
    check_network(profile, record)
    nft_apply(lease_transaction(profile, kinds, seconds))
    write_state(profile)
    print(profile_line(profile))


def close_lease(data, profile, words):
    record_of(data, profile)
    require(len(words) <= 1, "Usage: hermes-firewall close PROFILE [internet|lan|all]")
    nft_apply(lease_transaction(profile, lease_kinds(words[0] if words else "all")))
    write_state(profile)
    print(profile_line(profile))


# --- MCP servers ----------------------------------------------------------------------------

def mcp_report(user, profile):
    """The profile's MCP servers as seen by the Hermes user's process; its output is not trusted."""
    answer = as_user(user, "mcp-scan", profile)
    try:
        report = json.loads((answer.strip().splitlines() or [""])[-1])
        require(type(report) is list and all(type(s) is dict and {type(s.get(k)) for k in ("name", "state", "text")} == {str}
                                             for s in report), "")
    except (ValueError, FirewallError):
        raise FirewallError(f"Unexpected answer when reading the MCP servers of {profile}.") from None
    return report


def mcp_warnings(profile, user):
    """One line for every MCP server of the profile that runs in Docker without a firewall."""
    try:
        report = mcp_report(user, profile)
    except FirewallError as error:
        return [f"{profile}: WARNING - could not check its MCP servers: {error}"]
    return [f"{profile}: WARNING - MCP server {s['name']} {s['text']}" for s in report
            if s["state"] in ("ready", "manual", "refused")]


def mcp_owners(data):
    """{profile: user} of everything that can have MCP servers to check."""
    owners = {p: r["user"] for p, r in data["profiles"].items()}
    owners.update({key.split("/")[0]: r["user"] for key, r in data.get("mcp", {}).items()})
    return dict(sorted(owners.items()))


def allowed_text(conf, key):
    """What this MCP server can reach, for the user."""
    parts = [f"{t.get('net') or t['host']}" + "".join(f" {p} {','.join(map(str, t[p]))}" for p in ("tcp", "udp") if t[p])
             for t in conf["mcp"].get(key, [])]
    return "; ".join(parts) or "nothing"


def mcp_scan(profile, user):
    report = mcp_report(user, profile)
    print(f"{profile}: MCP servers" if report else f"{profile}: no MCP servers.")
    for server in report:
        print(f"  {server['name']} {server['text']}")


def mcp_check(profile, server, user):
    """Can this server get a firewall? -> its state; otherwise an error that says why."""
    identity(f"{profile}/{server}")
    require(hermes_home(user.pw_dir, profile).is_dir(),
            f"No Hermes profile {profile} for {user.pw_name} ({hermes_home(user.pw_dir, profile)} missing).")
    found = {s["name"]: s for s in mcp_report(user, profile)}
    require(server in found, f"{profile} has no MCP server {server}. See: sudo hermes-firewall mcp scan {profile}")
    state, message = found[server]["state"], found[server]["text"]
    require(state in ("ready", "isolated", "protected", "manual", "off"), f"MCP server {server} {message}")
    return state


def mcp_block(profile, server, allow):
    """The [[mcp]] table of a server, as it goes into config.toml."""
    targets_text = []
    for target in allow:
        fields = [f'{kind} = {json.dumps(target[kind])}' for kind in ("net", "host") if kind in target]
        fields += [f"{proto} = {json.dumps(target[proto])}" for proto in ("tcp", "udp") if target[proto]]
        targets_text.append("{ " + ", ".join(fields) + " }")
    return f'[[mcp]]\nprofile = {json.dumps(profile)}\nserver = {json.dumps(server)}\nallow = [{", ".join(targets_text)}]\n'


def ask_target():
    """One host, address or network from the user -> an allow entry without ports, None when done."""
    while True:
        text = input("Host name, IP address or network (empty = done): ").strip()
        if not text:
            return None
        try:
            network = ipaddress.ip_network(text)
            if network.prefixlen:
                return {"net": str(network)}
            print("  That would be a whole address family, which disables the firewall.")
            continue
        except ValueError:
            pass
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", text) and re.search("[A-Za-z]", text):
            return {"host": text}
        print("  Not a host name, IP address or network. Examples: api.github.com, 140.82.112.3, 140.82.112.0/20")


def ask_ports(proto, default):
    """Port numbers for one protocol; the default on an empty answer, nothing on "none"."""
    while True:
        text = input(f"  {proto.upper()} ports, separated by commas [{default or 'none'}]: ").strip() or default or "none"
        if text == "none":
            return []
        numbers = re.split(r"[,\s]+", text)
        if all(n.isascii() and n.isdigit() and 0 < int(n) < 65536 for n in numbers):
            return sorted({int(n) for n in numbers})
        print("  Port numbers from 1 to 65535, for example 443 or 80,443.")


def mcp_ask_allow(profile, server, user):
    """Ask for the allow list of a server that has none. -> the list, or None if it has one or nobody
    can answer. Runs BEFORE the global lock: a person may take their time, and /firewall must keep working."""
    key = f"{profile}/{server}"
    identity(key)
    if key in load_config()["mcp"] or not sys.stdin.isatty():
        return None
    mcp_check(profile, server, user)
    print(f"MCP server {server} has no allow list yet. Without one, its container reaches nothing.\n"
          f"Your answers are saved in {CONFIG}. You can also edit that file yourself at any time,\n"
          "then run: sudo hermes-firewall refresh\n")
    allow = []
    try:
        if input("Do you want to allow certain hosts or networks for this MCP server? [y/N] ").strip().lower() in ("y", "yes"):
            while target := ask_target():
                while True:
                    target.update(tcp=ask_ports("tcp", "443"), udp=ask_ports("udp", ""))
                    if target["tcp"] or target["udp"]:
                        break
                    print("  Name at least one port: the firewall opens only the ports you name.")
                allow.append(target)
    except (EOFError, KeyboardInterrupt):
        raise FirewallError("\nStopped; nothing was changed.") from None
    return allow


def mcp_save_allow(profile, server, allow):
    """Append the server's [[mcp]] table to config.toml; everything else in the file stays as it is."""
    block = mcp_block(profile, server, allow)
    text = CONFIG.read_text(encoding="utf-8").rstrip() + "\n\n" + block
    # The whole file must still be valid BEFORE it replaces the old one.
    check = CONF / ".config-check.toml"
    atomic_write(check, text)
    try:
        conf = load_config(check)
    finally:
        check.unlink(missing_ok=True)
    atomic_write(CONFIG, text)
    print(f"\nSaved in {CONFIG}:\n\n{block}")
    if any("host" in target for target in allow):
        print("A host name also gives this server the DNS servers from [sandbox] dns.\n")
    return conf


def mcp_add(data, profile, server, user, allow=None):
    key = f"{profile}/{server}"
    item = identity(key)
    state = mcp_check(profile, server, user)
    conf = load_config()
    if key not in conf["mcp"]:
        require(allow is not None, f"No allow list for {key} yet. Without a terminal to ask you on, add it to {CONFIG}, "
                                   f"then run this again:\n\n{mcp_block(profile, server, [{'host': 'api.example.org', 'tcp': [443], 'udp': []}])}"
                                   "Every target names its ports; allow = [] means it reaches nothing.")
        conf = mcp_save_allow(profile, server, allow)
    existing = data.get("mcp", {}).get(key)
    require(not existing or existing["user"] == user.pw_name,
            f"{key} is protected for user {existing and existing['user']}; run this as that user.")
    if existing:
        health(key)  # Running it again repairs the network and the Hermes side.
        docker_ready()
        if item["network"] not in networks():
            create_network(key, existing)
        check_network(key, existing)
    else:
        docker_ready()
        record = {"user": user.pw_name, "ipv6": ipv6_enabled(conf), "subnet": free_subnet(data, conf), "dns": []}
        create_firewall(data, key, record, conf)
    as_user(user, "mcp-attach", profile, server)
    dns = mcp_dns(conf, key)
    data["mcp"][key]["dns"] = dns
    save_registry(data)
    print(f"{key}: firewall active, can reach only: {allowed_text(conf, key)}")
    if state == "manual":
        print(f"Add this to its docker command yourself: --network={item['network']} "
              + " ".join(f"--dns={s}" for s in dns))
    print("It applies when the server starts again: /reload-mcp in the chat, or restart the gateway.")


def mcp_remove(data, profile, server):
    key = f"{profile}/{server}"
    item = identity(key)
    require(key in data.get("mcp", {}), f"{key} has no firewall.")
    record = data["mcp"][key]
    docker_ready()
    exists = item["network"] in networks()
    if exists:
        check_network(key, record)
    note = []
    user = pwd.getpwnam(record["user"])
    if hermes_home(user.pw_dir, profile).is_dir():
        note = as_user(user, "mcp-detach", profile, server).strip().splitlines()[-1:]
    if exists:
        for container in run("docker", "ps", "-aq", "--filter", f"network={item['network']}").stdout.split():
            run("docker", "network", "disconnect", "-f", item["network"], container)
        run("docker", "network", "rm", item["network"])
    require(not interface_exists(item["bridge"]), f"Bridge still exists: {item['bridge']}; protection kept.")
    nft_apply(drop_table(item["table"]))
    del data["mcp"][key]
    save_registry(data)
    print(f"{key}: firewall removed. {' '.join(note)}".strip())


# --- status --proof ---------------------------------------------------------------------------

def reject_count(table, chain, kind):
    """Packets of this kind (tcp or not) that one chain has refused so far. Only the matching rules: a
    new interface sends IPv6 multicast to the host by itself, which host_input_guard refuses as well."""
    data = json.loads(run("nft", "--json", "list", "chain", "inet", table, chain).stdout)
    total = 0
    for row in data["nftables"]:
        expr = row["rule"]["expr"] if "rule" in row else []
        rejects = [item["reject"] for item in expr if "reject" in item]
        if rejects and (rejects[0].get("type") == "tcp reset") == (kind == "tcp"):
            total += sum(item["counter"]["packets"] for item in expr if "counter" in item)
    return total


def probe_verdict(answer, refused):
    """Did the firewall stop this attempt? The counter decides, so a target that is down or refuses
    by itself does not count as blocked. An answer always means it got through."""
    return "blocked" if answer != "open" and refused else "passed"


def in_networks(address, networks):
    return any(ipaddress.ip_address(address) in network for network in networks)


def net_list(items):
    """Networks from set elements and config entries; ranges of auto-merged sets become their first address."""
    return [ipaddress.ip_network(str(item).split("-")[0], strict=False) for item in items]


def public_target(version, avoid):
    """A public address that no allow list opens, or None."""
    return next((a for a in PROOF_PUBLIC[version] if not in_networks(a, avoid)), None)


def host_addresses():
    """The host's own addresses outside Docker, IPv4 first."""
    found = [item["local"] for link in json.loads(run("ip", "-j", "addr", "show").stdout)
             if not link.get("ifname", "").startswith(VIRTUAL_INTERFACES)
             for item in link.get("addr_info", []) if item.get("scope") == "global"]
    return sorted(found, key=family)


def lan_targets(elements, ipv6, avoid, local):
    """One address per family in the LAN, not the host itself: the router if it is in there."""
    routers = [r["gateway"] for version in ("-4", "-6")
               for r in json.loads(run("ip", "-j", version, "route", "show", "default").stdout or "[]") if r.get("gateway")]
    found = []
    for version in (4, 6) if ipv6 else (4,):
        # IPv6 prefixes longer than /64 are NAT64-embedded IPv4 networks or single hosts.
        networks = [n for n in net_list(elements) if n.version == version and (version == 4 or n.prefixlen <= 64)]
        candidates = [r for r in routers if family(r) == version and in_networks(r, networks)]
        candidates += [str(a) for n in networks for _, a in zip(range(4), n.hosts())]
        found += [a for a in candidates if a not in local and not in_networks(a, avoid)][:1]
    return found


def proof_targets(name, record, conf):
    """What to try from this firewall's network: [(label, kind, address, port, expected)]."""
    ipv6, local = record["ipv6"], host_addresses()
    usable = [v for v in (4, 6) if v == 4 or ipv6]
    wanted = []
    if "/" in name:
        addresses = mcp_addresses(conf)
        entries = []
        for target in conf["mcp"].get(name, []):
            nets = net_list([target["net"]] if "net" in target else addresses.get(target["host"], []))
            entries += [(n, target) for n in nets]
        avoid = allowed_nets = [n for n, _ in entries]
        lan_elements = [n for item in conf["lan_networks"] for n in (host_networks() if item == "auto" else [item])]
        internet, lan, dns = "blocked", "blocked", "passed" if mcp_dns(conf, name) != [NO_DNS] else "blocked"
        for network, target in entries:
            if network.version in usable:
                address = str(next(iter(network.hosts()), network[0]))
                kind = "tcp" if target["tcp"] else "udp"
                wanted.append(("allowed target", kind, address, target[kind][0], "passed"))
        allowed = [w for w in wanted if w[1] == "tcp"]
        if allowed:
            listed = {t for _, target in entries for t in target["tcp"]}
            wanted.append(("other port", "tcp", allowed[0][2], next(p for p in (9, 19, 7, 13, 37) if p not in listed), "blocked"))
    else:
        allowed_nets = net_list(e["net"] for e in conf["allow"])
        internet = "passed" if lease_remaining(name, "internet") is not None else "blocked"
        lan = "passed" if lease_remaining(name, "lan") is not None else "blocked"
        dns = "passed"
        lan_elements = set_elements(name, "lan_v4") + (set_elements(name, "lan_v6") if ipv6 else [])
        avoid = allowed_nets + net_list(lan_elements)
    wanted += [("Internet", "tcp", address, 443, internet)
               for address in (public_target(v, avoid) for v in usable) if address]
    wanted += [("LAN", "tcp", address, 443, lan)
               for address in lan_targets(lan_elements, ipv6, allowed_nets, local)]
    gateways = [c["Gateway"] for c in network_config(name) if c.get("Gateway")]
    wanted += [("host", "tcp", address, 22, "blocked") for address in [*local[:1], *gateways[:1]]]
    servers = [s for s in conf["dns"] if family(s) in usable and not in_networks(s, avoid if "/" in name else [])]
    wanted += [("DNS", "udp", servers[0], 53, dns)] if servers else []
    return wanted


def network_config(name):
    """Subnets and gateways of the firewall's Docker network, with the addresses in use."""
    network = json.loads(run("docker", "network", "inspect", identity(name)["network"]).stdout)[0]
    used = {c.get(key, "").split("/")[0] for c in (network.get("Containers") or {}).values()
            for key in ("IPv4Address", "IPv6Address")}
    config = [dict(c) for c in (network.get("IPAM") or {}).get("Config") or [] if c.get("Subnet")]
    for item in config:
        item["used"] = sorted(used - {""})
    return config


class ProofEndpoint:
    """A temporary network namespace on the firewall's bridge: packets from it take the same way as a
    container's. It lives in a process, so it disappears with that process, also after a crash."""
    def __init__(self, name):
        self.name, self.item, self.process = name, identity(name), None
        self.link = "hfwp" + self.item["bridge"][3:14]

    def __enter__(self):
        run("ip", "link", "del", self.link, check=False)  # left by a crash less than 5 minutes ago
        self.process = subprocess.Popen([shutil.which("unshare", path=ENV["PATH"]) or "unshare", "-n", "sleep", "300"],
                                        env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self.prepare()
        except Exception:
            self.__exit__()
            raise
        return self

    def prepare(self):
        pid = str(self.process.pid)
        deadline = time.monotonic() + 3
        while os.readlink(f"/proc/{pid}/ns/net") == os.readlink("/proc/self/ns/net"):
            require(self.process.poll() is None and time.monotonic() < deadline, "no test network namespace")
            time.sleep(0.02)
        run("ip", "link", "add", self.link, "type", "veth", "peer", "name", "eth0", "netns", pid)
        run("ip", "link", "set", self.link, "master", self.item["bridge"], "up")
        self.inside("ip", "link", "set", "lo", "up")
        self.inside("ip", "link", "set", "eth0", "up")
        for config in network_config(self.name):
            network = ipaddress.ip_network(config["Subnet"])
            # From the top of the subnet: Docker hands out addresses from the bottom.
            address = next(a for a in (network[-2 - i] for i in range(8)) if str(a) not in config["used"])
            extra = ["nodad"] if network.version == 6 else []
            self.inside("ip", f"-{network.version}", "addr", "add", f"{address}/{network.prefixlen}", "dev", "eth0", *extra)
            gateway = config.get("Gateway") or str(network[1])
            self.inside("ip", f"-{network.version}", "route", "add", "default", "via", gateway)

    def inside(self, *arguments):
        return run("nsenter", "-t", str(self.process.pid), "-n", *arguments)

    def attempt(self, chain, kind, address, port):
        """Try one connection -> (answer, packets this chain refused meanwhile)."""
        before = reject_count(self.item["table"], chain, kind)
        answer = self.inside("python3", "-I", "-c", PROOF_PROBE, kind, address, str(port)).stdout.strip()
        return answer, reject_count(self.item["table"], chain, kind) - before

    def __exit__(self, *details):
        self.process.kill()
        self.process.wait()
        run("ip", "link", "del", self.link, check=False)


def prove(name, record, conf):
    """Test the firewall with real packets -> (the line for the user, did it hold?)."""
    try:
        wanted = proof_targets(name, record, conf)
        with ProofEndpoint(name) as endpoint:
            results = [(*target, probe_verdict(*endpoint.attempt("host_input_guard" if target[0] == "host" else "outbound",
                                                                 *target[1:4]))) for target in wanted]
    except (FirewallError, OSError, KeyError, ValueError, IndexError, StopIteration, subprocess.SubprocessError) as error:
        return f"proof: not tested ({str(error).splitlines()[0] if str(error) else type(error).__name__})", True
    wrong = [f"{label} {address} port {port} should be {expected}, was {got}"
             for label, _, address, port, expected, got in results if got != expected]
    if wrong:
        return "PROOF FAILED: " + "; ".join(wrong), False
    labels = dict.fromkeys(f"{label} {expected}" for label, _, _, _, expected, _ in results)
    return "proof: " + ", ".join(labels), True


def status(data, user=None, selected=None, verbose=False, proof=False):
    if selected:
        record_of(data, selected)
        profiles = [selected]
    else:
        profiles = sorted(set(data["profiles"]) | (hermes_profiles(user) if user else set()))
    conf = load_config() if targets(data) else None
    keys = [k for k in sorted(data.get("mcp", {})) if not selected or k.startswith(f"{selected}/")]
    problems = []
    # Two kinds of firewall, two parts. /firewall status of a profile without MCP firewalls stays one line.
    parts = not selected or bool(keys)
    indent = "  " if parts else ""
    if parts:
        print("Sandbox firewall (the Docker sandbox of each Hermes profile; open and close change it):")
    if not profiles:
        print(f"{indent}No Hermes profiles found.")
    for profile in profiles:
        if profile not in data["profiles"]:
            print(f"{indent}{profile}: NOT protected (to protect it: sudo hermes-firewall add {profile})")
            continue
        try:
            health(profile)
        except FirewallError as error:
            problems.append(profile)
            print(f"{indent}{profile}: ERROR - the firewall is not working ({error}). "
                  "Fix: sudo hermes-firewall restore (closes all leases)")
            continue
        try:
            require(identity(profile)["network"] in networks(), "its Docker network is missing")
            check_network(profile, data["profiles"][profile])
            messages = protect_sandboxes(profile, data["profiles"][profile], conf)
        except FirewallError as error:
            problems.append(profile)
            print(f"{indent}{profile}: ERROR - {error}. Fix: sudo hermes-firewall add {profile}")
            continue
        print(f"{indent}{profile_line(profile)}")
        for message in messages:
            print(f"{indent}{message}")
        if proof:
            line, held = prove(profile, data["profiles"][profile], conf)
            print(f"{indent}  {line}")
            if not held:
                problems.append(profile)
        if verbose:
            item = identity(profile)
            print(f"{indent}  network {item['network']}, bridge {item['bridge']}, table inet {item['table']}, "
                  f"IPv6 {'on ' + item['subnet6'] if data['profiles'][profile]['ipv6'] else 'off'}")
            print(f"{indent}  LAN: {', '.join(set_elements(profile, 'lan_v4') + set_elements(profile, 'lan_v6')) or 'nothing'}")
            for container in sandboxes(data["profiles"][profile]["label"]):
                print(f"{indent}  sandbox {container['Name'].lstrip('/')}: {container['State']['Status']}, networks "
                      f"{', '.join((container.get('NetworkSettings') or {}).get('Networks') or {}) or 'none'}")
    if data["profiles"] and not selected:
        print(f"{indent}Always reachable from protected sandboxes: {always_text(conf)}")
    if parts:
        print("\nMCP container firewall (one per MCP server in Docker; never opens, only its allow list):")
    warnings = []
    if not selected:
        for profile, owner in mcp_owners(data).items():
            try:
                warnings += mcp_warnings(profile, pwd.getpwnam(owner))
            except KeyError:
                warnings.append(f"{profile}: WARNING - user {owner} does not exist.")
    for key in keys:
        profile, server = key.split("/")
        record = data["mcp"][key]
        try:
            health(key)
        except FirewallError as error:
            problems.append(key)
            print(f"  {key}: ERROR - the firewall is not working ({error}). "
                  "Fix: sudo hermes-firewall restore (closes all leases)")
            continue
        try:
            require(identity(key)["network"] in networks(), "its Docker network is missing")
            check_network(key, record)
        except FirewallError as error:
            problems.append(key)
            print(f"  {key}: ERROR - {error}. Fix: sudo hermes-firewall mcp add {profile} {server}")
            continue
        print(f"  {key}: firewall active, can reach only: {allowed_text(conf, key)}")
        if key not in conf["mcp"]:
            print(f"  {key}: WARNING - no [[mcp]] entry in {CONFIG}, so it reaches nothing.")
        if proof:
            line, held = prove(key, record, conf)
            print(f"    {line}")
            if not held:
                problems.append(key)
        if verbose:
            item = identity(key)
            print(f"    network {item['network']} ({record['subnet']}), bridge {item['bridge']}, table inet {item['table']}")
            print(f"    allowed now: {', '.join(set_elements(key, 'allow_ports_v4') + set_elements(key, 'allow_ports_v6')) or 'nothing'}")
    for message in warnings:
        print(f"  {message}")
    if parts and not keys and not warnings:
        print("  none (MCP servers of a profile: sudo hermes-firewall mcp scan PROFILE)")
    unsafe = replaceable_by_others(EXE) if targets(data) else []
    if unsafe:
        problems.append("program")
        print(f"ERROR - {', '.join(unsafe)} can be changed by non-root users; /firewall runs this program "
              "as root. Fix: chown root and chmod go-w.")
    require(not problems, f"Firewall problem for: {', '.join(problems)}.")


def refresh(data):
    """Timer job: heal missing tables (closed), refresh addresses, follow DNS changes, protect sandboxes.

    Every step runs even if an earlier one failed; the failures are reported at the end."""
    problems = []
    def attempt(what, step):
        try:
            step()
        except (FirewallError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
            problems.append(f"{what}: {error}")
    def heal():
        missing = [p for p in targets(data) if identity(p)["table"] not in table_names()]
        if missing:
            sets = all_sets(data)
            nft_apply("".join(rules(p, sets[p]) for p in missing))
            print(f"Firewall restored (closed) for: {', '.join(missing)}", file=sys.stderr)
    attempt("restore", heal)
    # Strict: on a resolution failure the current addresses stay in place.
    attempt("addresses", lambda: nft_apply(refresh_transaction(data, all_sets(data, strict=True))))
    conf = load_config()
    for profile, record in sorted(data["profiles"].items()):
        def follow_dns():
            if record["dns"] != conf["dns"]:
                as_user(pwd.getpwnam(record["user"]), "attach", profile)
                record["dns"] = conf["dns"]
                save_registry(data)
        attempt(profile, follow_dns)
        attempt(profile, lambda: [print(m) for m in protect_sandboxes(profile, record, conf)])
        write_state(profile)
    for key, record in sorted(data.get("mcp", {}).items()):
        def follow_mcp_dns():
            if record["dns"] != mcp_dns(conf, key):
                as_user(pwd.getpwnam(record["user"]), "mcp-attach", *key.split("/"))
                record["dns"] = mcp_dns(conf, key)
                save_registry(data)
                print(f"{key}: its DNS servers changed; this applies when the server starts again.")
        attempt(key, follow_mcp_dns)
    for profile, owner in mcp_owners(data).items():
        attempt(profile, lambda: [print(m) for m in mcp_warnings(profile, pwd.getpwnam(owner))])
    require(not problems, "; ".join(problems))


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
    # openSUSE keeps the main file in /usr/etc/sudoers.
    for name in ("/etc/sudoers", "/usr/etc/sudoers"):
        try:
            if not re.search(r"^[@#]includedir\s+/etc/sudoers\.d", Path(name).read_text(encoding="utf-8"), re.M):
                found.append(f"WARNING: {name} does not include /etc/sudoers.d; /firewall in Hermes will not work.")
            break
        except OSError:
            continue
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
    require(not CONF.exists() or {p.name for p in CONF.iterdir()} <= {"config.toml", "resolved.json"},
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
    require_safe_program()
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
    require_safe_program()
    write_program(bundle)
    if write_units(conf):
        run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", REFRESH_TIMER.name)
    write_sudoers(data)
    outdated = []
    for profile in targets(data):
        try:
            health(profile)
        except FirewallError:
            outdated.append(profile)
    if outdated:
        # The rule layout changed: reload all tables in one transaction (closes all leases).
        nft_apply(restore_transaction(data))
    elif targets(data):
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
        write_state(profile)
    save_registry(data)
    for warning in flush_warnings():
        print(warning)
    print(f"Upgraded to {VERSION}." + (" The firewall rules changed: ALL leases are now closed." if outdated else ""))


def uninstall(data, purge=False):
    require(not targets(data), "Remove the protected profiles and MCP firewalls first: "
                               "sudo hermes-firewall remove PROFILE, sudo hermes-firewall mcp remove PROFILE SERVER")
    docker_ready()
    require(not run("docker", "network", "ls", "-q", "--filter", f"label={LABEL}").stdout.strip(),
            "Docker networks of hermes-firewall remain; refusing uninstall.")
    require(not any(name.startswith("hermes_fw_") for name in table_names()),
            "Firewall tables of hermes-firewall remain; refusing uninstall.")
    names = {p.name for p in CONF.iterdir()}
    require(names <= {"profiles.json", "config.toml", "resolved.json"}, f"{CONF} contains unknown files; refusing uninstall.")
    # Detach the dependency BEFORE disabling the guard; never restart/stop Docker.
    if DROPIN.exists():
        DROPIN.unlink()
        run("systemctl", "daemon-reload")
    dependencies = run("systemctl", "show", "docker.service", "-p", "Requires", "--value").stdout.split()
    require(SERVICE not in dependencies, "Docker still requires this firewall through another configuration.")
    run("systemctl", "disable", "--now", REFRESH_TIMER.name, check=False)
    run("systemctl", "stop", SERVICE)
    run("systemctl", "disable", SERVICE)
    for path in (UNIT, REFRESH_UNIT, REFRESH_TIMER, SUDOERS, REGISTRY, CACHE, EXE, *STATE.glob("*.json"),
                 *(SHARE / "plugin" / name for name in PLUGIN_FILES)):
        path.unlink(missing_ok=True)
    for folder in (SHARE / "plugin", SHARE, STATE):
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
  hermes-firewall status [PROFILE] [--verbose] [--proof]   --proof tests each firewall with real packets
  hermes-firewall remove PROFILE                  remove the firewall; the sandbox then has no network
  hermes-firewall mcp scan PROFILE                what the profile's MCP servers can reach
  hermes-firewall mcp add PROFILE SERVER          lock a Docker MCP server to an allow list (asks for it if there is none)
  hermes-firewall mcp remove PROFILE SERVER       remove its firewall; the server then has no network
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
    allowed = {"add": {"--yes"}, "status": {"--verbose", "--proof"}, "uninstall": {"--purge"},
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
    allow = mcp_ask_allow(words[2], words[3], hermes_user()) if words[:2] == ["mcp", "add"] and len(words) == 4 else None
    import fcntl
    descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022, "Unsafe lock file; refusing concurrent state changes.")
        deadline = time.monotonic() + 120
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, "Another hermes-firewall command has been running for "
                                                     "2 minutes; nothing was changed. Try again later.")
                time.sleep(0.2)
        verb, rest = words[0], words[1:]
        if verb in ("install", "upgrade"):
            require(not rest and type(options.get("--bundle")) is str, "Use install.sh.")
            (install if verb == "install" else upgrade)(Path(options["--bundle"]).resolve())
            return
        data = load_registry()
        if verb == "restore" and not rest:
            # One atomic transaction; all leases intentionally reset on boot/restore.
            nft_apply(restore_transaction(data))
            for profile in sorted(data["profiles"]):
                write_state(profile)
            print("All leases of all protected profiles are closed.")
        elif verb == "refresh" and not rest:
            refresh(data)
        elif verb == "uninstall" and not rest:
            uninstall(data, "--purge" in options)
        elif verb == "status" and len(rest) <= 1:
            user = hermes_user() if os.environ.get("SUDO_USER") and not rest else None
            status(data, user, rest[0] if rest else None, "--verbose" in options, "--proof" in options)
        elif verb == "add" and len(rest) == 1:
            add_profile(data, rest[0], hermes_user(), "--yes" in options)
        elif verb == "remove" and len(rest) == 1:
            remove_profile(data, rest[0])
        elif verb == "open" and rest:
            open_lease(data, rest[0], rest[1:])
        elif verb == "close" and rest:
            close_lease(data, rest[0], rest[1:])
        elif verb == "mcp" and len(rest) == 2 and rest[0] == "scan":
            mcp_scan(rest[1], hermes_user())
        elif verb == "mcp" and len(rest) == 3 and rest[0] == "add":
            mcp_add(data, rest[1], rest[2], hermes_user(), allow)
        elif verb == "mcp" and len(rest) == 3 and rest[0] == "remove":
            mcp_remove(data, rest[1], rest[2])
        else:
            raise FirewallError("Did not understand that. See: hermes-firewall --help")


if __name__ == "__main__":
    try:
        main()
    except (FirewallError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)

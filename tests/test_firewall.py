"""Control-plane regression tests; no root, daemon, network or nft required."""
import contextlib
import importlib.util
import json
import os
import pwd
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hermes_firewall", ROOT / "hermes_firewall.py")
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


def result(output="", code=0, error=""):
    return subprocess.CompletedProcess([], code, output, error)


CONF = {"ipv6": "auto", "docker_requires_firewall": True, "lease_default": 3600, "lease_max": 86400,
        "egress_proxy": True, "dns": ["192.168.0.5"], "lan_networks": ["192.168.0.0/24"], "lan_hosts": [],
        "allow": [{"net": "192.168.0.2/32", "tcp": [8088], "udp": []}]}
USER = pwd.struct_passwd(("hermes", "x", 1000, 1000, "", "/nonexistent-home", "/bin/bash"))


def record(user="hermes", ipv6=False, label=None, dns=None):
    return {"user": user, "ipv6": ipv6, "label": label or "", "dns": dns if dns is not None else CONF["dns"]}


def registry(*profiles):
    return {"version": 2, "profiles": {p: record(label=p) for p in profiles}}


def config_file(directory, text):
    path = Path(directory) / "config.toml"
    path.write_text(text)
    return path


def load(text):
    with tempfile.TemporaryDirectory() as directory, patch.object(fw, "trusted"):
        return fw.load_config(config_file(directory, text))


def setUpModule():
    # Tests also run as root (tests/distros.sh): never touch the real /run/hermes-firewall.
    directory = tempfile.TemporaryDirectory()
    unittest.addModuleCleanup(directory.cleanup)
    state = patch.object(fw, "STATE", Path(directory.name) / "run")
    state.start()
    unittest.addModuleCleanup(state.stop)


class IdentityAndInputTests(unittest.TestCase):
    def test_identity_is_deterministic_and_fits_linux_limits(self):
        name = "a" * 64
        self.assertEqual(fw.identity(name), fw.identity(name))
        self.assertLessEqual(len(fw.identity(name)["bridge"]), 15)
        self.assertNotEqual(fw.identity("research"), fw.identity("work"))
        self.assertTrue(fw.identity("research")["subnet6"].startswith("fd"))
        self.assertTrue(fw.identity("research")["subnet6"].endswith("::/64"))

    def test_unsafe_names_and_nft_injection_are_rejected(self):
        for name in ("", "../research", "-x", "a/b/c", "/a", "a/", "a b", "a; flush ruleset", 'a"', "a\n", "a" * 65, "ä",
                     "Research", "a.b"):
            with self.subTest(name=name), self.assertRaises(fw.FirewallError):
                fw.rules(name)

    def test_duration_boundaries(self):
        self.assertEqual(fw.duration("1h"), 3600)
        self.assertEqual(fw.duration("86400s"), 86400)
        self.assertEqual(fw.duration("1440m"), 86400)
        for value in ("0s", "01h", "25h", "-1s", "1h;flush ruleset", "1", "86401s", "1d"):
            with self.subTest(value=value), self.assertRaises(fw.FirewallError):
                fw.duration(value)

    def test_open_defaults_and_free_order(self):
        cases = {(): (("internet",), 3600), ("30m",): (("internet",), 1800), ("lan",): (("lan",), 3600),
                 ("lan", "2h"): (("lan",), 7200), ("2h", "lan"): (("lan",), 7200),
                 ("for", "internet", "1h"): (("internet",), 3600), ("lan", "for", "30m"): (("lan",), 1800),
                 ("all",): (fw.KINDS, 3600)}
        for words, expected in cases.items():
            with self.subTest(words=words):
                self.assertEqual(fw.open_arguments(list(words), CONF), expected)
        for words in (["lan", "lan"], ["1h", "2h"], ["everything"], ["--yes"]):
            with self.subTest(words=words), self.assertRaises(fw.FirewallError):
                fw.open_arguments(words, CONF)
        with self.assertRaisesRegex(fw.FirewallError, "longest lease here is 2h"):
            fw.open_arguments(["3h"], {**CONF, "lease_max": 7200})

    def test_options_only_where_allowed(self):
        self.assertEqual(fw.parse(["add", "research", "--yes"]), (["add", "research"], {"--yes": True}))
        self.assertEqual(fw.parse([]), (["status"], {}))
        self.assertEqual(fw.parse(["install", "--bundle=/x"]), (["install"], {"--bundle": "/x"}))
        # open/close are reachable via sudoers wildcards: no options at all.
        for argv in (["open", "research", "--bundle=/tmp/x"], ["close", "research", "--yes"],
                     ["open", "research", "--verbose"], ["remove", "research", "--yes"]):
            with self.subTest(argv=argv), self.assertRaisesRegex(fw.FirewallError, "Unknown option"):
                fw.parse(argv)

    def test_help_and_version_work_without_root(self):
        with patch("builtins.print") as output:
            fw.main(["--help"])
            fw.main(["--version"])
        self.assertIn("hermes-firewall open PROFILE", output.call_args_list[0].args[0])
        self.assertEqual(output.call_args_list[1].args[0], fw.VERSION)


class ConfigTests(unittest.TestCase):
    def test_example_configuration_is_valid_and_gets_detected_dns(self):
        example = (ROOT / "config.example.toml").read_text()
        conf = load(example)
        self.assertEqual((conf["lease_default"], conf["lease_max"]), (3600, 86400))
        self.assertEqual(conf["lan_networks"], ["auto"])
        self.assertEqual(conf["allow"], [])
        detected = load(fw.config_text(example, ["192.168.0.5", "fd00::53"]))
        self.assertEqual(detected["dns"], ["192.168.0.5", "fd00::53"])
        self.assertEqual(fw.config_text(example, []), example)

    def test_defaults_and_allow_entries(self):
        conf = load('[sandbox]\ndns = ["9.9.9.9"]\n[[allow]]\nnet = "192.168.0.2"\ntcp = [8088, 8088]\n'
                    '[[allow]]\nnet = "2001:db8::/32"\n')
        self.assertEqual(conf["ipv6"], "auto")
        self.assertTrue(conf["docker_requires_firewall"])
        self.assertEqual(conf["allow"], [{"net": "192.168.0.2/32", "tcp": [8088], "udp": []},
                                         {"net": "2001:db8::/32", "tcp": [], "udp": []}])

    def test_invalid_configurations_are_refused(self):
        base = '[sandbox]\ndns = ["9.9.9.9"]\n'
        for text in ("", '[sandbox]\ndns = []\n', '[sandbox]\ndns = ["127.0.0.53"]\n',
                     '[sandbox]\ndns = ["fe80::1"]\n', base + "typo = 1\n", base + "[lease]\nmax = \"25h\"\n",
                     base + '[lease]\ndefault = "2h"\nmax = "1h"\n', base + "[lease]\ndefault = 3600\n",
                     base + '[lan]\nnetworks = ["8.8.8.0/24"]\n', base + '[lan]\nnetworks = ["0.0.0.0/0"]\n',
                     base + '[lan]\nnetworks = ["2a01:db8::/32"]\n', base + '[lan]\nnetworks = ["192.168.0.1/24"]\n',
                     base + '[lan]\nhosts = ["a b"]\n', base + '[[allow]]\nnet = "0.0.0.0/0"\n',
                     base + '[[allow]]\nnet = "1.2.3.4"\ntcp = [70000]\n', base + '[[allow]]\naddress = "1.2.3.4"\n',
                     base + 'ipv6 = "maybe"\n', base + "[sandbox.extra]\n", "not toml ["):
            with self.subTest(text=text), self.assertRaises(fw.FirewallError):
                load(text)

    def test_lan_networks_private_or_ipv6_prefix(self):
        self.assertEqual(fw.lan_network("10.1.0.0/16"), "10.1.0.0/16")
        self.assertEqual(fw.lan_network("fd00:1::/64"), "fd00:1::/64")
        self.assertEqual(fw.lan_network("2a01:4f8:1:2::/64"), "2a01:4f8:1:2::/64")
        for network in ("8.8.8.0/24", "127.0.0.0/8", "169.254.0.0/16", "2a01:4f8::/32", "::/0"):
            with self.subTest(network=network), self.assertRaises(fw.FirewallError):
                fw.lan_network(network)

    def test_detected_dns_skips_loopback_and_follows_systemd_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            stub, upstream = Path(directory) / "stub", Path(directory) / "upstream"
            stub.write_text("nameserver 127.0.0.53\noptions edns0\n")
            upstream.write_text("nameserver 192.168.0.5\nnameserver fe80::1%eth0\nnameserver 2001:4860:4860::8888\n")
            self.assertEqual(fw.detected_dns((str(stub), str(upstream))), ["192.168.0.5", "2001:4860:4860::8888"])
            self.assertEqual(fw.detected_dns((str(Path(directory) / "missing"),)), [])


class AddressTests(unittest.TestCase):
    def test_nat64_embedding(self):
        self.assertEqual(fw.nat64([fw.NAT64_WKP], ["192.168.0.0/16", "93.184.1.7"]),
                         ["64:ff9b::c0a8:0/112", "64:ff9b::5db8:107/128"])
        self.assertEqual(fw.nat64(["2001:db8:64::/96"], ["10.0.0.0/8"]), ["2001:db8:64::a00:0/104"])

    def test_nat64_prefixes_from_dns64(self):
        with patch.object(fw, "resolve", return_value=["2001:db8:64::c000:aa", "2001:db8:64::c000:ab", "2001:db8::1"]):
            self.assertEqual(fw.nat64_prefixes(["9.9.9.9"]), [fw.NAT64_WKP, "2001:db8:64::/96"])
        with patch.object(fw, "resolve", side_effect=OSError("timeout")), self.assertRaises(OSError):
            fw.nat64_prefixes(["9.9.9.9"])

    def test_host_networks_ignore_virtual_and_public(self):
        links = [{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
                 {"ifname": "eth0", "addr_info": [
                     {"family": "inet", "local": "192.168.0.20", "prefixlen": 24, "scope": "global"},
                     {"family": "inet", "local": "93.184.0.87", "prefixlen": 24, "scope": "global"},
                     {"family": "inet6", "local": "2a01:4f8:1:2::87", "prefixlen": 64, "scope": "global"},
                     {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]},
                 {"ifname": "docker0", "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16, "scope": "global"}]},
                 {"ifname": "hfw0123456789ab", "addr_info": [{"family": "inet", "local": "172.18.0.1", "prefixlen": 16, "scope": "global"}]}]
        routes4 = [{"dst": "default", "gateway": "192.168.0.1", "dev": "eth0"},
                   {"dst": "192.168.0.0/24", "dev": "eth0"}, {"dst": "10.8.0.0/24", "dev": "wg0"},
                   {"dst": "172.17.0.0/16", "dev": "docker0"}, {"dst": "10.9.0.0/16", "gateway": "10.8.0.1", "dev": "wg0"}]
        # A DHCPv6 /128 address: the LAN /64 comes from the on-link route.
        routes6 = [{"dst": "2a01:4f8:1:3::/64", "dev": "eth0"}, {"dst": "fe80::/64", "dev": "eth0"},
                   {"dst": "default", "gateway": "fe80::1", "dev": "eth0"}]
        outputs = {"addr": links, "-4": routes4, "-6": routes6}
        with patch.object(fw, "run", side_effect=lambda *a, **k: result(json.dumps(outputs[a[2]]))):
            self.assertEqual(fw.host_networks(), ["192.168.0.0/24", "2a01:4f8:1:2::/64", "10.8.0.0/24",
                                                  "2a01:4f8:1:3::/64"])

    def test_proxy_ports_only_iron_proxy_of_a_user_on_the_docker_bridge(self):
        ss = ('LISTEN 0 4096 172.17.0.1:9090 0.0.0.0:* users:(("iron-proxy",pid=7,fd=3)) uid:1000 ino:1 sk:1\n'
              'LISTEN 0 4096 172.17.0.1:9091 0.0.0.0:* users:(("iron-proxy",pid=7,fd=4)) uid:1000 ino:2 sk:2\n'
              'LISTEN 0 4096 127.0.0.1:9092 0.0.0.0:* users:(("iron-proxy",pid=7,fd=5)) uid:1000 ino:3 sk:3\n'
              'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3)) ino:4 sk:4\n'
              'LISTEN 0 128 172.17.0.1:8000 0.0.0.0:* users:(("python3",pid=9,fd=3)) uid:1000 ino:5 sk:5\n')
        with patch.object(fw, "docker_gateway", return_value="172.17.0.1"), \
             patch.object(fw, "run", return_value=result(ss)):
            self.assertEqual(fw.proxy_ports(CONF), {1000: ["172.17.0.1 . tcp . 9090", "172.17.0.1 . tcp . 9091"]})
            self.assertEqual(fw.proxy_ports({**CONF, "egress_proxy": False}), {})

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        for item in (patch.object(fw, "CACHE", Path(directory.name) / "resolved.json"), patch.object(fw, "trusted")):
            item.start()
            self.addCleanup(item.stop)

    def test_common_sets(self):
        conf = {**CONF, "lan_networks": ["auto", "fd00:1::/64"], "lan_hosts": ["nas.example"],
                "dns": ["192.168.0.5", "2001:4860:4860::8888"],
                "allow": [{"net": "192.168.0.2/32", "tcp": [8088], "udp": [53]},
                          {"net": "2001:db8::/32", "tcp": [], "udp": []}]}
        with patch.object(fw, "host_networks", return_value=["192.168.0.0/24"]), \
             patch.object(fw, "resolve_host", return_value=["203.0.113.7", "2001:db8:1::7"]) as resolve, \
             patch.object(fw, "nat64_prefixes", return_value=[fw.NAT64_WKP]):
            sets = fw.common_sets(conf)
        resolve.assert_called_once_with("nas.example", conf["dns"])  # the sandbox's DNS
        self.assertEqual(sets["lan_v4"], ["192.168.0.0/24", "203.0.113.7"])
        self.assertEqual(sets["lan_v6"], ["fd00:1::/64", "2001:db8:1::7", "64:ff9b::c0a8:0/120", "64:ff9b::cb00:7107/128"])
        self.assertEqual((sets["dns_v4"], sets["dns_v6"]), (["192.168.0.5"], ["2001:4860:4860::8888"]))
        self.assertEqual(sets["allow_ports_v4"], ["192.168.0.2/32 . tcp . 8088", "192.168.0.2/32 . udp . 53"])
        self.assertEqual((sets["allow_v4"], sets["allow_v6"]), ([], ["2001:db8::/32"]))
        self.assertIn("64:ff9b::a00:0/104", sets["non_public_v6"])  # 10.0.0.0/8 via NAT64
        self.assertIn("fc00::/7", sets["non_public_v6"])

    def test_unresolvable_host_is_strict_only_on_refresh(self):
        conf = {**CONF, "lan_hosts": ["nas.example"]}
        with patch.object(fw, "resolve_host", side_effect=OSError("no network")), \
             patch.object(fw, "nat64_prefixes", return_value=[fw.NAT64_WKP]), patch("builtins.print"):
            self.assertEqual(fw.common_sets(conf)["lan_v4"], ["192.168.0.0/24"])
            with self.assertRaisesRegex(fw.FirewallError, "unchanged"):
                fw.common_sets(conf, strict=True)

    def test_last_known_addresses_are_used_while_dns_is_down(self):
        # Otherwise an Internet lease could reach the LAN host's public address at boot.
        conf = {**CONF, "lan_hosts": ["nas.example"]}
        with patch.object(fw, "resolve_host", return_value=["203.0.113.7"]), \
             patch.object(fw, "nat64_prefixes", return_value=[fw.NAT64_WKP, "2001:db8:64::/96"]):
            fw.common_sets(conf, strict=True)
        with patch.object(fw, "resolve_host", side_effect=OSError("down")), \
             patch.object(fw, "nat64_prefixes", side_effect=OSError("down")), patch("builtins.print"):
            sets = fw.common_sets(conf)
            with self.assertRaisesRegex(fw.FirewallError, "DNS64"):
                fw.common_sets({**conf, "lan_hosts": []}, strict=True)
        self.assertEqual(sets["lan_v4"], ["192.168.0.0/24", "203.0.113.7"])
        self.assertIn("2001:db8:64::c0a8:0/120", sets["lan_v6"])

    def test_overlapping_allow_networks_are_collapsed(self):
        # nft refuses overlapping intervals in a concatenated set, which would break every table.
        conf = {**CONF, "allow": [{"net": "10.0.0.0/8", "tcp": [443], "udp": []},
                                  {"net": "10.1.0.0/16", "tcp": [443, 80], "udp": []}]}
        with patch.object(fw, "nat64_prefixes", return_value=[fw.NAT64_WKP]):
            sets = fw.common_sets(conf)
        self.assertEqual(sets["allow_ports_v4"], ["10.1.0.0/16 . tcp . 80", "10.0.0.0/8 . tcp . 443"])

    def answer(self, query_id, rcode=0, records=(), qtype=1):
        question = b"\x06server\x07example\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
        header = query_id + (0x8180 | rcode).to_bytes(2, "big") + b"\x00\x01" + len(records).to_bytes(2, "big") + b"\x00\x00\x00\x00"
        return header + question + b"".join(records)

    def test_dns_answer_parses_a_and_aaaa_behind_cname(self):
        cname = b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x07\x04edge\xc0\x13"
        a = b"\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([203, 0, 113, 7])
        aaaa = b"\xc0\x2c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + bytes.fromhex("20010db8000000000000000000000007")
        query_id, query = fw.dns_query("server.example")
        self.assertTrue(query.endswith(b"\x06server\x07example\x00\x00\x01\x00\x01"))
        self.assertTrue(fw.dns_query("server.example", 28)[1].endswith(b"\x00\x00\x1c\x00\x01"))
        self.assertEqual(fw.dns_answer(query_id, self.answer(query_id, records=(cname, a))), ["203.0.113.7"])
        self.assertEqual(fw.dns_answer(query_id, self.answer(query_id, records=(cname, aaaa), qtype=28), 28),
                         ["2001:db8::7"])
        self.assertEqual(fw.dns_answer(query_id, self.answer(query_id, records=(cname,))), [])
        with self.assertRaisesRegex(fw.FirewallError, "match"):
            fw.dns_answer(b"zz", self.answer(query_id, records=(a,)))
        with self.assertRaisesRegex(fw.FirewallError, "code 3"):
            fw.dns_answer(query_id, self.answer(query_id, rcode=3))

    def test_resolve_host_combines_ipv4_and_ipv6(self):
        with patch.object(fw, "resolve", side_effect=[["203.0.113.7"], OSError("no AAAA server")]):
            self.assertEqual(fw.resolve_host("nas", ["9.9.9.9"]), ["203.0.113.7"])
        with patch.object(fw, "resolve", side_effect=[[], []]), self.assertRaises(OSError):
            fw.resolve_host("nas", ["9.9.9.9"])


class RuleTests(unittest.TestCase):
    def outbound(self):
        chain = fw.rules("research").split("chain outbound {", 1)[1].split("\n    }", 1)[0].splitlines()
        return [line.strip() for line in chain if line.strip()]

    def test_outbound_order(self):
        rules = self.outbound()
        # DNS and the allow list first: reachable in every state, but only exactly those.
        self.assertTrue(all("dns_v" in r or "allow" in r for r in rules[:6]))
        position = {name: next(i for i, r in enumerate(rules) if name in r)
                    for name in ("iifname @open_lan", "@lan_v4 meta l4proto tcp counter reject",
                                 "@lan_v6 meta l4proto tcp counter reject", "@non_public_v4", "@non_public_v6",
                                 "@open_internet")}
        # An Internet lease never opens the LAN, private networks or NAT64-embedded private addresses.
        for name in ("@lan_v4 meta l4proto tcp counter reject", "@lan_v6 meta l4proto tcp counter reject",
                     "@non_public_v4", "@non_public_v6"):
            self.assertLess(position["iifname @open_lan"], position[name])
            self.assertLess(position[name], position["@open_internet"])
        self.assertEqual(rules[-1], "counter reject with icmpx type admin-prohibited")

    def test_host_is_blocked_except_neighbour_discovery_and_egress_proxy(self):
        text = fw.rules("research")
        bridge = fw.identity("research")["bridge"]
        chains = fw.chain_rules(text)
        self.assertEqual(chains["host_input_guard"][-1], f'iifname "{bridge}" counter reject with icmpx type admin-prohibited')
        self.assertEqual(chains["host_output_guard"][-1], f'oifname "{bridge}" counter drop')
        self.assertEqual(len(chains["host_input_guard"]), 4)
        self.assertIn("ct state established", chains["host_output_guard"][3])

    def test_blocked_connections_are_refused_at_once(self):
        chains = fw.chain_rules(fw.rules("research"))
        # TCP gets a reset (no ICMP rate limit), everything else ICMP; never a silent drop outwards
        self.assertEqual(chains["outbound"][-2:], ["meta l4proto tcp counter reject with tcp reset",
                                                   "counter reject with icmpx type admin-prohibited"])
        self.assertFalse(any(rule.endswith("drop") for rule in chains["outbound"] + chains["host_input_guard"]))
        bridge = fw.identity("research")["bridge"]
        self.assertIn(f'oifname "{bridge}" tcp flags rst counter return', chains["host_output_guard"])
        # traffic from outside to the sandbox stays a silent drop
        self.assertEqual(chains["forward_guard"][-1], f'oifname "{bridge}" counter drop')

    def test_layout_fingerprint_follows_the_rules(self):
        self.assertIn(f"layout {fw.layout(fw.identity('research')['bridge'])}", fw.rules("research"))
        self.assertNotEqual(fw.layout("hfwa"), fw.layout("hfwb"))

    def test_boot_rules_never_contain_leases(self):
        text = fw.rules("research", {"lan_v4": ["192.168.0.0/24"]})
        for kind in fw.KINDS:
            declaration = text.split(f"set open_{kind}", 1)[1].split("}", 1)[0]
            self.assertNotIn("elements", declaration)
            self.assertIn("flags timeout", declaration)
        self.assertIn("elements = { 192.168.0.0/24 }", text)

    def test_profile_operations_never_touch_other_table(self):
        other = fw.identity("work")["table"]
        for text in (fw.rules("research"), fw.lease_transaction("research", fw.KINDS, 3600),
                     fw.lease_transaction("research"), fw.refresh_transaction(registry("research"), {"research": {}})):
            self.assertNotIn(other, text)
            self.assertNotIn("flush ruleset", text)

    def test_leases_are_independent_and_atomic(self):
        lan = fw.lease_transaction("research", ("lan",), 60)
        self.assertNotIn("open_internet", lan)
        self.assertEqual(len(fw.lease_transaction("research", ("internet",), 3600).splitlines()), 2)
        self.assertEqual(fw.lease_kinds("all"), fw.KINDS)
        calls = []
        with patch.object(fw, "run", side_effect=lambda *a, **kw: calls.append((a, kw)) or result()):
            fw.nft_apply(lan)
        self.assertIn("--check", calls[0][0])
        self.assertEqual(calls[1][1]["input"], lan)

    def test_refresh_replaces_every_set_but_no_lease(self):
        sets = {name: [] for name, _, _ in fw.SETS}
        sets["dns_v4"] = ["192.168.0.5"]
        text = fw.refresh_transaction(registry("research", "work"), {"research": sets, "work": sets})
        for profile in ("research", "work"):
            table = fw.identity(profile)["table"]
            for name, _, _ in fw.SETS:
                self.assertIn(f"flush set inet {table} {name}\n", text)
            self.assertIn(f"add element inet {table} dns_v4 {{ 192.168.0.5 }}\n", text)
        self.assertNotIn("open_", text)

    def kernel(self, rules_text):
        chains = fw.chain_rules(rules_text)
        hooks = {"forward_guard": "forward", "host_input_guard": "input", "host_output_guard": "output"}
        rows = [{"chain": {"name": n, "hook": hooks[n], "prio": -10}} for n in hooks] + [{"chain": {"name": "outbound"}}]
        rows += [{"rule": {"chain": chain}} for chain, lines in chains.items() for _ in lines]
        return json.dumps({"nftables": rows})

    def test_health_checks_hooks_and_rule_counts(self):
        text = fw.rules("research").split("delete table", 1)[1]  # what "nft list table" prints (roughly)
        good = self.kernel(fw.rules("research"))
        with patch.object(fw, "run", side_effect=[result(), result(good), result(text)]):
            fw.health("research")
        older = text.replace(f"layout {fw.layout(fw.identity('research')['bridge'])}", "layout 000000000000")
        for json_text, listing in ((json.dumps({"nftables": []}), text), (good.replace('"prio": -10', '"prio": 0', 1), text),
                                   (good, older), (good, text.replace("comment", "#"))):
            with self.subTest(listing=listing[:20], json=json_text[:30]), \
                 patch.object(fw, "run", side_effect=[result(), result(json_text), result(listing)]):
                with self.assertRaises(fw.FirewallError):
                    fw.health("research")


class RegistryAndCreationTests(unittest.TestCase):
    def test_registry_validation(self):
        fw.validate_registry(registry("research"))
        for data in ({"version": 1, "profiles": {}}, {"version": 2, "profiles": {"Research": record()}},
                     {"version": 2, "profiles": {"research": {"user": "hermes"}}}):
            with self.subTest(data=data), self.assertRaises(fw.FirewallError):
                fw.validate_registry(data)

    def creation(self, data, nft=None, order=None):
        order = [] if order is None else order
        def command(*args, **kwargs):
            if args[:3] == ("docker", "network", "create"):
                order.append(("network", args))
            return result()
        with patch.object(fw, "docker_ready"), patch.object(fw, "networks", return_value=set()), \
             patch.object(fw, "table_names", return_value=set()), patch.object(fw, "interface_exists", return_value=False), \
             patch.object(fw, "common_sets", return_value={}), patch.object(fw, "proxy_ports", return_value={}), \
             patch.object(fw, "save_registry", side_effect=lambda _: order.append("persist")), \
             patch.object(fw, "nft_apply", side_effect=nft or (lambda text: order.append("protect"))), \
             patch.object(fw, "run", side_effect=command):
            fw.create_firewall(data, "research", record(ipv6=True), CONF)
        return order

    def test_protection_comes_before_the_network(self):
        data = registry("work")
        order = self.creation(data)
        self.assertEqual([o if isinstance(o, str) else o[0] for o in order], ["persist", "protect", "network"])
        self.assertIn(fw.identity("research")["subnet6"], order[2][1])
        self.assertIn("research", data["profiles"])

    def test_no_network_when_protection_fails(self):
        order = []
        with self.assertRaises(fw.FirewallError):
            self.creation(registry(), nft=fw.FirewallError("nft failed"), order=order)
        self.assertEqual(order, ["persist"])


@contextlib.contextmanager
def hermes_home(profile="research"):
    with tempfile.TemporaryDirectory() as home:
        fw.hermes_home(home, profile).mkdir(parents=True)
        yield pwd.struct_passwd(("hermes", "x", 1000, 1000, "", home, "/bin/bash"))


class ProfileTests(unittest.TestCase):
    def setUp(self):
        # Independent of the machine running the tests (on CI runners /usr/local/bin is not root-only).
        item = patch.object(fw, "replaceable_by_others", return_value=[])
        item.start()
        self.addCleanup(item.stop)

    def add(self, data, user, existing_network=True):
        calls = []
        def as_user(u, *arguments):
            calls.append(arguments)
            return 'greeting from .profile\n{"key": "", "hints": ["Hint: x"]}\n' if arguments[0] == "info" else ""
        with patch.object(fw, "load_config", return_value=CONF), patch.object(fw, "as_user", side_effect=as_user), \
             patch.object(fw, "health"), patch.object(fw, "docker_ready"), patch.object(fw, "check_network"), \
             patch.object(fw, "networks", return_value={"hermes-fw-research"} if existing_network else set()), \
             patch.object(fw, "create_network") as network, patch.object(fw, "create_firewall") as create, \
             patch.object(fw, "ipv6_enabled", return_value=False), patch.object(fw, "save_registry"), \
             patch.object(fw, "write_sudoers") as sudoers, patch.object(fw, "protect_sandboxes", return_value=[]), \
             patch.object(fw, "mcp_warnings", return_value=[]), \
             patch.object(fw, "profile_line", return_value="research: firewall active"), patch("builtins.print") as output:
            create.side_effect = lambda d, p, r, c: d["profiles"].__setitem__(p, r)
            fw.add_profile(data, "research", user)
        return calls, create, network, sudoers, [c.args[0] for c in output.call_args_list]

    def test_add_protects_attaches_and_allows_the_plugin(self):
        with hermes_home() as user:
            data = registry()
            calls, create, _, sudoers, lines = self.add(data, user)
        self.assertEqual(calls, [("info", "research"), ("attach", "research")])
        create.assert_called_once()
        sudoers.assert_called_once_with(data)
        self.assertEqual(data["profiles"]["research"], record(label="research"))
        self.assertIn("Hint: x", lines)
        self.assertIn("/firewall open", lines[-1])

    def test_add_again_repairs_a_missing_network(self):
        with hermes_home() as user:
            _, create, network, _, _ = self.add(registry("research"), user, existing_network=False)
        create.assert_not_called()
        network.assert_called_once()

    def test_add_refuses_unknown_profile_and_other_user(self):
        with patch.object(fw, "create_firewall") as create:
            with self.assertRaisesRegex(fw.FirewallError, "No Hermes profile"):
                fw.add_profile(registry(), "typo", USER)
            with hermes_home() as user, self.assertRaisesRegex(fw.FirewallError, "protected for user"):
                data = registry()
                data["profiles"]["research"] = record(user="someone")
                fw.add_profile(data, "research", user)
            create.assert_not_called()

    def test_remove_detaches_before_removing_network_and_protection(self):
        data = registry("research", "work")
        order = []
        def command(*args, **kwargs):
            if args[:3] in (("docker", "network", "disconnect"), ("docker", "network", "rm")):
                order.append(args[2])
            return result("abc\n" if args[:3] == ("docker", "ps", "-aq") else "")
        with hermes_home() as user:
            with patch.object(fw.pwd, "getpwnam", return_value=user), patch.object(fw, "docker_ready"), \
                 patch.object(fw, "networks", return_value={"hermes-fw-research"}), patch.object(fw, "check_network"), \
                 patch.object(fw, "run", side_effect=command), patch.object(fw, "interface_exists", return_value=False), \
                 patch.object(fw, "as_user", side_effect=lambda u, *a: order.append(a)), \
                 patch.object(fw, "nft_apply", side_effect=lambda text: order.append(text)), \
                 patch.object(fw, "save_registry"), patch.object(fw, "write_sudoers"), patch("builtins.print"):
                fw.remove_profile(data, "research")
        self.assertEqual(order[:3], [("detach", "research"), "disconnect", "rm"])
        self.assertEqual(order[3], fw.drop_table(fw.identity("research")["table"]))
        self.assertEqual(set(data["profiles"]), {"work"})

    def test_add_refuses_answers_it_cannot_trust_and_label_clashes(self):
        with hermes_home() as user:
            for answer in ('{"label": "work"}', "no json", '{"key": 5, "hints": []}'):
                with self.subTest(answer=answer), patch.object(fw, "load_config", return_value=CONF), \
                     patch.object(fw, "as_user", return_value=answer), self.assertRaisesRegex(fw.FirewallError, "Unexpected"):
                    fw.add_profile(registry(), "research", user)
            with patch.object(fw, "load_config", return_value=CONF), \
                 patch.object(fw, "as_user", side_effect=fw.FirewallError("does not use a Docker sandbox")), \
                 self.assertRaisesRegex(fw.FirewallError, "Docker sandbox"):
                fw.add_profile(registry(), "research", user)
            data = registry("work")
            data["profiles"]["work"]["label"] = "research"
            with patch.object(fw, "load_config", return_value=CONF), \
                 patch.object(fw, "as_user", return_value='{"key": "", "hints": []}'), \
                 self.assertRaisesRegex(fw.FirewallError, "mixed up"):
                fw.add_profile(data, "research", user)

    def test_status_wording(self):
        data = registry("research")
        with patch.object(fw, "hermes_profiles", return_value={"research", "work"}), patch.object(fw, "health"), \
             patch.object(fw, "networks", return_value={"hermes-fw-research"}), patch.object(fw, "check_network"), \
             patch.object(fw, "load_config", return_value=CONF), patch.object(fw, "protect_sandboxes", return_value=[]), \
             patch.object(fw, "lease_remaining", side_effect=[2472, None]), patch("builtins.print") as output:
            fw.status(data, USER)
        lines = [c.args[0] for c in output.call_args_list]
        self.assertTrue(lines[0].startswith("Sandbox firewall"))
        self.assertRegex(lines[1], r"^  research: firewall active, Internet open for 41m \(until \d\d:\d\d\), LAN closed$")
        self.assertEqual(lines[2], "  work: NOT protected (to protect it: sudo hermes-firewall add work)")
        self.assertEqual(lines[3], "  Always reachable from protected sandboxes: DNS 192.168.0.5; "
                                   "192.168.0.2/32 tcp 8088; Hermes egress proxy")

    def test_status_reports_broken_firewall(self):
        with patch.object(fw, "health", side_effect=fw.FirewallError("hook missing")), \
             patch.object(fw, "load_config", return_value=CONF), patch("builtins.print") as output:
            with self.assertRaisesRegex(fw.FirewallError, "problem for: research"):
                fw.status(registry("research"), selected="research")
        self.assertIn("Fix: sudo hermes-firewall restore", output.call_args.args[0])
        with patch.object(fw, "health"), patch.object(fw, "networks", return_value=set()), \
             patch.object(fw, "load_config", return_value=CONF), patch("builtins.print") as output:
            with self.assertRaises(fw.FirewallError):
                fw.status(registry("research"), selected="research")
        self.assertIn("network is missing. Fix: sudo hermes-firewall add research", output.call_args.args[0])

    def test_ipv6_auto_needs_docker_nat66(self):
        with tempfile.TemporaryDirectory() as directory:
            daemon = Path(directory) / "daemon.json"
            for version, setting, expected in (("29.0.1", None, True), ("26.1.5+dfsg1", None, False),
                                               ("26.1.5", {"ip6tables": True}, False),
                                               ("26.1.5", {"ip6tables": True, "experimental": True}, True),
                                               ("28.0.0", {"ip6tables": False}, False)):
                with self.subTest(version=version, setting=setting):
                    daemon.write_text(json.dumps(setting)) if setting else daemon.unlink(missing_ok=True)
                    with patch.object(fw, "run", return_value=result(version + "\n")):
                        self.assertEqual(fw.docker_nat66(daemon), expected)
        with patch.object(fw, "run", return_value=result('[{"dst": "default"}]')), \
             patch.object(fw, "docker_nat66", return_value=False):
            self.assertFalse(fw.ipv6_enabled({"ipv6": "auto"}))
            self.assertTrue(fw.ipv6_enabled({"ipv6": True}))

    def test_left(self):
        self.assertEqual([fw.left(s) for s in (30, 59, 60, 2472, 3600, 7380)], ["30s", "59s", "1m", "41m", "1h", "2h 03m"])
        self.assertEqual(fw.lease_state(None), "closed")

    def test_lease_parsing(self):
        closed = {"nftables": [{"set": {"name": "open_internet"}}]}
        opened = {"nftables": [{"set": {"name": "open_lan", "elem": [{"elem": {"val": "hfw", "expires": 2472}}]}}]}
        with patch.object(fw, "run", return_value=result(json.dumps(closed))):
            self.assertIsNone(fw.lease_remaining("research"))
        with patch.object(fw, "run", return_value=result(json.dumps(opened))):
            self.assertEqual(fw.lease_remaining("research", "lan"), 2472)


EGRESS_ENFORCED = fw.egress_enforced  # the real function; other tests replace it


class HermesSideTests(unittest.TestCase):
    def setUp(self):
        item = patch.object(fw, "egress_enforced", return_value=False)
        item.start()
        self.addCleanup(item.stop)

    def settings(self, **values):
        return {"backend": "docker", "docker_network": True, "docker_extra_args": [],
                "docker_shared_container_key": "", **values}

    def test_info_explains_the_enforcing_egress_proxy(self):
        sections = {"terminal": self.settings(), "proxy": {"enabled": True}}
        with patch.object(fw, "config_section", side_effect=lambda p, name: sections[name]), \
             patch.object(fw, "egress_enforced", EGRESS_ENFORCED):
            with self.assertRaisesRegex(fw.FirewallError, "config set proxy.enforce_on_docker false"):
                fw.hermes_info("research")
            sections["proxy"] = {"enabled": True, "enforce_on_docker": False}
            self.assertEqual(fw.hermes_info("research")["hints"], [])
            sections["proxy"] = {"enabled": False}
            fw.hermes_info("research")

    def test_info_requires_docker_backend(self):
        with patch.object(fw, "terminal_settings", return_value=self.settings(backend="local")):
            with self.assertRaisesRegex(fw.FirewallError, "config set terminal.backend docker"):
                fw.hermes_info("research")

    def test_info_refuses_a_shared_sandbox_and_computes_labels(self):
        settings = {"research": self.settings(docker_shared_container_key="team"),
                    "work": self.settings(docker_shared_container_key="team"), "default": self.settings()}
        with hermes_home() as user, patch.object(fw.pwd, "getpwuid", return_value=user), \
             patch.object(fw, "hermes_profiles", return_value=set(settings)), \
             patch.object(fw, "terminal_settings", side_effect=lambda p: settings[p]):
            with self.assertRaisesRegex(fw.FirewallError, "share one sandbox"):
                fw.hermes_info("research")
            settings["work"] = self.settings()
            key = fw.hermes_info("research")["key"]
        self.assertEqual(key, "team")
        label = fw.container_label("research", key)
        self.assertTrue(label.startswith("team-") and len(label) == 17)
        self.assertEqual(fw.container_label("research"), "research")

    def test_info_warns_about_sandbox_escapes(self):
        settings = self.settings(docker_extra_args=["--privileged"], docker_volumes=["/var/run/docker.sock:/s"])
        with patch.object(fw, "terminal_settings", return_value=settings):
            hint = fw.hermes_info("research")["hints"][0]
        self.assertIn("--privileged", hint)
        self.assertIn("docker.sock", hint)

    def test_info_hints(self):
        with patch.object(fw, "terminal_settings", return_value=self.settings(docker_mount_cwd_to_workspace=True)):
            self.assertIn("working directory", fw.hermes_info("research")["hints"][0])
        with patch.object(fw, "terminal_settings", return_value=self.settings(docker_extra_args=["--network", "x"])):
            with self.assertRaisesRegex(fw.FirewallError, "--network=VALUE"):
                fw.hermes_info("research")

    def test_attach_sets_only_network_keys_and_keeps_foreign_arguments(self):
        current = self.settings(docker_network=False, docker_extra_args=["--cap-drop=ALL", "--dns=8.8.8.8", "--network=old"])
        with patch.object(fw, "terminal_settings", return_value=current), patch.object(fw, "hermes") as hermes, \
             patch.object(fw, "install_plugin") as plugin:
            fw.hermes_attach("research", ["192.168.0.5"])
        sets = [c.args for c in hermes.call_args_list]
        self.assertEqual(sets[0], ("-p", "research", "config", "set", "terminal.docker_network", "true"))
        self.assertEqual(json.loads(sets[1][-1]), ["--cap-drop=ALL", "--network=hermes-fw-research", "--dns=192.168.0.5"])
        self.assertEqual(len(sets), 2)  # nothing else, e.g. container_persistent, is touched
        plugin.assert_called_once_with("research")

    def test_attach_twice_changes_nothing(self):
        done = self.settings(docker_extra_args=["--network=hermes-fw-research", "--dns=192.168.0.5"])
        with patch.object(fw, "terminal_settings", return_value=done), patch.object(fw, "hermes") as hermes, \
             patch.object(fw, "install_plugin"):
            fw.hermes_attach("research", ["192.168.0.5"])
        hermes.assert_not_called()

    def test_detach_leaves_no_network(self):
        attached = self.settings(docker_extra_args=["-v=/x:/x", "--network=hermes-fw-research", "--dns=192.168.0.5"])
        with tempfile.TemporaryDirectory() as home, patch.object(fw.Path, "home", return_value=Path(home)), \
             patch.object(fw, "terminal_settings", return_value=attached), patch.object(fw, "hermes") as hermes:
            fw.hermes_detach("research")
        sets = [c.args for c in hermes.call_args_list]
        self.assertEqual(sets[0], ("-p", "research", "config", "set", "terminal.docker_network", "false"))
        self.assertEqual(json.loads(sets[1][-1]), ["-v=/x:/x"])

    def test_plugin_install_and_removal_touch_only_own_files(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as share:
            (Path(share) / "plugin").mkdir()
            for name in fw.PLUGIN_FILES:
                (Path(share) / "plugin" / name).write_text(name)
            with patch.object(fw.Path, "home", return_value=Path(home)), patch.object(fw, "SHARE", Path(share)), \
                 patch.object(fw, "hermes") as hermes:
                fw.install_plugin("research")
                target = fw.hermes_home(home, "research") / "plugins" / fw.PLUGIN
                self.assertEqual(sorted(p.name for p in target.iterdir()), sorted(fw.PLUGIN_FILES))
                hermes.assert_called_once_with("-p", "research", "plugins", "enable", fw.PLUGIN)
                (target / "__pycache__").mkdir()
                (target / "__pycache__" / "x.pyc").write_text("")
                fw.install_plugin("research")  # reinstall over Hermes' bytecode cache
                (target / "notes.txt").write_text("mine")
                with self.assertRaisesRegex(fw.FirewallError, "do not belong"):
                    fw.remove_plugin_files(target)
                self.assertTrue((target / "notes.txt").exists())

    def test_internal_command_refuses_root(self):
        with patch.object(fw.os, "geteuid", return_value=0), self.assertRaisesRegex(fw.FirewallError, "not as root"):
            fw.main(["_hermes", "info", "research"])


def container(mode="bridge", networks=("bridge",), dns=None, mounts=()):
    return {"Id": "c1", "Name": "/hermes-c1", "State": {"Status": "running"},
            "HostConfig": {"NetworkMode": mode, "Dns": dns if dns is not None else CONF["dns"]},
            "NetworkSettings": {"Networks": {n: {} for n in networks}},
            "Mounts": [{"Type": "bind", "Destination": m, "RW": True} for m in mounts]}


class SandboxTests(unittest.TestCase):
    def protect(self, item, interactive=False, yes=False, answer="n"):
        with patch.object(fw, "sandboxes", return_value=[item]), patch.object(fw, "run", return_value=result()) as run, \
             patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value=answer), \
             patch("builtins.print"):
            messages = fw.protect_sandboxes("research", record(label="research"), CONF, interactive, yes)
        return messages, [c.args for c in run.call_args_list]

    def test_sandbox_outside_is_moved_without_asking(self):
        messages, calls = self.protect(container())
        self.assertEqual(calls, [("docker", "network", "disconnect", "-f", "bridge", "c1"),
                                 ("docker", "network", "connect", "hermes-fw-research", "c1")])
        self.assertIn("protected now", messages[0])

    def test_protected_sandbox_is_left_alone(self):
        self.assertEqual(self.protect(container(mode="hermes-fw-research", networks=("hermes-fw-research",))), ([], []))

    def test_host_network_cannot_be_moved(self):
        messages, calls = self.protect(container(mode="host", networks=("host",)))
        self.assertEqual(calls, [])
        self.assertIn("NOT protected", messages[0])
        self.assertIn("sudo hermes-firewall add research", messages[0])

    def test_old_dns_needs_a_reset_and_add_can_do_it(self):
        moved = container(dns=[], mounts=("/root", "/workspace"))
        messages, _ = self.protect(moved)
        self.assertIn("needs a reset", messages[1])
        messages, calls = self.protect(moved, interactive=True, answer="y")
        self.assertIn(("docker", "rm", "-f", "c1"), calls)
        self.assertEqual(messages[-1], "research: the sandbox was reset.")
        self.assertIn("your files in /root, /workspace", fw.kept_text(moved))
        self.assertIn("everything inside the sandbox", fw.kept_text(container()))

    def test_add_without_terminal_points_to_yes(self):
        with patch.object(fw, "sandboxes", return_value=[container(mode="none", networks=("none",))]), \
             patch.object(fw, "run", return_value=result()), patch("sys.stdin.isatty", return_value=False):
            interactive = fw.protect_sandboxes("research", record(label="research"), CONF, interactive=True)
            plain = fw.protect_sandboxes("research", record(label="research"), CONF)
        self.assertTrue(interactive[0].endswith("Fix: sudo hermes-firewall add research --yes"))
        self.assertTrue(plain[0].endswith("Fix: sudo hermes-firewall add research"))

    def test_no_reset_without_confirmation(self):
        _, calls = self.protect(container(mode="none", networks=("none",)), interactive=True, answer="")
        self.assertNotIn(("docker", "rm", "-f", "c1"), calls)


class SudoersTests(unittest.TestCase):
    def test_only_open_close_status_of_registered_profiles(self):
        text = fw.sudoers_text(registry("research"))
        rule = [line for line in text.splitlines() if line.startswith("hermes")][0]
        commands = rule.split("NOPASSWD: ", 1)[1].split(", ")
        exe = str(fw.EXE)
        self.assertEqual(commands, [f"{exe} open research", f"{exe} open research *", f"{exe} close research",
                                    f"{exe} close research *", f"{exe} status research"])
        self.assertEqual(fw.sudoers_text(registry()), "")

    def test_write_validates_before_installing(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hermes-firewall"
            with patch.object(fw, "SUDOERS", target), patch.object(fw, "run", side_effect=fw.FirewallError("syntax")):
                with self.assertRaises(fw.FirewallError):
                    fw.write_sudoers(registry("research"))
            self.assertEqual(os.listdir(directory), [])
            with patch.object(fw, "SUDOERS", target), patch.object(fw, "run", return_value=result()) as run:
                fw.write_sudoers(registry("research"))
                self.assertEqual(run.call_args.args[:2], ("visudo", "-cf"))
                self.assertEqual(oct(target.stat().st_mode & 0o777), "0o440")
                fw.write_sudoers(registry())
            self.assertFalse(target.exists())


class InstallTests(unittest.TestCase):
    @contextlib.contextmanager
    def installed_paths(self, base):
        names = {"CONF": "conf", "EXE": "bin/hermes-firewall", "SHARE": "share", "UNIT": "units/fw.service",
                 "DROPIN": "units/docker.d/90.conf", "REFRESH_UNIT": "units/refresh.service",
                 "REFRESH_TIMER": "units/refresh.timer", "SUDOERS": "sudoers/hermes-firewall"}
        for folder in ("bin", "units", "sudoers"):
            (base / folder).mkdir()
        with contextlib.ExitStack() as stack:
            for key, value in names.items():
                stack.enter_context(patch.object(fw, key, base / value))
            stack.enter_context(patch.object(fw, "REGISTRY", base / "conf" / "profiles.json"))
            stack.enter_context(patch.object(fw, "CONFIG", base / "conf" / "config.toml"))
            stack.enter_context(patch.object(fw, "trusted"))
            stack.enter_context(patch.object(fw, "docker_ready"))
            stack.enter_context(patch.object(fw, "flush_warnings", return_value=[]))
            stack.enter_context(patch.object(fw, "replaceable_by_others", return_value=[]))
            stack.enter_context(patch("builtins.print"))
            yield stack.enter_context(patch.object(fw, "run", return_value=result()))

    def bundle(self, base):
        bundle = base / "bundle"
        (bundle / "plugin" / fw.PLUGIN).mkdir(parents=True, exist_ok=True)
        for name in fw.PLUGIN_FILES:
            (bundle / "plugin" / fw.PLUGIN / name).write_text(name)
        (bundle / "hermes_firewall.py").write_text("program")
        (bundle / "config.example.toml").write_text((ROOT / "config.example.toml").read_text())
        return bundle

    def test_install_writes_everything_with_detected_dns(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with self.installed_paths(base) as run, patch.object(fw.shutil, "which", return_value="/bin/x"), \
                 patch.object(fw, "detected_dns", return_value=["192.168.0.5"]):
                fw.install(self.bundle(base))
                self.assertEqual(fw.load_config()["dns"], ["192.168.0.5"])
                self.assertEqual(json.loads(fw.REGISTRY.read_text()), {"version": 2, "profiles": {}})
                self.assertEqual(fw.EXE.read_text(), "program")
                self.assertTrue((fw.SHARE / "plugin" / "__init__.py").exists())
                self.assertEqual(fw.DROPIN.read_text(), fw.DROPIN_TEXT)
                self.assertIn(("systemctl", "enable", fw.SERVICE, fw.REFRESH_TIMER.name),
                              [c.args for c in run.call_args_list])
                with self.assertRaisesRegex(fw.FirewallError, "already"):
                    fw.install(self.bundle(base))

    def test_reinstall_keeps_settings_of_an_uninstall_without_purge(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "conf").mkdir()
            (base / "conf" / "config.toml").write_text('docker_requires_firewall = false\n[sandbox]\ndns = ["10.0.0.53"]\n')
            with self.installed_paths(base), patch.object(fw.shutil, "which", return_value="/bin/x"), \
                 patch.object(fw, "detected_dns", return_value=["192.168.0.5"]):
                fw.install(self.bundle(base))
                self.assertEqual(fw.load_config()["dns"], ["10.0.0.53"])
                self.assertFalse(fw.DROPIN.exists())

    def test_upgrade_reloads_rules_only_when_layout_changed(self):
        for healthy in (True, False):
            with self.subTest(healthy=healthy), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                (base / "conf").mkdir()
                (base / "conf" / "config.toml").write_text('[sandbox]\ndns = ["192.168.0.5"]\n')
                (base / "conf" / "profiles.json").write_text(json.dumps(registry("research")))
                with self.installed_paths(base):
                    fw.UNIT.write_text("old unit")
                    with patch.object(fw, "health", side_effect=None if healthy else fw.FirewallError("old")), \
                         patch.object(fw, "nft_apply") as nft, patch.object(fw, "write_sudoers"), \
                         patch.object(fw, "all_sets", return_value={"research": {}}), \
                         patch.object(fw, "restore_transaction", return_value="delete table\n"), \
                         patch.object(fw, "as_user") as as_user, patch.object(fw.pwd, "getpwnam", return_value=USER):
                        fw.upgrade(self.bundle(base))
                    self.assertEqual(fw.UNIT.read_text(), fw.UNIT_TEXT)
                text = nft.call_args.args[0]
                self.assertEqual("delete table" in text, not healthy)
                as_user.assert_called_once_with(USER, "attach", "research")

    def test_upgrade_refuses_missing_installation(self):
        with tempfile.TemporaryDirectory() as directory, self.installed_paths(Path(directory)):
            with self.assertRaisesRegex(fw.FirewallError, "not .*installed"):
                fw.upgrade(Path(directory))


def fake_stat(owners):
    """os.stat/lstat replacement: {path: (uid, gid, mode)}; unknown paths are root 0755 directories."""
    def stat_of(path):
        uid, gid, mode = owners.get(str(path), (0, 0, 0o40755))
        return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))
    return stat_of


class ProgramPathTests(unittest.TestCase):
    def check(self, owners):
        stat_of = fake_stat(owners)
        with patch.object(fw.os, "stat", side_effect=stat_of), patch.object(fw.os, "lstat", side_effect=stat_of):
            return fw.replaceable_by_others(Path("/usr/local/bin/hermes-firewall"))

    def test_root_owned_path_is_safe(self):
        self.assertEqual(self.check({"/usr/local/bin/hermes-firewall": (0, 0, 0o100755)}), [])
        # group root may write (some distributions); another group may not (old Debian: staff)
        self.assertEqual(self.check({"/usr/local": (0, 0, 0o42775)}), [])
        self.assertEqual(self.check({"/usr/local": (0, 50, 0o42775)}), ["/usr/local"])

    def test_anything_others_can_change_is_reported(self):
        for owners, bad in (({"/usr/local/bin/hermes-firewall": (1000, 1000, 0o100755)}, "/usr/local/bin/hermes-firewall"),
                            ({"/usr/local/bin/hermes-firewall": (0, 0, 0o100757)}, "/usr/local/bin/hermes-firewall"),
                            ({"/usr/local/bin/hermes-firewall": (0, 0, 0o120777)}, "/usr/local/bin/hermes-firewall"),
                            ({"/usr/local/bin": (0, 0, 0o40777)}, "/usr/local/bin"),
                            ({"/usr": (1000, 0, 0o40755)}, "/usr")):
            with self.subTest(bad=bad, owners=owners):
                self.assertEqual(self.check(owners), [bad])

    def test_install_and_status_refuse_a_replaceable_program(self):
        with patch.object(fw, "replaceable_by_others", return_value=["/usr/local/bin"]):
            with self.assertRaisesRegex(fw.FirewallError, "could be replaced"):
                fw.require_safe_program()
            with patch.object(fw, "health"), patch.object(fw, "networks", return_value={"hermes-fw-research"}), \
                 patch.object(fw, "check_network"), patch.object(fw, "load_config", return_value=CONF), \
                 patch.object(fw, "protect_sandboxes", return_value=[]), \
                 patch.object(fw, "lease_remaining", return_value=None), patch("builtins.print") as output:
                with self.assertRaisesRegex(fw.FirewallError, "program"):
                    fw.status(registry("research"))
        self.assertIn("can be changed by non-root users", output.call_args.args[0])


class McpConfigTests(unittest.TestCase):
    BASE = '[sandbox]\ndns = ["192.168.0.5"]\n'

    def test_allow_list_of_nets_and_names_with_ports(self):
        conf = load(self.BASE + """
[[mcp]]
profile = "research"
server = "github"
allow = [{ net = "140.82.112.0/20", tcp = [443] }, { host = "api.github.com", tcp = [443, 80], udp = [443] }]

[[mcp]]
profile = "research"
server = "offline"
""")
        self.assertEqual(conf["mcp"]["research/github"], [
            {"net": "140.82.112.0/20", "tcp": [443], "udp": []},
            {"host": "api.github.com", "tcp": [80, 443], "udp": [443]}])
        self.assertEqual(conf["mcp"]["research/offline"], [])
        self.assertEqual(conf["mcp_subnet"], fw.MCP_SUBNET)

    def test_every_target_names_its_ports_and_nothing_else_is_accepted(self):
        for entry, message in (('allow = [{ net = "1.2.3.4" }]', "ports"),
                               ('allow = [{ host = "x.org", tcp = [] }]', "ports"),
                               ('allow = [{ net = "1.2.3.4", host = "x.org", tcp = [1] }]', "net or host"),
                               ('allow = [{ tcp = [1] }]', "net or host"),
                               ('allow = [{ net = "nope", tcp = [1] }]', "not an address"),
                               ('allow = [{ net = "0.0.0.0/0", tcp = [443] }]', "whole address family"),
                               ('allow = [{ host = "a b", tcp = [1] }]', "not a host name"),
                               ('allow = [{ net = "1.2.3.4", tcp = [70000] }]', "port numbers"),
                               ('allow = "x"', "must be a list"),
                               ('oops = 1', "take profile")):
            with self.subTest(entry=entry), self.assertRaisesRegex(fw.FirewallError, message):
                load(self.BASE + f'[[mcp]]\nprofile = "research"\nserver = "github"\n{entry}\n')

    def test_bad_names_duplicates_and_subnets_are_refused(self):
        with self.assertRaises(fw.FirewallError):
            load(self.BASE + '[[mcp]]\nprofile = "Research"\nserver = "x"\n')
        with self.assertRaises(fw.FirewallError):
            load(self.BASE + '[[mcp]]\nprofile = "research"\nserver = "a.b"\n')
        with self.assertRaisesRegex(fw.FirewallError, "Two"):
            load(self.BASE + '[[mcp]]\nprofile = "r"\nserver = "x"\n[[mcp]]\nprofile = "r"\nserver = "x"\n')
        for subnet in ("8.8.8.0/24", "fd00::/64", "10.0.0.0/30", "nope"):
            with self.subTest(subnet=subnet), self.assertRaisesRegex(fw.FirewallError, "mcp_subnet"):
                load(f'mcp_subnet = "{subnet}"\n' + self.BASE)


MCP_CONF = {**CONF, "mcp_subnet": fw.MCP_SUBNET, "mcp": {
    "research/github": [{"host": "api.github.com", "tcp": [443], "udp": []},
                        {"net": "140.82.112.0/20", "tcp": [443], "udp": []}],
    "research/ips": [{"net": "203.0.113.5/32", "tcp": [8080], "udp": [53]}, {"net": "2001:4860::/32", "tcp": [443], "udp": []}],
    "research/off": []}}


class McpSetTests(unittest.TestCase):
    def test_identity_is_its_own_network_and_table(self):
        item, profile = fw.identity("research/github"), fw.identity("research")
        self.assertEqual(item["network"], "hermes-mcp-research-github")
        self.assertNotEqual(item["bridge"], profile["bridge"])
        self.assertNotEqual(item["table"], profile["table"])
        self.assertLessEqual(len(item["bridge"]), 15)
        self.assertTrue(item["table"].startswith("hermes_fw_"))

    def test_only_the_allow_list_with_ports_and_dns_only_for_names(self):
        sets = fw.mcp_sets(MCP_CONF, "research/github", {"api.github.com": ["140.82.112.5", "2606:50c0::1"]})
        self.assertEqual(sets["allow_ports_v4"], ["140.82.112.0/20 . tcp . 443"])  # the address lies in the network
        self.assertEqual(sets["allow_ports_v6"], ["2606:50c0::1/128 . tcp . 443"])
        self.assertEqual(sets["dns_v4"], ["192.168.0.5"])
        ips = fw.mcp_sets(MCP_CONF, "research/ips", {})
        self.assertEqual(ips["allow_ports_v4"], ["203.0.113.5/32 . tcp . 8080", "203.0.113.5/32 . udp . 53"])
        self.assertEqual((ips["dns_v4"], ips["dns_v6"]), ([], []))
        self.assertEqual(fw.mcp_dns(MCP_CONF, "research/ips"), [fw.NO_DNS])
        self.assertEqual(fw.mcp_dns(MCP_CONF, "research/github"), ["192.168.0.5"])

    def test_nothing_opens_it_apart_from_its_list(self):
        for key in ("research/off", "research/unknown"):
            sets = fw.mcp_sets(MCP_CONF, key, {})
            self.assertFalse(any(sets.values()), key)
        text = fw.rules("research/ips", fw.mcp_sets(MCP_CONF, "research/ips", {}))
        self.assertNotIn("192.168.0.5", text)
        self.assertRegex(text, r"meta l4proto tcp counter reject with tcp reset\n\s+counter reject with icmpx")

    def test_a_name_that_never_resolved_allows_nothing(self):
        sets = fw.mcp_sets(MCP_CONF, "research/github", {})
        self.assertEqual(sets["allow_ports_v4"], ["140.82.112.0/20 . tcp . 443"])
        sets = fw.mcp_sets({**MCP_CONF, "mcp": {"r/x": [{"host": "a.org", "tcp": [443], "udp": []}]}}, "r/x", {})
        self.assertEqual((sets["allow_ports_v4"], sets["allow_ports_v6"]), ([], []))

    def addresses(self, directory, answer, now):
        conf = {**CONF, "mcp": {"r/x": [{"host": "a.org", "tcp": [443], "udp": []}]}}
        with patch.object(fw, "CACHE", Path(directory) / "resolved.json"), patch.object(fw, "trusted"), \
             patch.object(fw, "resolve_host", **answer), patch.object(fw.time, "time", return_value=now), \
             patch("builtins.print"):
            return fw.mcp_addresses(conf)

    def test_addresses_accumulate_survive_failures_and_age_out(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.addresses(directory, {"return_value": ["1.1.1.1"]}, 1000), {"a.org": ["1.1.1.1"]})
            self.assertEqual(self.addresses(directory, {"return_value": ["2.2.2.2"]}, 2000), {"a.org": ["1.1.1.1", "2.2.2.2"]})
            self.assertEqual(self.addresses(directory, {"side_effect": OSError("down")}, 3000), {"a.org": ["1.1.1.1", "2.2.2.2"]})
            self.assertEqual(self.addresses(directory, {"return_value": ["2.2.2.2"]}, 1000 + fw.MCP_ADDRESS_KEEP), {"a.org": ["2.2.2.2"]})
            self.assertEqual(self.addresses(directory, {"side_effect": OSError("down")}, 9 * fw.MCP_ADDRESS_KEEP), {})

    def test_free_subnet_skips_what_is_in_use(self):
        networks_json = json.dumps([{"IPAM": {"Config": [{"Subnet": "172.31.240.16/28"}, {"Subnet": "fd00::/64"}]}}])
        routes = json.dumps([{"dst": "default"}, {"dst": "172.31.240.32/28"}])
        def run(*arguments, **kwargs):
            if arguments[:3] == ("docker", "network", "ls"):
                return result("abc\n")
            return result(networks_json if arguments[0] == "docker" else routes)
        data = {"mcp": {"r/x": {"subnet": "172.31.240.0/28"}}}
        with patch.object(fw, "run", side_effect=run):
            self.assertEqual(fw.free_subnet(data, MCP_CONF), "172.31.240.48/28")
            with self.assertRaisesRegex(fw.FirewallError, "No free network"):
                fw.free_subnet(data, {**MCP_CONF, "mcp_subnet": "172.31.240.0/27"})


class McpStateTests(unittest.TestCase):
    def state(self, entry, text=None, name="github"):
        arguments = entry.get("args") or []
        return fw.mcp_state("research", name, entry, " ".join(map(str, arguments)) if text is None else text)

    def docker(self, *arguments):
        return {"command": "docker", "args": ["run", *arguments, "-i", "--rm", "ghcr.io/x/y"]}

    def test_a_plain_docker_run_can_be_changed(self):
        self.assertEqual(self.state(self.docker())[0], "ready")
        self.assertEqual(self.state({"command": "/usr/bin/docker", "args": ["run", "img"]})[0], "ready")
        self.assertIn("mcp add research github", self.state(self.docker())[1])

    def test_expanded_values_are_never_written_back(self):
        # config.yaml says ${TOKEN}; Hermes hands out the value.
        entry = self.docker("-e", "TOKEN=ghp_secret")
        self.assertEqual(self.state(entry, "args: [run, -e, 'TOKEN=${TOKEN}', -i, --rm, ghcr.io/x/y]")[0], "manual")
        self.assertEqual(self.state(entry, "")[0], "manual")

    def test_protected_and_isolated_are_recognised(self):
        self.assertEqual(self.state(self.docker("--network=hermes-mcp-research-github", "--dns=9.9.9.9"))[0], "protected")
        self.assertEqual(self.state(self.docker("--network=none"))[0], "isolated")
        self.assertEqual(self.state({"command": "bash", "args": ["-c", "docker run --network=hermes-mcp-research-github i"]})[0], "protected")

    def test_foreign_networks_and_escapes_are_refused(self):
        for entry in (self.docker("--network=host"), self.docker("--network", "bridge"), self.docker("--net=host"),
                      self.docker("-i", "--dns=8.8.8.8"), self.docker("--network=hermes-mcp-research-other"),
                      {"command": "docker", "args": ["run", "img", "--network=x"]},
                      self.docker("--privileged"), self.docker("-v", "/var/run/docker.sock:/s"), self.docker("--pid=host"),
                      self.docker("--cap-add=SYS_ADMIN")):
            with self.subTest(entry=entry):
                self.assertEqual(self.state(entry)[0], "refused")
        self.assertEqual(self.state(self.docker(), name="a.b")[0], "refused")
        self.assertEqual(self.state({**self.docker(), "env": {"DOCKER_HOST": "tcp://other:2375"}})[0], "refused")
        self.assertEqual(self.state({**self.docker(), "env": {"TOKEN": "x"}})[0], "ready")

    def test_other_ways_to_start_docker_get_a_hint_only(self):
        for entry in ({"command": "docker", "args": ["compose", "run", "x"]}, {"command": "docker", "args": ["exec", "-i", "c", "x"]},
                      {"command": "docker", "args": ["--context", "x", "run", "i"]}, {"command": "bash", "args": ["-c", "docker run i"]},
                      {"command": "podman", "args": ["run", "i"]}):
            with self.subTest(entry=entry):
                state, text = self.state(entry)
                self.assertEqual(state, "manual")
                self.assertIn("--network=hermes-mcp-research-github", text)

    def test_what_is_no_container_is_named(self):
        self.assertEqual(self.state({"command": "npx", "args": ["-y", "x"]})[0], "host")
        self.assertEqual(self.state({"url": "https://x"})[0], "url")
        self.assertEqual(self.state({**self.docker(), "enabled": False})[0], "off")


class McpHermesSideTests(unittest.TestCase):
    """As the Hermes user: only the args of the named server, and only own entries right after run."""
    NETWORK = "--network=hermes-mcp-research-github"

    def attach(self, arguments, conf=MCP_CONF, text=None, function=None):
        calls, servers = [], {"github": {"command": "docker", "args": list(arguments)}}
        def hermes(*words):
            calls.append(words)
            servers["github"]["args"] = json.loads(words[-1])
        with patch.object(fw, "hermes", side_effect=hermes), patch.object(fw, "mcp_servers", return_value=servers), \
             patch.object(fw, "config_file_text", return_value=" ".join(arguments) if text is None else text), \
             patch.object(fw, "load_config", return_value=conf), patch("builtins.print") as output:
            (function or fw.hermes_mcp_attach)("research", "github")
        return calls, servers["github"]["args"], output

    def test_network_and_dns_go_right_after_run(self):
        calls, args, _ = self.attach(["run", "-i", "--rm", "img", "--flag"])
        self.assertEqual(args, ["run", self.NETWORK, "--dns=192.168.0.5", "-i", "--rm", "img", "--flag"])
        self.assertEqual(calls[0][:4], ("-p", "research", "config", "set"))
        self.assertEqual(calls[0][4], "mcp_servers.github.args")
        self.assertEqual(len(calls), 1)

    def test_no_names_means_no_real_dns_server(self):
        conf = {**MCP_CONF, "mcp": {"research/github": [{"net": "1.2.3.4/32", "tcp": [443], "udp": []}]}}
        _, args, _ = self.attach(["run", "img"], conf)
        self.assertEqual(args, ["run", self.NETWORK, f"--dns={fw.NO_DNS}", "img"])

    def test_nothing_is_written_when_nothing_changes(self):
        calls, _, _ = self.attach(["run", self.NETWORK, "--dns=192.168.0.5", "img"])
        self.assertEqual(calls, [])

    def test_changed_dns_replaces_only_own_entries(self):
        _, args, _ = self.attach(["run", self.NETWORK, f"--dns={fw.NO_DNS}", "-i", "img"])
        self.assertEqual(args, ["run", self.NETWORK, "--dns=192.168.0.5", "-i", "img"])

    def test_args_with_expanded_values_are_not_written(self):
        calls, _, _ = self.attach(["run", "-e", "T=secret", "img"], text="run -e T=${T} img")
        self.assertEqual(calls, [])
        with self.assertRaisesRegex(fw.FirewallError, "change them yourself"):
            self.attach(["run", self.NETWORK, "--dns=9.9.9.9", "-e", "T=secret", "img"], text=f"run {self.NETWORK} --dns=9.9.9.9 -e T=${{T}} img")

    def test_refused_servers_are_not_touched(self):
        with self.assertRaisesRegex(fw.FirewallError, "--network=host"):
            self.attach(["run", "--network=host", "img"])

    def test_detach_leaves_no_network_never_an_unfiltered_one(self):
        calls, args, output = self.attach(["run", self.NETWORK, "--dns=9.9.9.9", "-i", "img"], function=fw.hermes_mcp_detach)
        self.assertEqual(args, ["run", "--network=none", "-i", "img"])
        self.assertIn("without any network", output.call_args.args[0])

    def test_attach_again_after_detach(self):
        _, args, _ = self.attach(["run", "--network=none", "-i", "img"])
        self.assertEqual(args, ["run", self.NETWORK, "--dns=192.168.0.5", "-i", "img"])

    def test_a_server_that_is_switched_off_can_get_its_firewall_first(self):
        calls, servers = [], {"github": {"command": "docker", "args": ["run", "img"], "enabled": False}}
        def hermes(*words):
            calls.append(words)
            servers["github"]["args"] = json.loads(words[-1])
        with patch.object(fw, "hermes", side_effect=hermes), patch.object(fw, "mcp_servers", return_value=servers), \
             patch.object(fw, "config_file_text", return_value="run img --network=none hermes-mcp-research-github"), \
             patch.object(fw, "load_config", return_value=MCP_CONF), patch("builtins.print"):
            fw.hermes_mcp_attach("research", "github")
            self.assertEqual(servers["github"]["args"], ["run", self.NETWORK, "--dns=192.168.0.5", "img"])
            with patch.object(fw, "config_file_text", return_value=f"run {self.NETWORK} --dns=192.168.0.5 img"):
                fw.hermes_mcp_detach("research", "github")
            self.assertEqual(servers["github"]["args"], ["run", "--network=none", "img"])

    def test_detach_of_a_hand_made_setup_says_what_to_do(self):
        calls, _, output = self.attach(["run", self.NETWORK, "-e", "T=x", "img"], text="${T}", function=fw.hermes_mcp_detach)
        self.assertEqual(calls, [])
        self.assertIn("will not start", output.call_args.args[0])

    def test_mcp_servers_reads_unmasked_and_tolerates_none(self):
        with patch.object(fw, "hermes", return_value='{"a": {"url": "x"}}') as hermes:
            self.assertEqual(fw.mcp_servers("research"), {"a": {"url": "x"}})
        self.assertIn("--raw", hermes.call_args.args)
        with patch.object(fw, "hermes", side_effect=fw.FirewallError("Config key not set: mcp_servers")):
            self.assertEqual(fw.mcp_servers("research"), {})
        with patch.object(fw, "hermes", side_effect=fw.FirewallError("boom")), self.assertRaises(fw.FirewallError):
            fw.mcp_servers("research")

    def test_internal_command_refuses_root_and_bad_names(self):
        with patch.object(fw.os, "geteuid", return_value=1000):
            for words in (["_hermes", "mcp-attach", "research"], ["_hermes", "mcp-attach", "research", "a.b"],
                          ["_hermes", "mcp-scan", "research/x"], ["_hermes", "mcp-other", "research", "x"]):
                with self.subTest(words=words), self.assertRaises(fw.FirewallError):
                    fw.user_command(words)


class McpAllowDialogTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.user = pwd.struct_passwd(("hermes", "x", 1000, 1000, "", self.home.name, "/bin/bash"))

    def ask(self, answers, tty=True, state="ready"):
        with patch.object(fw, "load_config", return_value={**MCP_CONF, "mcp": {}}), patch.object(fw.sys.stdin, "isatty", return_value=tty), \
             patch.object(fw, "mcp_check", return_value=state) as check, patch("builtins.input", side_effect=answers) as asked, \
             patch("builtins.print") as output:
            allow = fw.mcp_ask_allow("research", "github", self.user)
        return allow, check, asked, "\n".join(str(c.args[0]) for c in output.call_args_list if c.args)

    def test_it_says_where_the_list_goes_and_how_to_change_it_yourself(self):
        _, _, asked, output = self.ask(["n"])
        self.assertIn(str(fw.CONFIG), output)
        self.assertIn("edit that file yourself", output)
        self.assertIn("sudo hermes-firewall refresh", output)
        self.assertIn("Do you want to allow certain hosts or networks for this MCP server?", asked.call_args_list[0].args[0])

    def test_no_means_it_reaches_nothing(self):
        for answers in (["n"], [""], ["y", ""]):
            with self.subTest(answers=answers):
                self.assertEqual(self.ask(answers)[0], [])

    def test_hosts_addresses_and_networks_with_their_ports(self):
        allow, _, _, _ = self.ask(["y", "api.github.com", "", "", "140.82.112.3", "80, 443", "53", "2001:db8::/32", "443", "none", ""])
        self.assertEqual(allow, [{"host": "api.github.com", "tcp": [443], "udp": []},
                                 {"net": "140.82.112.3/32", "tcp": [80, 443], "udp": [53]},
                                 {"net": "2001:db8::/32", "tcp": [443], "udp": []}])

    def test_wrong_answers_are_asked_again(self):
        allow, _, _, output = self.ask(["y", "a b", "1.2.3.4/33", "999.1.1.1", "0.0.0.0/0", "x.org", "0", "abc", "70000", "443", "", ""])
        self.assertEqual(allow, [{"host": "x.org", "tcp": [443], "udp": []}])
        self.assertIn("Not a host name", output)
        self.assertIn("whole address family", output)
        self.assertIn("Port numbers", output)

    def test_a_target_without_any_port_is_not_accepted(self):
        allow, _, _, output = self.ask(["y", "x.org", "none", "none", "8443", "", ""])
        self.assertEqual(allow, [{"host": "x.org", "tcp": [8443], "udp": []}])
        self.assertIn("at least one port", output)

    def test_no_questions_without_a_terminal_or_with_a_list(self):
        allow, check, asked, _ = self.ask([], tty=False)
        self.assertIsNone(allow)
        check.assert_not_called()
        asked.assert_not_called()
        with patch.object(fw, "load_config", return_value=MCP_CONF), patch.object(fw.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input") as asked:
            self.assertIsNone(fw.mcp_ask_allow("research", "github", self.user))
        asked.assert_not_called()

    def test_what_cannot_be_protected_is_refused_before_any_question(self):
        with patch.object(fw, "load_config", return_value={**MCP_CONF, "mcp": {}}), patch.object(fw.sys.stdin, "isatty", return_value=True), \
             patch.object(fw, "mcp_check", side_effect=fw.FirewallError("runs on the host")), patch("builtins.input") as asked, \
             self.assertRaisesRegex(fw.FirewallError, "runs on the host"):
            fw.mcp_ask_allow("research", "github", self.user)
        asked.assert_not_called()

    def test_stopping_changes_nothing(self):
        for stop in (EOFError(), KeyboardInterrupt()):
            with self.subTest(stop=stop), self.assertRaisesRegex(fw.FirewallError, "nothing was changed"):
                self.ask(["y", stop])

    def saved(self, allow, text='# my comment\n[sandbox]\ndns = ["192.168.0.5"]   # keep\n'):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text(text)
            with patch.object(fw, "CONF", Path(directory)), patch.object(fw, "CONFIG", config), patch.object(fw, "trusted"), \
                 patch("builtins.print") as output:
                conf = fw.mcp_save_allow("research", "github", allow)
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["config.toml"])
            return conf, config.read_text(), "\n".join(str(c.args[0]) for c in output.call_args_list)

    def test_saved_list_is_valid_and_the_rest_of_the_file_stays(self):
        allow = [{"host": "api.github.com", "tcp": [443], "udp": []}, {"net": "2001:db8::/32", "tcp": [], "udp": [53, 443]}]
        conf, text, output = self.saved(allow)
        self.assertEqual(conf["mcp"]["research/github"], allow)
        self.assertTrue(text.startswith('# my comment\n[sandbox]\ndns = ["192.168.0.5"]   # keep\n\n[[mcp]]\n'))
        self.assertIn('allow = [{ host = "api.github.com", tcp = [443] }, { net = "2001:db8::/32", udp = [53, 443] }]', text)
        self.assertIn("Saved in", output)
        self.assertIn("DNS servers", output)
        self.assertEqual(self.saved([])[0]["mcp"]["research/github"], [])
        self.assertIn("allow = []", self.saved([])[1])

    def test_a_broken_config_file_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text("broken = \n")
            with patch.object(fw, "CONF", Path(directory)), patch.object(fw, "CONFIG", config), patch.object(fw, "trusted"), \
                 self.assertRaises(fw.FirewallError):
                fw.mcp_save_allow("research", "github", [])
            self.assertEqual(config.read_text(), "broken = \n")
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["config.toml"])

    def test_add_saves_the_answers_and_uses_them(self):
        new = {**MCP_CONF, "mcp": {"research/github": [{"host": "x.org", "tcp": [443], "udp": []}]}}
        answers = [{"host": "x.org", "tcp": [443], "udp": []}]
        data = registry()
        (Path(self.home.name) / ".hermes").mkdir()
        with patch.object(fw, "load_config", return_value={**MCP_CONF, "mcp": {}}), patch.object(fw, "mcp_check", return_value="ready"), \
             patch.object(fw, "mcp_save_allow", return_value=new) as save, patch.object(fw, "as_user", return_value=""), \
             patch.object(fw, "docker_ready"), patch.object(fw, "free_subnet", return_value="172.31.240.0/28"), \
             patch.object(fw, "ipv6_enabled", return_value=False), patch.object(fw, "save_registry"), \
             patch.object(fw, "create_firewall", side_effect=lambda d, k, r, c: d.setdefault("mcp", {}).__setitem__(k, r)) as create, \
             patch("builtins.print") as output:
            fw.mcp_add(data, "research", "github", self.user, answers)
        save.assert_called_once_with("research", "github", answers)
        self.assertEqual(create.call_args.args[3], new)
        self.assertIn("x.org tcp 443", "\n".join(str(c.args[0]) for c in output.call_args_list))

    def test_questions_come_before_the_lock(self):
        order = []
        lock = os.stat_result((0o100600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        with tempfile.TemporaryDirectory() as directory, patch.object(fw, "LOCK", Path(directory) / "lock"), \
             patch.object(fw.os, "geteuid", return_value=0), patch.object(fw.os, "fstat", return_value=lock), \
             patch.object(fw, "hermes_user", return_value=self.user), patch.object(fw, "load_registry", side_effect=lambda: order.append("locked") or registry()), \
             patch.object(fw, "mcp_ask_allow", side_effect=lambda *a: order.append("asked") or []), \
             patch.object(fw, "mcp_add", side_effect=lambda *a: order.append(a[-1])):
            fw.main(["mcp", "add", "research", "github"])
        self.assertEqual(order, ["asked", "locked", []])


class StatusPartsTests(unittest.TestCase):
    def setUp(self):
        for name, value in (("replaceable_by_others", []), ("health", None), ("networks", {"hermes-fw-research", "hermes-mcp-research-github"}),
                            ("check_network", None), ("protect_sandboxes", []), ("load_config", MCP_CONF),
                            ("profile_line", "research: firewall active, Internet closed, LAN closed")):
            item = patch.object(fw, name, return_value=value)
            item.start()
            self.addCleanup(item.stop)
        self.data = {**registry("research"), "mcp": {"research/github": {"user": "hermes", "ipv6": False, "subnet": "172.31.240.0/28", "dns": []}}}

    def lines(self, data, selected=None, warnings=()):
        with patch.object(fw, "mcp_warnings", return_value=list(warnings)), patch.object(fw.pwd, "getpwnam", return_value=USER), \
             patch("builtins.print") as output:
            fw.status(data, selected=selected)
        return "\n".join(str(c.args[0]) for c in output.call_args_list).split("\n")

    def test_sandboxes_and_mcp_containers_are_two_parts(self):
        lines = self.lines(self.data, warnings=["research: WARNING - MCP server other runs in Docker WITHOUT a firewall."])
        blank = lines.index("")
        sandbox, mcp = lines[:blank], lines[blank + 1:]
        self.assertTrue(sandbox[0].startswith("Sandbox firewall"))
        self.assertEqual(sandbox[1], "  research: firewall active, Internet closed, LAN closed")
        self.assertIn("Always reachable", sandbox[2])
        self.assertTrue(mcp[0].startswith("MCP container firewall"))
        self.assertTrue(mcp[1].startswith("  research/github: firewall active, can reach only: api.github.com tcp 443"))
        self.assertIn("WARNING - MCP server other", mcp[2])
        self.assertEqual(len(sandbox) + len(mcp) + 1, len(lines))

    def test_the_mcp_part_also_says_when_there_is_nothing(self):
        lines = self.lines(registry("research"))
        self.assertTrue(lines[lines.index("") + 1].startswith("MCP container firewall"))
        self.assertTrue(lines[-1].startswith("  none"))

    def test_status_of_one_profile_stays_one_line_without_mcp_firewalls(self):
        self.assertEqual(self.lines(registry("research"), selected="research"), ["research: firewall active, Internet closed, LAN closed"])

    def test_status_of_one_profile_shows_only_its_own_mcp_firewalls(self):
        other = {"user": "hermes", "ipv6": False, "subnet": "172.31.240.16/28", "dns": []}
        data = {**self.data, "mcp": {**self.data["mcp"], "work/x": other}}
        lines = self.lines(data, selected="research")
        self.assertTrue(any(l.startswith("  research/github:") for l in lines))
        self.assertFalse(any("work/x" in l for l in lines))
        self.assertFalse(any("Always reachable" in l for l in lines))

    def test_the_plugin_still_reads_the_lease_line(self):
        lines = "\n".join(self.lines(self.data, selected="research"))
        self.assertRegex(lines, r"(?m)firewall active, Internet (.+?), LAN (.+)$")


class McpCommandTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        (Path(self.home.name) / ".hermes" / "profiles" / "research").mkdir(parents=True)
        self.user = pwd.struct_passwd(("hermes", "x", 1000, 1000, "", self.home.name, "/bin/bash"))

    def mcp_add(self, data, state="ready", existing_network=True, server="github", conf=MCP_CONF):
        calls = []
        def as_user(user, *arguments):
            calls.append(arguments)
            if arguments[0] == "mcp-scan":
                return 'greeting\n' + json.dumps([{"name": "github", "state": state, "text": "says why"}]) + "\n"
            return ""
        with patch.object(fw, "load_config", return_value=conf), patch.object(fw, "as_user", side_effect=as_user), \
             patch.object(fw, "health"), patch.object(fw, "docker_ready"), patch.object(fw, "check_network"), \
             patch.object(fw, "networks", return_value={"hermes-mcp-research-github"} if existing_network else set()), \
             patch.object(fw, "create_network") as network, patch.object(fw, "create_firewall") as create, \
             patch.object(fw, "free_subnet", return_value="172.31.240.0/28"), patch.object(fw, "ipv6_enabled", return_value=False), \
             patch.object(fw, "save_registry") as save, patch("builtins.print") as output:
            create.side_effect = lambda d, k, r, c: d.setdefault("mcp", {}).__setitem__(k, r)
            fw.mcp_add(data, "research", server, self.user)
        return calls, create, network, save, "\n".join(c.args[0] for c in output.call_args_list)

    def test_add_creates_the_firewall_before_touching_hermes(self):
        data = registry()
        calls, create, _, save, output = self.mcp_add(data)
        create.assert_called_once()
        self.assertEqual(calls, [("mcp-scan", "research"), ("mcp-attach", "research", "github")])
        self.assertEqual(data["mcp"]["research/github"],
                         {"user": "hermes", "ipv6": False, "subnet": "172.31.240.0/28", "dns": ["192.168.0.5"]})
        fw.validate_registry(data)
        save.assert_called()
        self.assertIn("api.github.com tcp 443", output)
        self.assertIn("/reload-mcp", output)

    def test_add_again_repairs_the_network(self):
        data = {**registry(), "mcp": {"research/github": {"user": "hermes", "ipv6": False, "subnet": "172.31.240.0/28", "dns": []}}}
        _, create, network, _, _ = self.mcp_add(data, "protected", existing_network=False)
        create.assert_not_called()
        network.assert_called_once()

    def test_without_a_terminal_add_explains_how_to_write_the_allow_list(self):
        conf = {**MCP_CONF, "mcp": {}}
        with self.assertRaisesRegex(fw.FirewallError, r"(?s)\[\[mcp\]\]\nprofile = \"research\".*allow = \[\{ host"):
            self.mcp_add(registry(), conf=conf)

    def test_add_refuses_what_it_cannot_protect(self):
        for state in ("refused", "host", "url"):
            with self.subTest(state=state), self.assertRaisesRegex(fw.FirewallError, "says why"):
                self.mcp_add(registry(), state)
        with self.assertRaisesRegex(fw.FirewallError, "no MCP server"):
            self.mcp_add(registry(), server="research-x", conf={**MCP_CONF, "mcp": {"research/research-x": []}})

    def test_manual_setups_get_the_network_and_a_hint(self):
        _, create, _, _, output = self.mcp_add(registry(), "manual")
        create.assert_called_once()
        self.assertIn("--network=hermes-mcp-research-github --dns=192.168.0.5", output)

    def test_remove_detaches_before_removing_network_and_protection(self):
        data = {**registry(), "mcp": {"research/github": {"user": "hermes", "ipv6": False, "subnet": "172.31.240.0/28", "dns": []}}}
        order = []
        def run(*arguments, **kwargs):
            order.append(arguments[:3])
            return result("c1\n" if arguments[:2] == ("docker", "ps") else "")
        with patch.object(fw, "docker_ready"), patch.object(fw, "networks", return_value={"hermes-mcp-research-github"}), \
             patch.object(fw, "check_network"), patch.object(fw.pwd, "getpwnam", return_value=self.user), \
             patch.object(fw, "as_user", side_effect=lambda u, *a: order.append(a) or "It runs without any network now.\n"), \
             patch.object(fw, "run", side_effect=run), patch.object(fw, "interface_exists", return_value=False), \
             patch.object(fw, "nft_apply", side_effect=lambda text: order.append("table")), patch.object(fw, "save_registry"), \
             patch("builtins.print") as output:
            fw.mcp_remove(data, "research", "github")
        self.assertEqual(order[0], ("mcp-detach", "research", "github"))
        self.assertLess(order.index(("docker", "network", "rm")), order.index("table"))
        self.assertEqual(data["mcp"], {})
        self.assertIn("without any network", output.call_args.args[0])

    def test_profile_with_mcp_firewalls_is_not_removed_first(self):
        data = {**registry("research"), "mcp": {"research/github": {"user": "hermes", "ipv6": False, "subnet": "172.31.240.0/28", "dns": []}}}
        with self.assertRaisesRegex(fw.FirewallError, "mcp remove research github"):
            fw.remove_profile(data, "research")

    def test_uninstall_refuses_remaining_mcp_firewalls(self):
        data = {**registry(), "mcp": {"research/github": {"user": "hermes", "ipv6": False, "subnet": "172.31.240.0/28", "dns": []}}}
        with self.assertRaisesRegex(fw.FirewallError, "mcp remove"):
            fw.uninstall(data)

    def test_warnings_name_what_runs_without_a_firewall(self):
        report = [{"name": n, "state": s, "text": "t"} for n, s in (("a", "ready"), ("b", "manual"), ("c", "refused"),
                                                                    ("d", "protected"), ("e", "isolated"), ("f", "host"), ("g", "url"))]
        with patch.object(fw, "mcp_report", return_value=report):
            self.assertEqual([m.split()[5] for m in fw.mcp_warnings("research", self.user)], ["a", "b", "c"])
        with patch.object(fw, "mcp_report", side_effect=fw.FirewallError("no")):
            self.assertIn("could not check", fw.mcp_warnings("research", self.user)[0])

    def test_untrusted_scan_answers_are_refused(self):
        for answer in ("", "not json", "{}", '[{"name": "a"}]', '[{"name": 1, "state": "x", "text": "y"}]'):
            with self.subTest(answer=answer), patch.object(fw, "as_user", return_value=answer), \
                 self.assertRaisesRegex(fw.FirewallError, "Unexpected answer"):
                fw.mcp_report(self.user, "research")

    def test_registry_and_transactions_cover_mcp_firewalls(self):
        record = {"user": "hermes", "ipv6": False, "subnet": "172.31.240.0/28", "dns": []}
        data = {**registry("research"), "mcp": {"research/github": record}}
        fw.validate_registry(data)
        self.assertEqual(fw.targets(data), ["research", "research/github"])
        text = fw.refresh_transaction(data, {"research": {}, "research/github": {"allow_ports_v4": ["1.2.3.4/32 . tcp . 443"]}})
        self.assertIn(f"add element inet {fw.identity('research/github')['table']} allow_ports_v4", text)
        for bad in ({**registry(), "mcp": {"research": record}}, {**registry(), "mcp": {"r/x": {**record, "label": ""}}},
                    {**registry(), "mcp": []}):
            with self.subTest(bad=bad), self.assertRaises(fw.FirewallError):
                fw.validate_registry(bad)
        fw.validate_registry(registry("research"))  # registries from before MCP firewalls stay valid

    def test_mcp_firewalls_have_no_leases_and_no_sudo_rules(self):
        record = {"user": "hermes", "ipv6": False, "subnet": "172.31.240.0/28", "dns": []}
        data = {**registry("research"), "mcp": {"research/github": record}}
        self.assertNotIn("github", fw.sudoers_text(data))
        for call in (lambda: fw.open_lease(data, "research/github", []), lambda: fw.close_lease(data, "research/github", []),
                     lambda: fw.remove_profile(data, "research/github")):
            with self.assertRaisesRegex(fw.FirewallError, "never opens"):
                call()
        with self.assertRaisesRegex(fw.FirewallError, "profile name"):
            fw.add_profile(data, "research/github", self.user)


class StateFileTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name) / "run"
        item = patch.object(fw, "STATE", self.state)
        item.start()
        self.addCleanup(item.stop)

    def read(self, profile="research"):
        return json.loads((self.state / f"{profile}.json").read_text())

    def test_holds_end_times_readable_by_everyone(self):
        with patch.object(fw, "lease_remaining", side_effect=lambda p, kind: 600 if kind == "lan" else None), \
             patch.object(fw.time, "time", return_value=1000):
            fw.write_state("research")
        self.assertEqual(self.read(), {"internet": None, "lan": 1600})
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.state / "research.json").stat().st_mode & 0o777, 0o644)

    def test_failure_only_warns_because_the_lease_is_already_in_the_kernel(self):
        with patch.object(fw, "lease_remaining", side_effect=fw.FirewallError("nft failed")), \
             patch("builtins.print") as output:
            fw.write_state("research")
        self.assertIn("nft failed", output.call_args.args[0])
        self.assertFalse((self.state / "research.json").exists())

    def test_open_and_close_report_the_new_state_after_applying_it(self):
        order = []
        with patch.object(fw, "load_config", return_value=CONF), patch.object(fw, "health"), \
             patch.object(fw, "docker_ready"), patch.object(fw, "check_network"), \
             patch.object(fw, "nft_apply", side_effect=lambda text: order.append("nft")), \
             patch.object(fw, "write_state", side_effect=lambda profile: order.append(profile)), \
             patch.object(fw, "profile_line", return_value=""), patch("builtins.print"):
            fw.open_lease(registry("research"), "research", ["lan"])
            fw.close_lease(registry("research"), "research", [])
        self.assertEqual(order, ["nft", "research", "nft", "research"])

    def test_restore_reports_every_profile_as_closed(self):
        lock = os.stat_result((0o100600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        with tempfile.TemporaryDirectory() as directory, patch.object(fw, "LOCK", Path(directory) / "lock"), \
             patch.object(fw.os, "geteuid", return_value=0), patch.object(fw.os, "fstat", return_value=lock), \
             patch.object(fw, "load_registry", return_value=registry("research", "work")), \
             patch.object(fw, "restore_transaction", return_value=""), patch.object(fw, "nft_apply"), \
             patch.object(fw, "lease_remaining", return_value=None), patch("builtins.print"):
            fw.main(["restore"])
        self.assertEqual(self.read("research"), {"internet": None, "lan": None})
        self.assertEqual(self.read("work"), {"internet": None, "lan": None})


class SudoArgumentFuzzTests(unittest.TestCase):
    """sudoers allows 'open P *' and 'close P *': whatever follows must either be a valid lease
    request or fail before anything changes."""
    TOKENS = ["internet", "lan", "all", "for", "30s", "10m", "2h", "24h", "25h", "0s", "1d", "01h", "-1h",
              "--yes", "--bundle=/tmp/x", "-v", "--", "-", "upgrade", "install", "remove", "add", "status",
              "research", "work", "../x", "/etc/passwd", "lan;id", "$(id)", "`id`", "lan\nall", "1h ", "",
              "ALL", "Internet", "ä", "x" * 300, "for", "for"]

    def valid(self, verb, words):
        kinds = [w for w in words if w in ("internet", "lan", "all")]
        durations = [w for w in words if w in ("30s", "10m", "2h", "24h")]
        rest = [w for w in words if w != "for" and w not in kinds and w not in durations]
        if verb == "close":
            return not rest and not durations and "for" not in words and len(kinds) <= 1
        return not rest and len(kinds) <= 1 and len(durations) <= 1

    def run_main(self, argv):
        applied = []
        lock = os.stat_result((0o100600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(fw, "LOCK", Path(directory) / "lock"), patch.object(fw.os, "geteuid", return_value=0), \
             patch.object(fw.os, "fstat", return_value=lock), patch.object(fw, "load_registry", return_value=registry("research")), \
             patch.object(fw, "load_config", return_value=CONF), patch.object(fw, "health"), patch.object(fw, "docker_ready"), \
             patch.object(fw, "check_network"), patch.object(fw, "profile_line", return_value=""), \
             patch.object(fw, "nft_apply", side_effect=applied.append), patch.object(fw, "run") as run, \
             patch.object(fw, "write_state"), patch("builtins.print"):
            try:
                fw.main(argv)
                error = None
            except fw.FirewallError as caught:
                error = caught
        return error, applied, run

    def test_random_arguments_behind_open_and_close(self):
        import random
        rng = random.Random(4711)  # fixed seed: the same cases on every run
        cases = [[]] + [[rng.choice(self.TOKENS) for _ in range(rng.randint(1, 4))] for _ in range(1500)]
        for verb in ("open", "close"):
            for words in cases:
                with self.subTest(verb=verb, words=words):
                    error, applied, run = self.run_main([verb, "research", *words])
                    run.assert_not_called()  # never another command
                    if self.valid(verb, words):
                        self.assertIsNone(error)
                        self.assertEqual(len(applied), 1)
                        self.assertNotIn("delete table", applied[0])
                        self.assertNotIn("work", applied[0])
                    else:
                        self.assertIsNotNone(error)
                        self.assertEqual(applied, [])

    def test_other_profiles_are_never_touched(self):
        for argv in (["open", "work"], ["close", "work", "lan"], ["open", "research/../work"], ["open", "Research"]):
            with self.subTest(argv=argv):
                error, applied, _ = self.run_main(argv)
                self.assertIsNotNone(error)
                self.assertEqual(applied, [])


if __name__ == "__main__":
    unittest.main()

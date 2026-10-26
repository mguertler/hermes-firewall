"""Tests of the Hermes plugin /firewall; Hermes itself is not needed."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hermes_firewall_plugin", ROOT / "plugin" / "hermes-firewall" / "__init__.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def result(output="", code=0, error=""):
    return subprocess.CompletedProcess([], code, output, error)


class PluginTests(unittest.TestCase):
    def run_handle(self, raw, output=result("research: firewall active, Internet closed, LAN closed\n")):
        with patch.object(plugin, "profile_name", return_value="research"), \
             patch.object(plugin.subprocess, "run", return_value=output) as run:
            return plugin.handle(raw), run

    def test_commands_become_one_sudo_call_for_this_profile(self):
        for raw, words in (("open", ["open"]), ("open lan 30m", ["open", "lan", "30m"]),
                           ("open for internet 2h", ["open", "for", "internet", "2h"]),
                           ("close", ["close"]), ("close lan", ["close", "lan"]), ("status", ["status"])):
            with self.subTest(raw=raw):
                answer, run = self.run_handle(raw)
                self.assertEqual(run.call_args.args[0], ["sudo", "-n", plugin.EXE, words[0], "research", *words[1:]])
                self.assertEqual(answer, "research: firewall active, Internet closed, LAN closed")

    def test_anything_else_shows_usage_without_calling_sudo(self):
        for raw in ("", "help", "add", "remove", "status extra", "open --bundle=/tmp/x", "open lan;reboot",
                    "open ../x", "open LAN"):
            with self.subTest(raw=raw):
                answer, run = self.run_handle(raw)
                self.assertEqual(answer, plugin.USAGE)
                run.assert_not_called()

    def test_missing_sudoers_rule_is_explained(self):
        answer, _ = self.run_handle("open", result(code=1, error="sudo: a password is required\n"))
        self.assertIn("sudo hermes-firewall add research", answer)
        answer, _ = self.run_handle("open 30h", result(code=1, error="ERROR: The longest lease is 24h.\n"))
        self.assertEqual(answer, "The longest lease is 24h.")

    def test_profile_from_hermes_home(self):
        with tempfile.TemporaryDirectory() as home, patch.object(plugin.Path, "home", return_value=Path(home)), \
             patch.dict("sys.modules", {"hermes_cli": None, "hermes_cli.profiles": None}):
            root = Path(home) / ".hermes"
            (root / "profiles" / "research").mkdir(parents=True)
            for hermes_home, expected in ((root, "default"), (root / "profiles" / "research", "research"),
                                          (Path(home) / "elsewhere", None)):
                with self.subTest(home=hermes_home), patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}):
                    self.assertEqual(plugin.profile_name(), expected)

    def test_unknown_profile_is_refused(self):
        with patch.object(plugin, "profile_name", return_value=None), patch.object(plugin.subprocess, "run") as run:
            self.assertIn("cannot tell", plugin.handle("open"))
        run.assert_not_called()

    def test_registers_a_slash_command_not_a_tool(self):
        class Context:
            def __init__(self):
                self.commands = []
            def register_command(self, name, handler, description="", args_hint=""):
                self.commands.append((name, handler))
        ctx = Context()
        plugin.register(ctx)
        self.assertEqual(ctx.commands, [("firewall", plugin.handle)])

    def test_manifest_matches(self):
        manifest = (ROOT / "plugin" / "hermes-firewall" / "plugin.yaml").read_text()
        self.assertIn("name: hermes-firewall\n", manifest)
        firewall = (ROOT / "hermes_firewall.py").read_text()
        version = firewall.split('VERSION = "', 1)[1].split('"', 1)[0]
        self.assertIn(f"version: {version}\n", manifest)


if __name__ == "__main__":
    unittest.main()

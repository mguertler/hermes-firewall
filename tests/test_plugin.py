"""Tests of the Hermes plugin /firewall; Hermes itself is not needed."""
import importlib.util
import json
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


class Context:
    """The parts of Hermes' PluginContext the plugin uses."""
    def __init__(self, settings=None):
        self.commands, self.hooks, self.settings = [], [], settings or {}

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands.append((name, handler))

    def register_hook(self, name, callback):
        self.hooks.append((name, callback))

    def get_config(self, key, default=None):
        return self.settings.get(key, default)


CLOSED = result("research: firewall active, Internet closed, LAN closed\n")
OPEN = result("research: firewall active, Internet open for 41m (until 14:32), LAN open for 41m (until 14:32)\n")


class AgentNoticeTests(unittest.TestCase):
    def hook(self, settings):
        ctx = Context(settings)
        plugin.register(ctx)
        return dict(ctx.hooks)["transform_terminal_output"]

    def call(self, hook, status=CLOSED, **kwargs):
        args = {"command": "curl -s https://example.com", "output": "", "returncode": 28, "env_type": "docker",
                "task_id": "t", "tool_call_id": "c", **kwargs}
        with patch.object(plugin, "profile_name", return_value="research"), \
             patch.object(plugin.subprocess, "run", return_value=status) as run:
            return hook(**args), run

    def test_off_by_default_and_costs_nothing(self):
        answer, run = self.call(self.hook({}))
        self.assertIsNone(answer)
        run.assert_not_called()

    def test_network_failure_on_closed_firewall_gets_one_line(self):
        hook = self.hook({"agent_notice": True})
        for command, output, code in (("curl -s https://example.com", "", 28),
                                      ("pip install requests", "Failed to establish a new connection", 1),
                                      ("git clone https://github.com/x/y", "fatal: unable to access 'https://github.com/x/y/': "
                                                                          "Failed to connect to github.com port 443", 128),
                                      ("npm install", "npm ERR! code ETIMEDOUT", 1),
                                      ("curl https://example.com", "curl: (7) Failed to connect: Connection refused", 7),
                                      ("pip download x", "Connection reset by peer", 1)):
            with self.subTest(command=command):
                answer, run = self.call(hook, command=command, output=output, returncode=code)
                self.assertTrue(answer.startswith(output))
                self.assertEqual(answer.count("\n[hermes-firewall]"), 1)
                self.assertIn("Internet closed, LAN closed", answer)
                self.assertIn("/firewall open", answer)
                self.assertEqual(run.call_args.args[0][:5], ["sudo", "-n", plugin.EXE, "status", "research"])

    def test_everything_else_is_left_alone_without_asking_the_firewall(self):
        hook = self.hook({"agent_notice": True})
        for kwargs in ({"returncode": 0}, {"returncode": None}, {"env_type": "local"},
                       {"command": "ls /nope", "output": "No such file or directory", "returncode": 2},
                       {"command": "python3 x.py", "output": "SyntaxError", "returncode": 1},
                       {"command": "curl http://localhost:8000", "output": "Connection refused", "returncode": 7},
                       {"command": "python3 -m app", "output": "connect to 127.0.0.1:5432: Connection refused", "returncode": 1}):
            with self.subTest(kwargs=kwargs):
                answer, run = self.call(hook, **kwargs)
                self.assertIsNone(answer)
                run.assert_not_called()

    def test_open_or_unknown_firewall_is_not_blamed(self):
        hook = self.hook({"agent_notice": True})
        self.assertIsNone(self.call(hook, status=OPEN)[0])
        self.assertIsNone(self.call(hook, status=result(code=1, error="sudo: a password is required"))[0])
        partly = result("research: firewall active, Internet open for 5m (until 14:00), LAN closed\n")
        self.assertIn("Internet open for 5m (until 14:00), LAN closed", self.call(hook, status=partly)[0])


class Hermes(Context):
    """A Hermes with frozen system prompt sections."""
    def __init__(self, settings=None):
        super().__init__(settings)
        self.sections = {}

    def register_system_prompt_section(self, id, content, **kwargs):
        self.sections[id] = content


class PromptRuleTests(unittest.TestCase):
    def rendered(self, settings):
        ctx = Hermes(settings)
        with patch.object(plugin.subprocess, "run") as run:
            plugin.register(ctx)
            text = ctx.sections["hermes-firewall.rule"]({"session_id": "s", "profile_name": "research"})
        run.assert_not_called()  # the rule holds no state, so it needs no firewall call
        return text

    def test_on_by_default_without_any_state(self):
        text = self.rendered({})
        self.assertEqual(text, plugin.RULE)
        self.assertIn("/firewall open", text)
        self.assertLess(len(text), 4000)  # Hermes skips longer sections
        self.assertNotIn("Internet", text)  # no state: a frozen state would go stale

    def test_can_be_switched_off(self):
        self.assertEqual(self.rendered({"prompt_rule": False}), "")  # empty: Hermes adds nothing

    def test_section_id_is_valid_for_hermes(self):
        ctx = Hermes()
        plugin.register(ctx)
        for name in ctx.sections:
            self.assertRegex(name, r"^[a-z0-9._-]{1,128}$")

    def test_older_hermes_without_sections_still_loads(self):
        ctx = Context()
        plugin.register(ctx)
        self.assertEqual(ctx.commands, [("firewall", plugin.handle)])


class StatusLineTests(unittest.TestCase):
    def hook(self, settings):
        ctx = Context(settings)
        plugin.register(ctx)
        return dict(ctx.hooks)["pre_llm_call"]

    def call(self, hook, content, now=1000):
        with tempfile.TemporaryDirectory() as directory, patch.object(plugin, "STATE", Path(directory)), \
             patch.object(plugin, "profile_name", return_value="research"), patch.object(plugin.time, "time", return_value=now), \
             patch.object(plugin.subprocess, "run") as run:
            if content is not None:
                (Path(directory) / "research.json").write_text(content)
            answer = hook(session_id="s", user_message="hi", telemetry_schema_version="x")
        run.assert_not_called()  # never sudo, not once per turn
        return answer

    def test_off_by_default(self):
        self.assertIsNone(self.call(self.hook({}), json.dumps({"internet": None, "lan": None})))

    def test_shows_the_current_state_when_switched_on(self):
        hook = self.hook({"status_line": True})
        for leases, expected in (({"internet": None, "lan": None}, "Internet closed, LAN closed"),
                                 ({"internet": 3460, "lan": None}, "Internet open for 41m, LAN closed"),
                                 ({"internet": None, "lan": 1030}, "Internet closed, LAN open for 30s"),
                                 ({"internet": 8380, "lan": 8380}, "Internet open for 2h 03m, LAN open for 2h 03m")):
            with self.subTest(leases=leases):
                self.assertEqual(self.call(hook, json.dumps(leases)), f"[hermes-firewall] Sandbox firewall: {expected}.")

    def test_expired_lease_reads_closed_without_a_new_file(self):
        hook = self.hook({"status_line": True})
        self.assertIn("Internet closed", self.call(hook, json.dumps({"internet": 999, "lan": None})))
        self.assertIn("Internet closed", self.call(hook, json.dumps({"internet": 1000, "lan": None})))

    def test_unknown_state_adds_nothing(self):
        hook = self.hook({"status_line": True})
        for content in (None, "", "not json", "[]", "{}", '{"internet": "soon", "lan": null}'):
            with self.subTest(content=content):
                self.assertIsNone(self.call(hook, content))


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
                self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
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
        ctx = Context()
        plugin.register(ctx)
        self.assertEqual(ctx.commands, [("firewall", plugin.handle)])
        self.assertEqual([name for name, _ in ctx.hooks], ["transform_terminal_output", "pre_llm_call"])
        self.assertFalse(hasattr(ctx, "tools"))

    def test_manifest_matches(self):
        manifest = (ROOT / "plugin" / "hermes-firewall" / "plugin.yaml").read_text()
        self.assertIn("name: hermes-firewall\n", manifest)
        firewall = (ROOT / "hermes_firewall.py").read_text()
        version = firewall.split('VERSION = "', 1)[1].split('"', 1)[0]
        self.assertIn(f"version: {version}\n", manifest)
        ctx = Context()
        plugin.register(ctx)
        for name, _ in ctx.hooks:
            self.assertIn(f"  - {name}\n", manifest)


if __name__ == "__main__":
    unittest.main()

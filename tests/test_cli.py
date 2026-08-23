import contextlib
import io
import json
import os
import tempfile
import unittest

from fenceline import cli


def run_cli(argv, root=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.run((["--root", root] if root else []) + argv)
    return code, out.getvalue(), err.getvalue()


def write_log(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(json.dumps(ln) + "\n")


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bad = os.path.join(self.tmp.name, "bad.jsonl")
        write_log(self.bad, [
            {"ts": 1700000000, "session": "s1", "tool": "bash",
             "detail": "sudo rm -rf /"},
            {"ts": 1700000060, "session": "s1", "tool": "write",
             "target": "/etc/hosts"},
        ])
        self.clean = os.path.join(self.tmp.name, "clean.jsonl")
        write_log(self.clean, [
            {"ts": 1700000000, "session": "s1", "tool": "bash",
             "detail": "ls -la"},
            {"ts": 1700000060, "session": "s1", "tool": "edit",
             "target": os.path.join(self.tmp.name, "ok.txt")},
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def test_exit_codes(self):
        code, _, _ = run_cli([self.clean], self.tmp.name)
        self.assertEqual(code, cli.EXIT_CLEAN)
        code, _, _ = run_cli([self.bad], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)
        code, _, err = run_cli([os.path.join(self.tmp.name, "missing.jsonl")])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("no readable sources", err)

    def test_human_report(self):
        code, out, _ = run_cli([self.bad], self.tmp.name)
        self.assertIn("VIOLATION", out)
        self.assertIn("forbidden-command", out)
        self.assertIn("outside-root", out)
        self.assertIn("total: 3 violation(s), 0 warning", out)

    def test_clean_message(self):
        code, out, _ = run_cli([self.clean], self.tmp.name)
        self.assertIn("clean:", out)

    def test_json_shape(self):
        code, out, _ = run_cli(["--json", self.bad], self.tmp.name)
        data = json.loads(out)
        self.assertEqual(data["events_scanned"], 2)
        self.assertEqual(len(data["violations"]), 3)
        v = data["violations"][0]
        for key in ("rule", "severity", "session", "ts", "time", "evidence"):
            self.assertIn(key, v)

    def test_statusline(self):
        code, out, _ = run_cli(["--statusline", self.bad], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)
        self.assertIn("events:2 violations:3+0w", out)
        code, out, _ = run_cli(["--statusline", self.clean], self.tmp.name)
        self.assertEqual(code, cli.EXIT_CLEAN)
        self.assertIn("violations:0+0w", out)

    def test_since_filter_excludes_old(self):
        code, out, _ = run_cli(
            ["--since", "1700000100", "--json", self.bad], self.tmp.name
        )
        data = json.loads(out)
        self.assertEqual(data["events_scanned"], 0)
        self.assertEqual(code, cli.EXIT_CLEAN)

    def test_allow_head_relents(self):
        only_sudo = os.path.join(self.tmp.name, "sudo.jsonl")
        write_log(only_sudo, [
            {"ts": 1700000000, "session": "s1", "tool": "bash",
             "detail": "docker ps"},
        ])
        code, _, _ = run_cli(["--allow-head", "docker", only_sudo], self.tmp.name)
        self.assertEqual(code, cli.EXIT_CLEAN)

    def test_remote_host_flags(self):
        log = os.path.join(self.tmp.name, "remote.jsonl")
        write_log(log, [
            {"ts": 1700000000, "session": "s1", "tool": "bash",
             "detail": "ssh storagebox ls /etc"},
            {"ts": 1700000060, "session": "s1", "tool": "bash",
             "detail": "rsync out/ storagebox:agent-backup/out/"},
        ])
        code, _, _ = run_cli([
            "--remote-host", "storagebox",
            "--remote-allow", "agent-backup",
            log,
        ], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)  # first line only

    def test_multiple_sources_merge(self):
        code, out, _ = run_cli([self.clean, self.bad], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)
        self.assertIn("audited 4 tool calls", out)


if __name__ == "__main__":
    unittest.main()

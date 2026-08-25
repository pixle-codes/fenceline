import contextlib
import io
import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

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


def epoch(days_ago: float, hour_offset: float = 0.0) -> int:
    dt = datetime.now(timezone.utc) - timedelta(
        days=days_ago, hours=-hour_offset
    )
    return int(dt.timestamp())


class TestKindFilter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bad = os.path.join(self.tmp.name, "bad.jsonl")
        write_log(self.bad, [
            {"ts": epoch(1), "session": "s1", "tool": "bash",
             "detail": "sudo rm -rf /"},
            {"ts": epoch(1), "session": "s1", "tool": "write",
             "target": "/opt/oxagent/MISSION.md"},
            {"ts": epoch(1), "session": "s2", "tool": "bash",
             "detail": "python3 -m http.server 8000"},
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def test_unknown_kind_exits_2_naming_roster(self):
        code, out, err = run_cli([self.bad, "--kind", "nope"],
                                 self.tmp.name)
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("unknown --kind", err)
        self.assertIn("outside-root", err)   # roster named in the hint
        self.assertEqual(out, "")            # nothing scanned/run

    def test_kind_narrows_findings_and_keeps_exit(self):
        code, out, _ = run_cli(
            [self.bad, "--kind", "destructive-pattern"], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)
        self.assertIn("destructive-pattern", out)
        self.assertNotIn("forbidden-command", out)
        self.assertNotIn("outside-root", out)
        self.assertNotIn("http.server", out)
        self.assertIn("total: 1 violation(s)", out)

    def test_kind_repeatable_union(self):
        code, out, _ = run_cli(
            [self.bad, "--kind", "outside-root",
             "--kind", "listen-server"], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)
        self.assertNotIn("forbidden-command", out)
        self.assertIn("outside-root", out)
        # listen-server is warn-severity -> counted under warnings
        self.assertIn("total: 1 violation(s), 1 warning(s)", out)

    def test_kind_clean_result_exits_0(self):
        code, out, _ = run_cli(
            [self.bad, "--kind", "remote-host"], self.tmp.name)
        self.assertEqual(code, cli.EXIT_CLEAN)
        self.assertIn("clean:", out)

    def test_kind_json_violations_filtered(self):
        _, out, _ = run_cli([self.bad, "--json",
                             "--kind", "outside-root"], self.tmp.name)
        data = json.loads(out)
        rules = {v["rule"] for v in data["violations"]}
        self.assertEqual(rules, {"outside-root"})
        self.assertNotIn("exempted", data)


class TestAllowPath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "mix.jsonl")
        write_log(self.log, [
            {"ts": epoch(1), "session": "s1", "tool": "read",
             "target": "/opt/oxagent/MISSION.md"},
            {"ts": epoch(1), "session": "s1", "tool": "bash",
             "detail": "cat /opt/oxagent/MISSION.md"},
            {"ts": epoch(1), "session": "s2", "tool": "write",
             "target": "/opt/other/file.txt"},
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def test_exempt_path_silences_gating_but_counts(self):
        code, out, _ = run_cli(
            [self.log, "--allow-path", "/opt/oxagent"], self.tmp.name)
        # the bare `cat /opt/...` bash call still flags -> exit 1
        self.assertEqual(code, cli.EXIT_VIOLATIONS)
        self.assertNotIn("/opt/oxagent/MISSION.md ->", out)  # exempt: gone
        self.assertIn("/opt/other/file.txt", out)            # still flagged
        self.assertIn("(1 exempt via --allow-path)", out)

    def test_exempt_only_path_finding_allows_exit_0(self):
        log = os.path.join(self.tmp.name, "onlypath.jsonl")
        write_log(log, [
            {"ts": epoch(1), "session": "s9", "tool": "read",
             "target": "/opt/oxagent/MISSION.md"},
        ])
        code, out, _ = run_cli(
            [log, "--allow-path", "/opt/oxagent"], self.tmp.name)
        self.assertEqual(code, cli.EXIT_CLEAN)
        self.assertIn("(1 exempt via --allow-path)", out)

    def test_exempt_never_covers_bash_commands(self):
        log = os.path.join(self.tmp.name, "cmdonly.jsonl")
        write_log(log, [
            {"ts": epoch(1), "session": "s9", "tool": "bash",
             "detail": "sudo cat /opt/oxagent/MISSION.md"},
        ])
        code, out, _ = run_cli(
            [log, "--allow-path", "/opt"], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)
        self.assertIn("forbidden-command", out)
        self.assertNotIn("exempt via", out)

    def test_component_boundary_required(self):
        log = os.path.join(self.tmp.name, "b.jsonl")
        write_log(log, [
            {"ts": epoch(1), "session": "s9", "tool": "read",
             "target": "/opt/oxagent/MISSION.md"},
        ])
        code, out, _ = run_cli(
            [log, "--allow-path", "/opt/ox"], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)  # /opt/ox != /opt/oxagent
        self.assertNotIn("exempt via", out)

    def test_statusline_and_json_report_exempts_last(self):
        _, out, _ = run_cli(
            [self.log, "--json", "--allow-path", "/opt/oxagent"],
            self.tmp.name)
        data = json.loads(out)
        self.assertEqual(data["exempted"], 1)
        self.assertEqual(list(data)[-1], "exempted")
        sl_out, sl_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(sl_out):
            code = cli.run([self.log, "--statusline",
                            "--allow-path", "/opt/oxagent"])
        self.assertIn("exempt:1", sl_out.getvalue())
        self.assertIn("violations:1+0w", sl_out.getvalue())


class TestSinceDays(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "ages.jsonl")
        write_log(self.log, [
            {"ts": epoch(30), "session": "old", "tool": "bash",
             "detail": "sudo apt install thing"},
            {"ts": epoch(1), "session": "new", "tool": "bash",
             "detail": "sudo systemctl stop x"},
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def test_recent_window_drops_old_findings(self):
        code, out, _ = run_cli(
            [self.log, "--since-days", "7"], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)
        self.assertIn("systemctl", out)
        self.assertNotIn("apt install", out)

    def test_zero_window_shows_nothing(self):
        code, out, _ = run_cli(
            [self.log, "--since-days", "90"], self.tmp.name)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)  # both inside window
        self.assertIn("total: 2 violation(s)", out)

    def test_negative_or_zero_rejected(self):
        for val in ("-1", "0"):
            code, _, err = run_cli([self.log, "--since-days", val],
                                   self.tmp.name)
            self.assertEqual(code, cli.EXIT_USAGE, val)
            self.assertIn("--since-days", err)

    def test_conflict_with_explicit_since_rejected(self):
        code, _, err = run_cli(
            [self.log, "--since-days", "7",
             "--since", "2026-08-01T00:00:00Z"], self.tmp.name)
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("--since", err)


if __name__ == "__main__":
    unittest.main()

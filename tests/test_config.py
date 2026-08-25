import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from fenceline import cli


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.run(argv)
    return code, out.getvalue(), err.getvalue()


def write_log(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(json.dumps(ln) + "\n")


def epoch(days_ago: float) -> int:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return int(dt.timestamp())


class ConfigBase(unittest.TestCase):
    """Scratch home + a session log with one exemptible scratch write."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.tmp.name, "home")
        os.makedirs(os.path.join(self.home, ".config", "fenceline"))
        self.log = os.path.join(self.tmp.name, "mix.jsonl")
        write_log(self.log, [
            {"ts": epoch(1), "session": "s1", "tool": "write",
             "target": "/tmp/opencode/scratch.py"},
            {"ts": epoch(1), "session": "s2", "tool": "write",
             "target": "/etc/hostile.conf"},
        ])
        patcher = mock.patch.dict(os.environ, {"HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def cfg_path(self):
        return os.path.join(self.home, ".config", "fenceline", "config.toml")

    def write_cfg(self, body):
        with open(self.cfg_path(), "w", encoding="utf-8") as f:
            f.write(body)


class TestDefaultResolution(ConfigBase):
    def test_default_absent_is_silent_noop(self):
        code, out, err = run_cli([self.log])
        self.assertEqual(code, cli.EXIT_VIOLATIONS)
        self.assertIn("/tmp/opencode/scratch.py", out)
        self.assertNotIn("exempt via", out)

    def test_valid_default_config_applies_bare(self):
        self.write_cfg('\
[audit]\nallow_paths = ["/tmp/opencode"]\n')
        code, out, _ = run_cli([self.log])
        self.assertEqual(code, cli.EXIT_VIOLATIONS)  # /etc hit remains
        self.assertNotIn("/tmp/opencode/scratch.py ->", out)
        self.assertIn("/etc/hostile.conf", out)
        self.assertIn("(1 exempt via --allow-path)", out)

    def test_config_only_exempt_allows_exit_0(self):
        log = os.path.join(self.tmp.name, "only.jsonl")
        write_log(log, [
            {"ts": epoch(1), "session": "s9", "tool": "read",
             "target": "/tmp/opencode/nextme.md"},
        ])
        self.write_cfg('\
[audit]\nallow_paths = ["/tmp/opencode"]\n')
        code, out, _ = run_cli([log])
        self.assertEqual(code, cli.EXIT_CLEAN)
        self.assertIn("(1 exempt via --allow-path)", out)


class TestExplicitFlag(ConfigBase):
    def test_explicit_config_used_verbatim(self):
        other = os.path.join(self.tmp.name, "other.toml")
        with open(other, "w", encoding="utf-8") as f:
            f.write('[audit]\nallow_paths = ["/etc"]\n')
        code, out, _ = run_cli([self.log, "--config", other])
        self.assertEqual(code, cli.EXIT_VIOLATIONS)  # /tmp/opencode remains
        self.assertIn("/tmp/opencode/scratch.py", out)
        self.assertNotIn("/etc/hostile.conf ->", out)
        self.assertIn("(1 exempt via --allow-path)", out)

    def test_missing_explicit_config_exits_2(self):
        ghost = os.path.join(self.tmp.name, "ghost.toml")
        code, out, err = run_cli([self.log, "--config", ghost])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertEqual(out, "")
        self.assertIn("ghost.toml", err)

    def test_flags_append_after_config_paths(self):
        self.write_cfg('\
[audit]\nallow_paths = ["/tmp/opencode"]\n')
        code, out, _ = run_cli(
            [self.log, "--allow-path", "/etc"])
        self.assertEqual(code, cli.EXIT_CLEAN)
        self.assertIn("(2 exempt via --allow-path)", out)

    def test_statusline_reports_config_exempt(self):
        self.write_cfg('\
[audit]\nallow_paths = ["/tmp/opencode"]\n')
        sl_out = io.StringIO()
        with contextlib.redirect_stdout(sl_out):
            code = cli.run([self.log, "--statusline"])
        line = sl_out.getvalue()
        self.assertIn("violations:1+0w", line)
        self.assertIn("exempt:1", line)
        self.assertEqual(code, cli.EXIT_VIOLATIONS)


class TestBadConfig(ConfigBase):
    def test_corrupt_toml_exits_2_naming_path(self):
        self.write_cfg("not [ valid toml ==")
        code, out, err = run_cli([self.log])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertEqual(out, "")
        self.assertIn("config.toml", err)

    def test_unknown_top_level_key_rejected(self):
        self.write_cfg('\
[audit]\nallow_paths = []\n\n[extra]\nx = 1\n')
        code, _, err = run_cli([self.log])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("extra", err)

    def test_unknown_audit_key_rejected(self):
        self.write_cfg('\
[audit]\nallow_path = ["/tmp/opencode"]\n')
        code, _, err = run_cli([self.log])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("allow_path", err)

    def test_allow_paths_wrong_type_rejected(self):
        self.write_cfg('\
[audit]\nallow_paths = "/tmp/opencode"\n')
        code, _, err = run_cli([self.log])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("allow_paths", err)

    def test_blank_entry_rejected(self):
        self.write_cfg('\
[audit]\nallow_paths = ["  "]\n')
        code, _, err = run_cli([self.log])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("non-empty", err)

    def test_bad_config_fails_before_scanning_sources(self):
        # usage-class errors must fire before any audit work: an unreadable
        # SOURCE would normally exit 2 too, but the CONFIG error must be the
        # reason named.
        self.write_cfg("not [ valid toml ==")
        code, _, err = run_cli(["/no/such/source.jsonl"])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("config.toml", err)
        self.assertNotIn("source", err)


class TestTildePaths(ConfigBase):
    def test_tilde_entry_expands_against_current_home(self):
        allowed = os.path.join(self.home, "sanctioned")
        os.makedirs(allowed)
        log = os.path.join(self.tmp.name, "t.jsonl")
        write_log(log, [
            {"ts": epoch(1), "session": "s1", "tool": "write",
             "target": os.path.join(allowed, "x.txt")},
        ])
        self.write_cfg('\
[audit]\nallow_paths = ["~/sanctioned"]\n')
        # narrow the allowed root so ~/sanctioned is OUTSIDE it and the
        # finding exists; only the expanded tilde prefix can exempt it
        code, out, _ = run_cli(
            [log, "--root", os.path.join(self.tmp.name, "elsewhere")])
        self.assertEqual(code, cli.EXIT_CLEAN)
        self.assertIn("(1 exempt via --allow-path)", out)


if __name__ == "__main__":
    unittest.main()

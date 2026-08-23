import json
import os
import sqlite3
import tempfile
import unittest

from fenceline.readers import (
    collect_events,
    looks_like_claude_code,
    looks_like_codex,
    looks_like_sqlite,
    parse_ts,
    read_claude,
    read_codex,
    read_db,
    read_events,
    read_jsonl,
    resolve_sources,
)


def write_jsonl(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(json.dumps(ln) + "\n")


def make_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE session (id TEXT PRIMARY KEY)")
    conn.execute(
        "CREATE TABLE part (session_id TEXT, time_created INTEGER, data TEXT)"
    )
    rows = [
        ("s1", 1700000000000, {"type": "tool", "tool": "bash",
                               "state": {"status": "completed",
                                         "input": {"command": "ls -la"}}}),
        ("s1", 1700000060000, {"type": "tool", "tool": "write",
                               "state": {"input": {"filePath": "/home/x/a.py"}}}),
        ("s1", 1700000120000, {"type": "text", "text": "prose"}),
        ("s2", 1700000200000, {"type": "tool", "tool": "bash",
                               "state": {"input": {"command": "sudo apt update"}}}),
        ("s2", 1700000200000, "not-a-dict"),
    ]
    for sid, ts, data in rows:
        payload = data if isinstance(data, str) else json.dumps(data)
        conn.execute("INSERT INTO part VALUES (?,?,?)", (sid, ts, payload))
    conn.commit()
    conn.close()


class TestParseTs(unittest.TestCase):
    def test_ms_epoch(self):
        self.assertEqual(parse_ts(1700000000000), 1700000000.0)

    def test_s_epoch(self):
        self.assertEqual(parse_ts(1700000000), 1700000000.0)

    def test_iso(self):
        self.assertEqual(parse_ts("2023-11-14T22:13:20Z"), 1700000000.0)

    def test_junk(self):
        self.assertIsNone(parse_ts("hello"))
        self.assertIsNone(parse_ts(None))


class TestJsonl(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "s.jsonl")
        write_jsonl(self.path, [
            {"ts": 1700000000000, "session": "s1", "tool": "bash",
             "detail": "rm -rf /"},
            {"time": "2023-11-14T22:13:30Z", "session_id": "s1",
             "tool": "edit", "target": "/etc/hosts"},
            {"ts": 1700000010, "role": "assistant", "tokens": {"input": 5}},
            {"ts": 1700000020, "session": "s2", "tool": "bash", "detail": "   "},
            "junk-line",
            {"ts": 1700000030, "session": "s2", "tool": "fetch",
             "target": "https://example.com"},
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def test_events_extracted(self):
        events, err = read_jsonl(self.path)
        self.assertIsNone(err)
        self.assertEqual(len(events), 3)
        bash = [e for e in events if e.tool == "bash"][0]
        self.assertEqual(bash.command, "rm -rf /")
        self.assertEqual(bash.sid, "s1")
        edit = [e for e in events if e.tool == "edit"][0]
        self.assertEqual(edit.target, "/etc/hosts")
        fetch = [e for e in events if e.tool == "fetch"][0]
        self.assertTrue(fetch.target.startswith("https://"))

    def test_sorted_by_ts(self):
        events, _ = read_jsonl(self.path)
        self.assertEqual([e.ts for e in events], sorted(e.ts for e in events))

    def test_missing_file_error(self):
        events, err = read_jsonl(os.path.join(self.tmp.name, "nope.jsonl"))
        self.assertEqual(events, [])
        self.assertIn("cannot open", err)

    def test_autodetect_false_for_jsonl(self):
        self.assertFalse(looks_like_sqlite(self.path))


class TestDb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "opencode.db")
        make_db(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_autodetect_true(self):
        self.assertTrue(looks_like_sqlite(self.path))

    def test_tool_parts_become_events(self):
        events, err = read_db(self.path)
        self.assertIsNone(err)
        self.assertEqual(len(events), 3)
        sudo = [e for e in events if "sudo" in e.command][0]
        self.assertEqual(sudo.sid, "s2")
        write_ev = [e for e in events if e.tool == "write"][0]
        self.assertEqual(write_ev.target, "/home/x/a.py")

    def test_bad_schema_reported(self):
        plain = os.path.join(self.tmp.name, "plain.db")
        conn = sqlite3.connect(plain)
        conn.execute("CREATE TABLE other (x INT)")
        conn.commit()
        conn.close()
        events, err = read_db(plain)
        self.assertEqual(events, [])
        self.assertIn("bad schema", err)

    def test_resolve_sources_default_missing(self):
        old = os.environ.get("HOME")
        try:
            os.environ["HOME"] = self.tmp.name
            paths, err = resolve_sources([])
            self.assertEqual(paths, [])
            self.assertIn("no default db", err)
            paths2, err2 = resolve_sources([self.path])
            self.assertEqual(paths2, [self.path])
            self.assertEqual(err2, "")
        finally:
            if old is not None:
                os.environ["HOME"] = old


class TestClaudeCode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "cc.jsonl")
        lines = [
            {"type": "summary", "summary": "s", "sessionId": "s1",
             "timestamp": "2026-08-01T00:00:00.000Z"},
            {"type": "user", "sessionId": "s1", "cwd": "/w",
             "timestamp": "2026-08-01T00:00:01.000Z",
             "message": {"role": "user", "content": "please fix"}},
            {"type": "assistant", "sessionId": "s1", "cwd": "/w",
             "timestamp": "2026-08-01T00:00:02.000Z",
             "message": {"role": "assistant", "content": [
                 {"type": "thinking", "thinking": "hmm"},
                 {"type": "text", "text": "running rm -rf / now"},
                 {"type": "tool_use", "id": "t1", "name": "Bash",
                  "input": {"command": "rm -rf /tmp/x"}},
                 {"type": "tool_use", "id": "t2", "name": "Edit",
                  "input": {"file_path": "/etc/passwd"}},
                 {"type": "tool_use", "id": "t3", "name": "WebFetch",
                  "input": {"url": "https://example.com"}},
             ]}},
        ]
        write_jsonl(self.path, lines)

    def tearDown(self):
        self.tmp.cleanup()

    def test_detection(self):
        self.assertTrue(looks_like_claude_code(self.path))
        generic = os.path.join(self.tmp.name, "g.jsonl")
        write_jsonl(generic, [{"ts": 1, "session": "a", "tool": "bash",
                               "detail": "ls"}])
        self.assertFalse(looks_like_claude_code(generic))
        self.assertFalse(looks_like_claude_code(os.path.join(self.tmp.name, "no")))

    def test_tool_calls_extracted_prose_ignored(self):
        events, err = read_events(self.path)
        self.assertIsNone(err)
        # bash + edit become events; WebFetch has no command/target keys we
        # treat as auditable file access... url IS captured as target.
        self.assertEqual(len(events), 3)
        bash = [e for e in events if e.tool == "bash"][0]
        self.assertEqual(bash.command, "rm -rf /tmp/x")
        edit = [e for e in events if e.tool == "edit"][0]
        self.assertEqual(edit.target, "/etc/passwd")
        fetch = [e for e in events if e.tool == "webfetch"][0]
        self.assertEqual(fetch.target, "https://example.com")
        # prose mentioning rm -rf / must NOT appear anywhere
        joined = " ".join(e.command for e in events)
        self.assertNotIn("rm -rf / ", joined)

    def test_directory_sweep(self):
        proj = tempfile.TemporaryDirectory()
        try:
            write_jsonl(os.path.join(proj.name, "s1.jsonl"), [
                {"type": "assistant", "sessionId": "sx",
                 "timestamp": "2026-08-01T00:00:02.000Z",
                 "message": {"role": "assistant", "content": [
                     {"type": "tool_use", "id": "t9", "name": "Bash",
                      "input": {"command": "sudo apt update"}}]}},
            ])
            events, errs = collect_events([proj.name])
            self.assertEqual(errs, [])
            self.assertEqual([e.command for e in events], ["sudo apt update"])
        finally:
            proj.cleanup()

    def test_snake_case_file_path_in_generic_reader(self):
        generic = os.path.join(self.tmp.name, "g2.jsonl")
        write_jsonl(generic, [{"ts": 5, "session": "a", "tool": "edit",
                               "target": "/w/x.py"}])
        events, err = read_jsonl(generic)
        self.assertIsNone(err)
        self.assertEqual(events[0].target, "/w/x.py")


class TestCodex(unittest.TestCase):
    T0 = "2026-08-20T10:00:00.000Z"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "rollout-1.jsonl")
        write_jsonl(self.path, [
            {"timestamp": self.T0, "type": "session_meta",
             "payload": {"id": "thr_abc", "cwd": "/home/x",
                         "originator": "codex_cli_rs",
                         "cli_version": "0.42.0"}},
            {"timestamp": self.T0, "type": "turn_context",
             "payload": {"cwd": "/home/x", "model": "gpt-5.2"}},
            # user PROSE asking for a destructive command: never an event
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "message", "role": "user",
                         "content": [{"type": "input_text",
                                      "text": "please run rm -rf /"}]}},
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "function_call", "name": "shell",
                         "arguments": "{\"command\":[\"sudo\",\"apt\","
                                      "\"update\"]}",
                         "call_id": "c1"}},
            {"timestamp": self.T0, "type": "event_msg",
             "payload": {"type": "token_count",
                         "info": {"total_token_usage": {
                             "input_tokens": 10}}}},
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "local_shell_call", "status": "completed",
                         "action": {"type": "exec",
                                    "command": ["bash", "-lc", "ls -la"]},
                         "call_id": "c2"}},
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "function_call_output", "call_id": "c1",
                         "output": "ok"}},
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "function_call", "name": "view_image",
                         "arguments": "{\"path\":\"/etc/hosts\"}",
                         "call_id": "c3"}},
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "custom_tool_call", "name": "apply_patch",
                         "input": "*** Begin Patch", "call_id": "c9"}},
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def test_detection(self):
        self.assertTrue(looks_like_codex(self.path))
        generic = os.path.join(self.tmp.name, "g.jsonl")
        write_jsonl(generic, [{"ts": 1, "session": "a", "tool": "bash",
                               "detail": "ls"}])
        self.assertFalse(looks_like_codex(generic))
        self.assertFalse(looks_like_codex(os.path.join(self.tmp.name, "no")))

    def test_tool_calls_extracted_prose_ignored(self):
        events, err = read_codex(self.path)
        self.assertIsNone(err)
        self.assertEqual(len(events), 3)
        shell = [e for e in events if e.tool == "bash"][0]
        self.assertEqual(shell.command, "sudo apt update")
        self.assertEqual(shell.sid, "thr_abc")
        lsc = [e for e in events if e.command == "bash -lc ls -la"]
        self.assertEqual(len(lsc), 1)
        img = [e for e in events if e.target == "/etc/hosts"][0]
        self.assertEqual(img.tool, "view_image")
        joined = " ".join(e.command for e in events)
        self.assertNotIn("rm -rf /", joined)

    def test_read_events_dispatch(self):
        events, err = read_events(self.path)
        self.assertIsNone(err)
        self.assertEqual(len(events), 3)

    def test_fallback_sid_without_meta(self):
        p2 = os.path.join(self.tmp.name, "rollout-nometa.jsonl")
        write_jsonl(p2, [
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "function_call", "name": "shell",
                         "arguments": "{\"command\":[\"ls\"]}",
                         "call_id": "c1"}},
        ])
        events, _ = read_codex(p2)
        self.assertEqual(events[0].sid, "codex")

    def test_legacy_session_id_key(self):
        p2 = os.path.join(self.tmp.name, "rollout-legacy.jsonl")
        write_jsonl(p2, [
            {"timestamp": self.T0, "type": "session_meta",
             "payload": {"session_id": "legacy-1"}},
        ])
        events, _ = read_codex(p2)
        self.assertEqual(events, [])
        p3 = os.path.join(self.tmp.name, "rollout-legacy2.jsonl")
        write_jsonl(p3, [
            {"timestamp": self.T0, "type": "session_meta",
             "payload": {"session_id": "legacy-1"}},
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "function_call", "name": "shell",
                         "arguments": "{\"command\":[\"ls\"]}",
                         "call_id": "c1"}},
        ])
        events, _ = read_codex(p3)
        self.assertEqual(events[0].sid, "legacy-1")

    def test_truncated_arguments_still_audited(self):
        p2 = os.path.join(self.tmp.name, "rollout-trunc.jsonl")
        write_jsonl(p2, [
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "function_call", "name": "shell",
                         "arguments": "{\"command\":[\"rm -rf /",  # truncated
                         "call_id": "c1"}},
        ])
        events, err = read_codex(p2)
        self.assertIsNone(err)
        self.assertEqual(len(events), 1)
        self.assertIn("rm -rf /", events[0].command)

    def test_non_shell_command_args_audited_as_bash(self):
        p2 = os.path.join(self.tmp.name, "rollout-exec.jsonl")
        write_jsonl(p2, [
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "function_call", "name": "container.exec",
                         "arguments": "{\"command\":[\"docker\",\"ps\"]}",
                         "call_id": "c1"}},
        ])
        events, _ = read_codex(p2)
        self.assertEqual(events[0].tool, "bash")
        self.assertEqual(events[0].command, "docker ps")

    def test_iso_timestamps_parsed(self):
        from datetime import datetime, timezone

        expect = datetime(2026, 8, 20, 10, 0,
                          tzinfo=timezone.utc).timestamp()
        events, _ = read_codex(self.path)
        for e in events:
            self.assertEqual(e.ts, expect)

    def test_directory_sweep_nested_layout(self):
        base = os.path.join(self.tmp.name, "sessions", "2026", "08", "20")
        os.makedirs(base)
        write_jsonl(os.path.join(base, "rollout-x.jsonl"), [
            {"timestamp": self.T0, "type": "session_meta",
             "payload": {"id": "thr_sweep"}},
            {"timestamp": self.T0, "type": "response_item",
             "payload": {"type": "function_call", "name": "shell",
                         "arguments": "{\"command\":[\"sudo\",\"ls\"]}",
                         "call_id": "c1"}},
        ])
        events, errs = collect_events(
            [os.path.join(self.tmp.name, "sessions")]
        )
        self.assertEqual(errs, [])
        self.assertEqual([e.command for e in events], ["sudo ls"])
        self.assertEqual(events[0].sid, "thr_sweep")


if __name__ == "__main__":
    unittest.main()

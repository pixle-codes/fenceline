import json
import os
import sqlite3
import tempfile
import unittest

from fenceline.readers import (
    looks_like_sqlite,
    parse_ts,
    read_db,
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


if __name__ == "__main__":
    unittest.main()

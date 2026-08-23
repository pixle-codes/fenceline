"""Session-log readers: opencode sqlite store + generic JSONL.

Both yield Event records for TOOL CALLS ONLY. Assistant prose is never an
event, so discussing a forbidden command can never become a finding.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone

from .model import Event

SQLITE_MAGIC = b"SQLite format 3\x00"

DEFAULT_DB = "~/.local/share/opencode/opencode.db"


def looks_like_sqlite(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def parse_ts(value) -> float | None:
    """Accept ms/s epoch ints/floats/strings or ISO strings -> epoch sec."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e12 else v
    if isinstance(value, str):
        try:
            v = float(value)
            return v / 1000.0 if v > 1e12 else v
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            return None
    return None


def read_events(path: str) -> tuple[list[Event], str | None]:
    """Read one source; returns (events, error). Autodetects format."""
    if looks_like_sqlite(path):
        return read_db(path)
    return read_jsonl(path)


def _mk_event(ts: float, sid: str, tool: str, inp: dict) -> Event | None:
    if not isinstance(inp, dict):
        inp = {}
    command = ""
    target = ""
    if tool == "bash":
        command = str(inp.get("command") or "")
        if not command.strip():
            return None
    else:
        for key in ("filePath", "path", "file"):
            if inp.get(key):
                target = str(inp[key])
                break
        if not target and inp.get("url"):
            target = str(inp["url"])
        if not target and not command:
            return None
    return Event(ts=ts, sid=sid, tool=tool, target=target, command=command)


def read_jsonl(path: str) -> tuple[list[Event], str | None]:
    """Line schema: {"ts": ..., "session": ..., "tool": "bash",
    "target": "...", "detail": "..."} (aliases time/timestamp,
    session_id). Non-tool lines are skipped."""
    out: list[Event] = []
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], f"cannot open {path}: {exc}"
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(d, dict) or not d.get("tool"):
                continue
            ts = 0.0
            for k in ("ts", "time", "timestamp"):
                if k in d:
                    parsed = parse_ts(d[k])
                    if parsed is not None:
                        ts = parsed
                        break
            sid = str(d.get("session") or d.get("session_id") or "log")
            tool = str(d["tool"])
            if tool == "bash":
                cmd = str(d.get("detail") or d.get("command") or "")
                if not cmd.strip():
                    continue
                out.append(Event(ts=ts, sid=sid, tool=tool, target="", command=cmd))
            else:
                target = str(d.get("target") or "")
                if not target:
                    continue
                out.append(Event(ts=ts, sid=sid, tool=tool, target=target, command=""))
    return out, None


_SESSION_SQL = (
    "SELECT id FROM session"
)
_PART_SQL = "SELECT session_id, time_created, data FROM part"


def read_db(path: str) -> tuple[list[Event], str | None]:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        return [], f"cannot open {path}: {exc}"
    events: list[Event] = []
    err = None
    try:
        try:
            conn.execute(_SESSION_SQL).fetchone()
        except sqlite3.Error as exc:
            return [], f"bad schema in {path}: {exc}"
        # Filter in Python: a WHERE-clause json_extract() raises
        # "malformed JSON" during iteration when any row holds junk.
        try:
            cursor = conn.execute(_PART_SQL)
        except sqlite3.Error:
            return [], f"read error in {path}: part table unreadable"
        for row in cursor:
            try:
                d = json.loads(row["data"])
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(d, dict) or d.get("type") != "tool":
                continue
            state = d.get("state") or {}
            inp = state.get("input")
            ts = (row["time_created"] or 0) / 1000.0
            ev = _mk_event(ts, str(row["session_id"]), str(d.get("tool") or ""), inp)
            if ev is not None:
                events.append(ev)
    except sqlite3.Error as exc:
        err = f"read error in {path}: {exc}"
    finally:
        conn.close()
    return events, err


def resolve_sources(paths: list[str]) -> tuple[list[str], str]:
    """Resolve positional args; empty list -> default db if present."""
    import os

    if paths:
        return list(paths), ""
    default = os.path.expanduser(DEFAULT_DB)
    if os.path.exists(default):
        return [default], ""
    return [], f"no sources given and no default db at {default}"


def collect_events(paths: list[str]) -> tuple[list[Event], list[str]]:
    """Read all sources; sort by ts; return (events, errors)."""
    events: list[Event] = []
    errors: list[str] = []
    for p in paths:
        evs, err = read_events(p)
        if err:
            errors.append(err)
            print(f"fenceline: {err}", file=sys.stderr)
        events.extend(evs)
    events.sort(key=lambda e: e.ts)
    return events, errors

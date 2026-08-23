"""Session-log readers: opencode sqlite store, Claude Code transcripts,
OpenAI Codex CLI rollouts, and generic JSONL.

All yield Event records for TOOL CALLS ONLY. Assistant prose is never an
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
    if looks_like_claude_code(path):
        return read_claude(path)
    if looks_like_codex(path):
        return read_codex(path)
    return read_jsonl(path)


def looks_like_claude_code(path: str) -> bool:
    """Claude Code transcripts: ~/.claude/projects/**/*.jsonl lines carry
    sessionId + a type discriminator (user/assistant/summary/...)."""
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return False
    with fh:
        for n, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            if n > 10:
                break
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                isinstance(d, dict)
                and isinstance(d.get("sessionId"), str)
                and (d.get("type") in ("user", "assistant", "summary")
                     or isinstance(d.get("message"), dict))
            ):
                return True
    return False


def read_claude(path: str) -> tuple[list[Event], str | None]:
    """Claude Code JSONL: assistant message.content[] tool_use blocks are the
    tool calls; prose/thinking blocks are ignored by construction."""
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
            if not isinstance(d, dict) or d.get("type") != "assistant":
                continue
            ts = parse_ts(d.get("timestamp")) or 0.0
            sid = d.get("sessionId") or "claude"
            msg = d.get("message")
            content = msg.get("content") if isinstance(msg, dict) else None
            if not isinstance(content, list):
                continue
            for b in content:
                if not (isinstance(b, dict) and b.get("type") == "tool_use"):
                    continue
                tool = str(b.get("name") or "").lower()
                inp = b.get("input")
                ev = _mk_event(ts, str(sid), tool, inp if isinstance(inp, dict) else {})
                if ev is not None:
                    out.append(ev)
    return out, None


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
        for key in ("filePath", "file_path", "notebook_path", "path", "file"):
            if inp.get(key):
                target = str(inp[key])
                break
        if not target and inp.get("url"):
            target = str(inp["url"])
        if not target and not command:
            return None
    return Event(ts=ts, sid=sid, tool=tool, target=target, command=command)


_CODEX_LINE_TYPES = (
    "session_meta",
    "response_item",
    "inter_agent_communication",
    "inter_agent_communication_metadata",
    "compacted",
    "turn_context",
    "world_state",
    "security_risk_score",
    "event_msg",
)

_SHELL_TOOLS = ("shell", "local_shell")


def looks_like_codex(path: str) -> bool:
    """Codex CLI rollouts (~/.codex/sessions/**/*.jsonl): lines carry a
    type discriminator + payload envelope."""
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return False
    with fh:
        for n, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            if n > 10:
                break
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                isinstance(d, dict)
                and d.get("type") in _CODEX_LINE_TYPES
                and isinstance(d.get("payload"), dict)
            ):
                return True
    return False


def _codex_args(arguments) -> dict | None:
    """Parse a function_call arguments JSON string -> dict, else None."""
    if not isinstance(arguments, str) or not arguments.strip():
        return None
    try:
        v = json.loads(arguments)
    except json.JSONDecodeError:
        return None
    return v if isinstance(v, dict) else None


def _codex_command(argsd: dict) -> str:
    cmd = argsd.get("command")
    if isinstance(cmd, list) and cmd:
        return " ".join(str(c) for c in cmd)
    if isinstance(cmd, str):
        return cmd
    return ""


def read_codex(path: str) -> tuple[list[Event], str | None]:
    """OpenAI Codex CLI rollout JSONL (envelope verified against the codex
    source tree, 2026-08): {"timestamp", "type", "payload"} per line.

    session_meta supplies the session id; response_item payloads of type
    function_call / local_shell_call / custom_tool_call are tool calls.
    Any call carrying an executable command is audited as bash; other calls
    fall back to target extraction (path/file_path/file/url). Prose,
    reasoning, turn_context and event_msg lines are never events.
    """
    out: list[Event] = []
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], f"cannot open {path}: {exc}"
    with fh:
        sid = "codex"
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(d, dict):
                continue
            typ = d.get("type")
            p = d.get("payload")
            if typ == "session_meta" and isinstance(p, dict):
                sid = str(p.get("id") or p.get("session_id") or "codex")
                continue
            if typ != "response_item" or not isinstance(p, dict):
                continue
            kind = p.get("type")
            ts = parse_ts(d.get("timestamp"))
            if ts is None:
                ts = parse_ts(p.get("timestamp"))
            ts = ts or 0.0

            if kind == "function_call":
                name = str(p.get("name") or "").lower()
                argsd = _codex_args(p.get("arguments"))
                if argsd is not None:
                    cmd = _codex_command(argsd)
                    ev = (
                        _mk_event(ts, sid, "bash", {"command": cmd})
                        if cmd.strip()
                        else _mk_event(ts, sid, name, argsd)
                    )
                elif name in _SHELL_TOOLS:
                    # truncated/unparseable envelope: audit the raw text
                    raw = p.get("arguments")
                    ev = _mk_event(
                        ts, sid, "bash",
                        {"command": raw if isinstance(raw, str) else ""},
                    )
                else:
                    ev = None
            elif kind == "local_shell_call":
                action = p.get("action") or {}
                cmd = action.get("command") if isinstance(action, dict) else None
                detail = ""
                if isinstance(cmd, list):
                    detail = " ".join(str(c) for c in cmd)
                elif isinstance(cmd, str):
                    detail = cmd
                ev = _mk_event(ts, sid, "bash", {"command": detail})
            elif kind == "custom_tool_call":
                name = str(p.get("name") or "").lower()
                inp = p.get("input")
                # string inputs (apply_patch bodies) are prose-like diff
                # text, not structured targets — conservative skip.
                ev = _mk_event(ts, sid, name, inp) if isinstance(inp, dict) else None
            else:
                ev = None
            if ev is not None:
                out.append(ev)
    return out, None


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
    import os

    events: list[Event] = []
    errors: list[str] = []
    expanded: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                expanded.extend(
                    os.path.join(root, f) for f in sorted(files) if f.endswith(".jsonl")
                )
        else:
            expanded.append(p)
    for p in expanded:
        evs, err = read_events(p)
        if err:
            errors.append(err)
            print(f"fenceline: {err}", file=sys.stderr)
        events.extend(evs)
    events.sort(key=lambda e: e.ts)
    return events, errors

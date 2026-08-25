"""CLI: fenceline [sources...] -- audit agent session logs against policy."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from .model import VERSION
from .readers import collect_events, parse_ts, resolve_sources
from .rules import audit, default_policy

EXIT_CLEAN = 0
EXIT_VIOLATIONS = 1
EXIT_USAGE = 2


class ConfigError(Exception):
    """Policy config unreadable or invalid; message names the file."""


def _default_config_path() -> str:
    return str(Path.home() / ".config" / "fenceline" / "config.toml")


def load_config(path: str | None = None) -> list[str]:
    """Return allow_paths from a policy TOML.

    Default path absent = silent no-op ([]); an explicit --config that is
    missing, unreadable, or invalid raises ConfigError. Validation rejects
    unknown keys so a typo can never silently narrow the audit.
    """
    target = Path(path).expanduser() if path else Path(_default_config_path())
    if not target.is_file():
        if path:
            raise ConfigError(f"config not found: {target}")
        return []
    try:
        raw = tomllib.loads(target.read_text(encoding="utf-8"))
    except OSError as e:
        raise ConfigError(f"cannot read {target}: {e}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{target}: not valid TOML: {e}") from e
    unknown = sorted(set(raw) - {"audit"})
    if unknown:
        raise ConfigError(
            f"{target}: unknown key(s) {', '.join(unknown)} (valid: audit)")
    tbl = raw.get("audit", {})
    if not isinstance(tbl, dict):
        raise ConfigError(f"{target}: [audit] must be a table")
    unknown_tbl = sorted(set(tbl) - {"allow_paths"})
    if unknown_tbl:
        raise ConfigError(f"{target}: unknown [audit] key(s) "
                          f"{', '.join(unknown_tbl)} (valid: allow_paths)")
    paths = tbl.get("allow_paths", [])
    if not isinstance(paths, list) or not all(isinstance(p, str)
                                              for p in paths):
        raise ConfigError(f"{target}: allow_paths must be a list of strings")
    if any(not p.strip() for p in paths):
        raise ConfigError(f"{target}: allow_paths entries must be non-empty")
    return paths

RULE_ROSTER = (
    "forbidden-command",
    "destructive-pattern",
    "outside-root",
    "remote-host",
    "listen-server",
)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="fenceline",
        description="Audit coding-agent session logs for boundary violations.",
    )
    ap.add_argument("sources", nargs="*", help="sqlite db or JSONL log files")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--statusline", action="store_true", help="one-line summary")
    ap.add_argument("--root", action="append", default=[], dest="roots",
                    help="allowed path root (repeatable; default: $HOME)")
    ap.add_argument("--remote-host", default="", help="restricted host alias to watch")
    ap.add_argument("--remote-allow", default="",
                    help="token that must co-occur with --remote-host")
    ap.add_argument("--allow-head", action="append", default=[],
                    dest="allow_heads", help="remove a command from the forbidden set")
    ap.add_argument("--kind", action="append", default=[], dest="kinds",
                    metavar="RULE",
                    help="only report this rule (repeatable; one of: "
                         + ", ".join(RULE_ROSTER) + ")")
    ap.add_argument("--allow-path", action="append", default=[],
                    dest="allow_paths", metavar="PREFIX",
                    help="exempt file targets under this path prefix "
                         "(repeatable); never applies to bash commands; "
                         "paths from the policy config come first")
    ap.add_argument("--config", default=None, metavar="FILE",
                    help="policy config TOML (default: "
                         "~/.config/fenceline/config.toml when present)")
    ap.add_argument("--since-days", type=float, default=None, metavar="N",
                    help="audit only events from the last N days")
    ap.add_argument("--since", default="", help="epoch or ISO timestamp filter")
    ap.add_argument("--until", default="", help="epoch or ISO timestamp filter")
    ap.add_argument("--version", action="version", version=f"fenceline {VERSION}")
    return ap


def _window(args) -> tuple[float, float]:
    lo = parse_ts(args.since) if args.since else None
    hi = parse_ts(args.until) if args.until else None
    return (lo if lo is not None else float("-inf"),
            hi if hi is not None else float("inf"))


def _evidence_path(f) -> str:
    """Resolved path side of a file-target finding ('x -> /real/path')."""
    if " -> " not in f.evidence:
        return ""
    return f.evidence.rsplit(" -> ", 1)[1].strip()


def _under(candidate: str, prefix: str) -> bool:
    cand = os.path.normpath(candidate)
    pre = os.path.normpath(prefix)
    return cand == pre or cand.startswith(pre.rstrip(os.sep) + os.sep)


def run(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    kinds = set(args.kinds)
    unknown = sorted(kinds - set(RULE_ROSTER))
    if unknown:
        print(f"fenceline: unknown --kind {unknown[0]!r} (valid: "
              f"{', '.join(RULE_ROSTER)})", file=sys.stderr)
        return EXIT_USAGE
    if args.since_days is not None:
        if args.since:
            print("fenceline: --since-days and --since are mutually "
                  "exclusive", file=sys.stderr)
            return EXIT_USAGE
        if args.since_days <= 0:
            print("fenceline: --since-days must be a positive number "
                  "of days", file=sys.stderr)
            return EXIT_USAGE
        args.since = ""   # window composed below from the relative cutoff
    try:
        cfg_allow = load_config(args.config)
    except ConfigError as e:
        print(f"fenceline: {e}", file=sys.stderr)
        return EXIT_USAGE
    paths, err = resolve_sources(args.sources)
    if err:
        print(f"fenceline: {err}", file=sys.stderr)
        return EXIT_USAGE
    pol = default_policy()
    if args.roots:
        pol.allowed_roots = [os.path.expanduser(r) for r in args.roots]
    pol.forbidden_heads -= set(args.allow_heads)
    pol.remote_host = args.remote_host
    pol.remote_allow = args.remote_allow
    events, errors = collect_events(paths)
    if errors and not events:
        print("fenceline: no readable sources", file=sys.stderr)
        return EXIT_USAGE
    lo, hi = _window(args)
    if args.since_days is not None:
        lo = time.time() - args.since_days * 86400
    events = [e for e in events if (e.ts == 0.0 or lo <= e.ts <= hi)]
    findings = audit(events, pol)
    prefixes = []
    for p in cfg_allow + args.allow_paths:
        if not p.strip():
            continue
        np_ = os.path.normpath(os.path.expanduser(p))
        if np_ not in prefixes:
            prefixes.append(np_)
    kept = []
    exempted = 0
    for f in findings:
        tgt = _evidence_path(f)
        if tgt and any(_under(tgt, p) for p in prefixes):
            exempted += 1
        else:
            kept.append(f)
    if kinds:
        kept = [f for f in kept if f.rule in kinds]
    findings = kept

    if args.statusline:
        errs = sum(1 for f in findings if f.severity == "error")
        warns = len(findings) - errs
        line = f"events:{len(events)} violations:{errs}+{warns}w"
        if exempted:
            line += f" exempt:{exempted}"
        print(line)
        return EXIT_VIOLATIONS if findings else EXIT_CLEAN

    if args.json:
        payload = {
            "sources": paths,
            "events_scanned": len(events),
            "violations": [
                {
                    "rule": f.rule,
                    "severity": f.severity,
                    "session": f.sid,
                    "ts": f.ts,
                    "time": f.iso,
                    "evidence": f.evidence,
                }
                for f in findings
            ],
        }
        if exempted:
            payload["exempted"] = exempted
        print(json.dumps(payload, indent=2))
    else:
        _report_human(paths, events, findings, exempted)
    return EXIT_VIOLATIONS if findings else EXIT_CLEAN


def _report_human(paths: list[str], events, findings,
                  exempted: int = 0) -> None:
    errs = [f for f in findings if f.severity == "error"]
    warns = [f for f in findings if f.severity != "error"]
    print(f"fenceline: audited {len(events)} tool calls "
          f"across {len({e.sid for e in events})} sessions")
    if not findings:
        print("clean: no boundary violations found.")
        if exempted:
            print(f"({exempted} exempt via --allow-path)")
        return
    for label, group in (("VIOLATION", errs), ("warning", warns)):
        for f in group:
            print(f"\n[{label}] {f.rule}  ({f.iso}, session {f.sid[:12]})")
            print(f"  {f.evidence}")
    total = f"\ntotal: {len(errs)} violation(s), {len(warns)} warning(s)"
    if exempted:
        total += f" ({exempted} exempt via --allow-path)"
    print(total)


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()

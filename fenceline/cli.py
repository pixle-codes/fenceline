"""CLI: fenceline [sources...] -- audit agent session logs against policy."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from .model import VERSION
from .readers import collect_events, parse_ts, resolve_sources
from .rules import audit, default_policy

EXIT_CLEAN = 0
EXIT_VIOLATIONS = 1
EXIT_USAGE = 2


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
    ap.add_argument("--since", default="", help="epoch or ISO timestamp filter")
    ap.add_argument("--until", default="", help="epoch or ISO timestamp filter")
    ap.add_argument("--version", action="version", version=f"fenceline {VERSION}")
    return ap


def _window(args) -> tuple[float, float]:
    lo = parse_ts(args.since) if args.since else None
    hi = parse_ts(args.until) if args.until else None
    return (lo if lo is not None else float("-inf"),
            hi if hi is not None else float("inf"))


def run(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
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
    events = [e for e in events if (e.ts == 0.0 or lo <= e.ts <= hi)]
    findings = audit(events, pol)

    if args.statusline:
        errs = sum(1 for f in findings if f.severity == "error")
        warns = len(findings) - errs
        print(f"events:{len(events)} violations:{errs}+{warns}w")
        return EXIT_VIOLATIONS if findings else EXIT_CLEAN

    if args.json:
        print(
            json.dumps(
                {
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
                },
                indent=2,
            )
        )
    else:
        _report_human(paths, events, findings)
    return EXIT_VIOLATIONS if findings else EXIT_CLEAN


def _report_human(paths: list[str], events, findings) -> None:
    errs = [f for f in findings if f.severity == "error"]
    warns = [f for f in findings if f.severity != "error"]
    print(f"fenceline: audited {len(events)} tool calls "
          f"across {len({e.sid for e in events})} sessions")
    if not findings:
        print("clean: no boundary violations found.")
        return
    for label, group in (("VIOLATION", errs), ("warning", warns)):
        for f in group:
            print(f"\n[{label}] {f.rule}  ({f.iso}, session {f.sid[:12]})")
            print(f"  {f.evidence}")
    print(f"\ntotal: {len(errs)} violation(s), {len(warns)} warning(s)")


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()

"""CLI: fenceline [sources...] -- audit agent session logs against policy."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

from .model import VERSION
from .readers import collect_events, parse_ts, resolve_sources
from .rules import audit, default_policy

EXIT_CLEAN = 0
EXIT_VIOLATIONS = 1
EXIT_USAGE = 2

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
                         "(repeatable); never applies to bash commands")
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
    prefixes = [os.path.normpath(os.path.expanduser(p))
                for p in args.allow_paths]
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

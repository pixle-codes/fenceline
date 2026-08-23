"""Policy defaults + detectors. Each detector yields Findings."""

from __future__ import annotations

import os
import re

from .model import Event, Finding, Policy

DEFAULT_FORBIDDEN_HEADS = (
    "sudo", "su", "doas",
    "apt", "apt-get", "dpkg",
    "systemctl", "service",
    "docker", "podman",
    "useradd", "adduser", "userdel", "usermod",
    "shutdown", "reboot", "halt", "poweroff",
)

# Anchored so "rm -rf /tmp/x" and "rm -rf /home/me" never match; only the
# filesystem root itself is destructive.
_DEFAULT_PATTERNS = (
    r"\bmkfs\b",
    r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+){1,2}/(?:\s|$)",
    r"\bchmod\s+-R\s+777\s+/(?:\s|$)",
    r"\bdd\s+[^;|&]*\bof=/dev/(?:sd|nvme|hd)",
)

DEFAULT_LISTEN_PATTERNS = (
    r"\bpython3?\s+-m\s+http\.server\b",
    r"\bnc\b[^|;&]*\s-l\b",
    r"\buvicorn\b",
    r"\bflask\s+run\b",
    r"\bgunicorn\b",
    r"\bnpx\s+serve\b",
    r"\bnpm\s+(run\s+)?dev\b",
)


def default_policy() -> Policy:
    import copy

    return Policy(
        allowed_roots=[os.path.expanduser("~")],
        forbidden_heads=set(DEFAULT_FORBIDDEN_HEADS),
        forbidden_patterns=[
            ("destructive-pattern", re.compile(p)) for p in _DEFAULT_PATTERNS
        ],
        listen_patterns=[re.compile(p) for p in DEFAULT_LISTEN_PATTERNS],
    )


def _head(command: str) -> str:
    parts = command.strip().split()
    if not parts:
        return ""
    return os.path.basename(parts[0])


def check_forbidden_head(ev: Event, pol: Policy) -> Finding | None:
    if ev.tool != "bash":
        return None
    if _head(ev.command) in pol.forbidden_heads:
        return Finding(
            rule="forbidden-command",
            severity="error",
            sid=ev.sid,
            ts=ev.ts,
            evidence=ev.command[:200],
        )
    return None


def check_patterns(ev: Event, pol: Policy) -> list[Finding]:
    if ev.tool != "bash":
        return []
    out = []
    for name, pat in pol.forbidden_patterns:
        m = pat.search(ev.command)
        if m:
            out.append(
                Finding(
                    rule=name,
                    severity="error",
                    sid=ev.sid,
                    ts=ev.ts,
                    evidence=ev.command[:200],
                )
            )
    return out


def _inside(real: str, root: str) -> bool:
    try:
        return os.path.commonpath([real, root]) == root
    except ValueError:
        return False


def check_outside_root(ev: Event, pol: Policy) -> Finding | None:
    if ev.tool == "bash" or not ev.target:
        return None
    if ev.target.startswith(("http://", "https://")):
        return None
    real = os.path.realpath(os.path.expanduser(ev.target))
    for root in pol.allowed_roots:
        rroot = os.path.realpath(root)
        if _inside(real, rroot):
            return None
    return Finding(
        rule="outside-root",
        severity="error",
        sid=ev.sid,
        ts=ev.ts,
        evidence=f"{ev.tool} {ev.target} -> {real}",
    )


def check_remote_host(ev: Event, pol: Policy) -> Finding | None:
    if not pol.allows_remote() or ev.tool != "bash":
        return None
    host = pol.remote_host
    if not re.search(rf"\b{re.escape(host)}\b", ev.command):
        return None
    if pol.remote_allow and pol.remote_allow in ev.command:
        return None
    return Finding(
        rule="remote-host",
        severity="error",
        sid=ev.sid,
        ts=ev.ts,
        evidence=ev.command[:200],
    )


def check_listen(ev: Event, pol: Policy) -> Finding | None:
    if ev.tool != "bash":
        return None
    for pat in pol.listen_patterns:
        if pat.search(ev.command):
            return Finding(
                rule="listen-server",
                severity="warn",
                sid=ev.sid,
                ts=ev.ts,
                evidence=ev.command[:200],
            )
    return None


def audit(events: list[Event], pol: Policy) -> list[Finding]:
    """Run every detector over every event; findings sorted by (ts, rule)."""
    out: list[Finding] = []
    for ev in events:
        f = check_forbidden_head(ev, pol)
        if f:
            out.append(f)
        out.extend(check_patterns(ev, pol))
        f = check_outside_root(ev, pol)
        if f:
            out.append(f)
        f = check_remote_host(ev, pol)
        if f:
            out.append(f)
        f = check_listen(ev, pol)
        if f:
            out.append(f)
    out.sort(key=lambda f: (f.ts, f.rule, f.evidence))
    return out

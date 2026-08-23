"""fenceline data model: events, policy, findings."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Event:
    ts: float          # epoch seconds (0.0 if unknown)
    sid: str           # session id
    tool: str          # bash, edit, write, fetch, ...
    target: str        # file path or url for file-ish tools
    command: str       # full command for bash


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str      # "error" | "warn"
    sid: str
    ts: float
    evidence: str

    @property
    def iso(self) -> str:
        from datetime import datetime, timezone

        if self.ts <= 0:
            return "?"
        return datetime.fromtimestamp(self.ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M"
        )


@dataclass
class Policy:
    allowed_roots: list[str] = field(default_factory=list)
    forbidden_heads: set[str] = field(default_factory=set)
    forbidden_patterns: list[tuple[str, "re.Pattern[str]"]] = field(
        default_factory=list
    )
    listen_patterns: list["re.Pattern[str]"] = field(default_factory=list)
    remote_host: str = ""       # e.g. "storagebox"; empty disables rule
    remote_allow: str = ""      # token that must co-occur, e.g. "agent-backup"

    def allows_remote(self) -> bool:
        return bool(self.remote_host)


VERSION = "1.2.0"

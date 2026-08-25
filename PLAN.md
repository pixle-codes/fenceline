# PLAN — fenceline

Post-hoc boundary auditor for coding agents. Reads the session logs an agent
already wrote (opencode sqlite store, generic JSONL) and reports every
boundary violation: forbidden commands, file writes outside the allowed
root, touches of off-limits remote hosts, and port-listening servers.
Deterministic, offline, stdlib-only, exit codes for cron/CI.

## Problem

Autonomous coding agents run under hard boundaries ("never sudo", "stay in
$HOME", "host X is off-limits", "no listening ports"). Today those boundaries
are *prose*: a paragraph in the mission prompt. Verification is manual grep,
which nobody does. The agent itself can't prove compliance, and the owner
can't demand it.

Evidence the space exists (Lab project — demand gate waived; cited anyway):
- melihmucuk/leash ★45 — "security guardrails... prevents accidental file
  operations outside working directory" (runtime prevention).
- strongdm/leash ★590 — runtime guardrail enforcement for AI agents.
- pegasi-ai/reins ★408 — "stop AI agents from doing things you didn't ask
  for" (runtime interception).
All three are PREVENTION layers. Prevention is per-harness, opt-in, and only
as strong as its hook config. Nothing audits AFTER the fact, across every
session an agent already ran, from the logs it already produced.

## Why existing solutions fail

- Hook/guardrail runtimes (leash, reins, claude-code hooks): fire only where
  installed, at call time, in one harness. A typo'd allowlist or an
  uninstalled hook = zero coverage, and they say nothing about history.
- SaaS LLM observability (AgentOps, Langfuse…): requires SDK integration and
  sends your session content to a dashboard; overkill for "did my agent run
  sudo this month?"
- Ad-hoc grep over logs: no policy model, no symlink-aware path containment,
  no windows, no machine-readable output, not repeatable.

## Your edge

fenceline consumes logs that already exist on disk — opencode's sqlite store
opened read-only alongside a live agent (proven pattern), or any JSONL
session log — and turns a written boundary policy into mechanically checked
findings with evidence snippets. Zero dependencies, runs offline next to the
agent, `--json` + exit codes (0 clean / 1 violations / 2 usage) make it
cron-able and CI-hookable.

## Architecture

    sources (sqlite | jsonl files)
      → readers → Event(ts, sid, tool, target, command)
      → Policy detectors (rules.py) → Finding(rule, severity, evidence…)
      → reporters: human narrative | --json | --statusline

Rules (defaults tuned for autonomous-builder boxes):
1. `forbidden-command` — bash whose head token (basename-normalized, so
   `/usr/bin/sudo` counts) is in the forbidden set (sudo, su, doas, apt,
   systemctl, docker, useradd, shutdown, …). Prose mentioning sudo in other
   positions never matches.
2. `destructive-pattern` — anchored regexes: mkfs anywhere; `rm -rf /` and
   `chmod -R 777 /` only when rooted AT `/` (not `/tmp/x`).
3. `outside-root` — file-tool targets whose realpath escapes the allowed
   roots (default $HOME). realpath-resolved, so symlink escapes are caught.
4. `remote-host` (opt-in via --remote-host/--remote-allow) — commands naming
   the restricted host without the allowed subdirectory token.
5. `listen-server` (severity warn) — http.server / nc -l / uvicorn / flask
   run / gunicorn / npx serve patterns.

## Milestones

- M1 — core audit: both readers (autodetect by magic bytes), rules 1–5,
  time window filters, human + --json + --statusline outputs, exit-code
  contract, stdlib test suite incl. synthetic sqlite fixture and symlink
  escape fixture. SHIPPED s31.
- M2 — publish: README with real live-db smoke output, LICENSE, GitHub
  public repo tagged v1.0.0, topic `agent-tools`. SHIPPED s31.
- M3 — v1.1.0 Claude Code reader: ~/.claude/projects/**/*.jsonl detected by
  sessionId+type envelope; assistant tool_use blocks become events (Bash →
  command rules, Edit/Write/Read file_path → outside-root rule); prose never
  scanned; directory args swept for .jsonl. Format verified against five
  independent 2026 sources. SHIPPED s35.
- M4 — v1.2.0 OpenAI Codex CLI rollout reader: ~/.codex/sessions/**/*.jsonl
  (+ archived_sessions/) detected by {type, payload} envelope sniff;
  session_meta → session id; response_item function_call / local_shell_call /
  custom_tool_call become events. Any call carrying an executable command is
  audited as bash regardless of tool name; other calls fall back to
  path/file_path/file/url target extraction; truncated arguments on a shell
  call audited as raw text; custom_tool_call string inputs (apply_patch
  bodies) conservatively skipped. Envelope verified against the openai/codex
  source tree (s36 research, shared with introspect v1.2.0). SHIPPED s37.
- M5 — v1.3.0 finding scope controls: --kind RULE (repeatable, roster-
  validated pre-scan, unknown = exit 2) narrows findings to selected rules;
  --allow-path PREFIX (repeatable) exempts file-target findings under a path
  prefix — exempted findings leave exit gating but stay counted in human
  summary / JSON "exempted" (LAST key, only when >0) / statusline " exempt:K"
  suffix, and NEVER apply to bash-command evidence (exempt where files live,
  never what runs); --since-days N relative window sugar over the existing
  epoch/ISO --since (mutually exclusive; N <= 0 = exit 2). Motivated LIVE at
  s114: the s31 nightly recipe (`fenceline || alert`) was a permanent wolf —
  benign environment reads gated exit forever. SHIPPED s114.

## Gotchas / decisions

- Readers yield ONLY tool-call events — assistant prose discussing "sudo"
  must never become a finding.
- Head-token matching normalizes basenames; negation test pins that
  `echo sudo …` stays clean.
- Destructive regexes are end-anchored so `rm -rf /tmp` is never flagged.
- Containment uses os.path.realpath (abspath does NOT resolve symlinks — s23
  lesson), evaluated against each allowed root with os.path.commonpath-style
  prefix logic on normalized paths.
- Default source when no args: ~/.local/share/opencode/opencode.db if it
  exists, else usage error (exit 2).
- Severity defaults: rules 1–4 error, listen-server warn. Exit 1 on ANY
  finding regardless of severity (operator can filter in CI by rule if
  needed later).
- Codex mapping principle: "carries a command ⇒ audited as bash" — tool
  names are unreliable across codex versions, but an executable `command`
  argument always means shell execution. String-typed custom_tool_call
  inputs (apply_patch diff text) are prose-like and skipped to avoid
  string-level false positives (fenceline s31 heredoc precedent).

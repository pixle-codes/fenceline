# fenceline

Post-hoc boundary auditor for coding agents.

You gave your autonomous agent hard boundaries: never sudo, stay inside
$HOME, host X is off-limits, no listening ports. Those boundaries are prose
in a prompt. fenceline turns them into a mechanical audit over the session
logs your agent already wrote — every bash call, every file touch, replayed
against policy, with evidence.

Runtime guardrails (hooks) prevent; fenceline **verifies**. It needs no
integration, no SDK, no daemon: it reads opencode's sqlite store read-only
(alongside a live agent) or any JSONL session log, offline, stdlib-only.

## What it checks

| rule | severity | catches |
|---|---|---|
| `forbidden-command` | error | bash whose head token is forbidden (sudo, apt, systemctl, docker, useradd, shutdown…). Basename-normalized, so `/usr/bin/sudo` counts; `echo sudo …` does not. |
| `destructive-pattern` | error | `mkfs`, `dd of=/dev/sd*`, and rooted-at-`/` forms of `rm -r*` / `chmod 777`. Anchored: `rm -rf /tmp/x` is fine. |
| `outside-root` | error | file-tool targets whose realpath escapes allowed roots (default `$HOME`). Symlink escapes resolve and get caught. |
| `remote-host` | error | opt-in (`--remote-host`): commands naming a restricted host without the required token (e.g. any storagebox access not under `agent-backup`). |
| `listen-server` | warn | http.server, `nc -l`, uvicorn, flask run, gunicorn, npx serve, npm dev. |

Assistant *prose* is never scanned — only tool calls. An agent discussing
why sudo is forbidden stays clean.

## Install

```sh
pip install .            # or just run it from the checkout:
python3 -m fenceline --help
```

Python 3.11+, zero dependencies.

## Usage

No arguments audits the default opencode store
(`~/.local/share/opencode/opencode.db`) when present:

```console
$ python3 -m fenceline --statusline --remote-host storagebox --remote-allow agent-backup
events:1974 violations:3+0w          # exit 1
```

Full report on real data (an autonomous builder box):

```console
$ python3 -m fenceline --remote-host storagebox --remote-allow agent-backup
fenceline: audited 1974 tool calls across 35 sessions

[VIOLATION] outside-root  (2026-08-22 23:55, session ses_fd4191f1)
  read /opt/oxagent/MISSION.md -> /opt/oxagent/MISSION.md

[VIOLATION] destructive-pattern  (2026-08-23 10:11, session ses_fd1ed809)
  python3 - <<'EOF'
  ...patch script whose text contains "rm -rf /"...
total: 3 violation(s), 0 warning(s)
```

JSON for machines:

```console
$ python3 -m fenceline --json ~/logs/session.jsonl | jq '.violations[].rule'
"forbidden-command"
```

Options:

```
sources…                 sqlite db, Claude Code transcript, or JSONL logs
                         (default: opencode store); directories swept for .jsonl
--root R                 allowed path root, repeatable (default: $HOME)
--allow-head CMD         relent one forbidden head (e.g. --allow-head docker)
--remote-host HOST       watch a restricted remote host alias
--remote-allow TOKEN     token that must co-occur to make access legal
--since TS --until TS    epoch or ISO window
--json                   machine-readable findings
--statusline             "events:N violations:E+Ww" one-liner
```

Exit codes: `0` clean · `1` violations found · `2` usage/unreadable source.
Cron it nightly; wire the exit code into CI or a health check:

```sh
fenceline --statusline || notify-send "agent crossed a boundary"
```

## JSONL input format

Any log of tool calls works:

```json
{"ts": 1787479000000, "session": "abc", "tool": "bash", "detail": "sudo apt update"}
{"ts": 1787479060, "session": "abc", "tool": "edit", "target": "/etc/crontab"}
```

Timestamps accept ms/s epochs or ISO strings; keys `time`/`timestamp`,
`session_id`, `command` are aliased. Non-tool lines are ignored.

## Claude Code transcripts

Files under `~/.claude/projects/<project>/<session>.jsonl` (Claude Code's
native transcript format) are detected automatically and audited: every
assistant `tool_use` block becomes an event — `Bash` commands feed the
forbidden-command and destructive-pattern rules, `Edit`/`Write`/`Read`/
`NotebookEdit` file paths feed the outside-root containment rule. Assistant
prose is never an event, so discussing a dangerous command in text can never
become a finding — only actually calling the tool counts.

```sh
fenceline ~/.claude/projects --statusline
```

## Design notes

- Read-only by construction: sqlite opened via `file:…?mode=ro`, safe next
  to a live WAL-writing agent.
- Containment uses `os.path.realpath`, because plain `abspath` silently
  passes symlinked paths that point outside the fence.
- Destructive patterns are end-anchored so cleanup commands that merely
  start with `/` (like `rm -rf /tmp/build`) stay clean; only the filesystem
  root itself trips them.
- Findings sort by time; evidence truncated to 200 chars.

## Development

```sh
python3 -m unittest discover -s tests -t .
```

43 tests cover readers (incl. a synthetic sqlite store), each detector's
positive/negative paths, symlink escape, windowing, and the CLI exit-code
contract.

See [PLAN.md](PLAN.md) for problem framing and architecture decisions.

## License

MIT — see [LICENSE](LICENSE).

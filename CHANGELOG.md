# Changelog

## 0.2.0 — 2026-08-23

### Harness reporter (pre-execution enforcement)

- New `src/reporter.mjs`: NDJSON unix-socket server at
  `~/.local/state/herdr-guard/reporter.sock` (override with
  `HERDR_GUARD_REPORTER_SOCKET`). Agent harnesses report tool calls before
  execution and receive an advisory verdict from the same policy:
  interrupt→`deny`, alert→`warn`, audit/none→`allow`. Stale socket files are
  reclaimed; a live socket from another guard is respected.
- New `hooks/claude-code-pretooluse.mjs`: zero-dependency Claude Code
  `PreToolUse` hook mapping `deny` to a blocked tool call and `warn` to a
  permission prompt. Strictly fail-open — a stopped guard never breaks the
  harness.
- Reported commands bypass `prompt_only` gating (no prompt glyphs in raw
  commands), honor project overrides by reported `cwd`, and are audited with
  `source: "harness:<agent>"`. Pause allows but still audits. The dashboard
  shows a harness-reports counter.

### Default policy hardening (26 → 52 rules)

- New interrupt-tier rules: device wipes (`wipefs`/`blkdiscard`/`shred` on
  devices), shell redirects onto block devices, recursive `chmod`/`chown` on
  rootish paths, `find / -delete`, fork bombs, `crontab -r`.
- New alert-tier rules: AWS/GCP/Azure resource deletion, PaaS app
  destruction, DB `DROP`/`TRUNCATE` (prompt-only), `kubectl delete
  namespace` / `helm uninstall`, `docker volume` removal, the package
  publish family (`cargo`/`twine`/`gem`/`yarn`/`pnpm`), SSH-key and
  credential-store reads, `curl` uploads of secret material, firewall
  disabling, guard tampering (plugin disable, killing Herdr, deleting
  rules/audit files), history clearing, `setsid`/`at now` detachment,
  hex-decode-to-shell, `gh repo delete`, `git push --delete`/`--mirror`.
- False-positive fixes: `git push --force-with-lease` no longer trips the
  force-push alert (it has its own audit-tier rule); `id_rsa.pub` reads and
  `curl` posts to URLs merely containing "credentials" stay silent.
- New `tests/rules-default.test.mjs`: every shipped rule carries canonical
  hits plus near-miss false-positive guards, with completeness enforced.

### Review hardening (post-review fixes, same release)

- Reporter lifecycle: socket claiming is now gated by an atomic pid lock
  (concurrent starters cannot orphan each other), `close()` only removes a
  socket/lock the instance owns, and a pre-existing parent directory of a
  user-overridden socket path is never chmodded.
- Rule fixes: `crontab -u <user> -r` now interrupts; mixed-case SQL
  `Drop Table` now alerts; `wipefs` without erase flags, `grep setsid`,
  `gcloud ... list | grep delete`, and `curl -d @file` posts to URLs merely
  containing "credentials" no longer false-positive.
- Guard and hook now agree that an empty `HERDR_GUARD_REPORTER_SOCKET`
  means unset.

## 0.1.1

- Transport hotfix: Herdr socket lifecycle repair, watcher lifecycle and
  audit gap fixes, per-session watchdog recovery isolation, malformed
  generation report deduplication, minimal CI validation workflow.

## 0.1.0

- Initial release: pane watcher with subscribe-first/reconcile-after
  bootstrap, content-based replay suppression, prompt-gated interrupt rules,
  severity-partitioned audit log with redaction and sanitization, project
  overrides capped at alert, pause/resume with TTL, self-healing watchdog,
  ANSI dashboard.

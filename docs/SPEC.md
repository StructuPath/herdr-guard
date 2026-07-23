# herdr-guard — Spec (v1)

Cross-agent command policy layer for [Herdr](https://herdr.dev). Watches herdr
panes for dangerous commands, then audits, alerts, or interrupts — from one
policy, regardless of which agent or shell is running in the pane.

## Honest capability model (verified against herdr 0.7.5 + red-teamed)

Coverage depends on pane type. This table is the product's contract — it
belongs in the README verbatim:

| Pane type | What the guard sees | `interrupt` guarantee |
| --- | --- | --- |
| Interactive shell (zsh/bash, canonical echo) | Everything typed, **including unsubmitted input** (tty echo) | **Pre-execution cancel**: ctrl+c wipes the readline before Enter. Strong |
| Shell in raw/no-echo mode (`stty -echo`, curses wrappers) | Nothing typed | None. `stty -echo` itself is an alert-class rule |
| TUI agent (Pi, Claude Code, Codex) | Only what the TUI renders — permission prompts, expanded tool views. Tool-executed command strings are usually NOT echoed | Incidental only. Do not rely on it |
| Plain process output (logs, builds) | Everything printed | Best-effort: only stops commands still running |
| Popup panes | **Nothing** — popups have no pane id, no pane events, no pane API | None. Hard blind spot, documented |

The guard matches command **text**, not command **intent**. Semantic
obfuscation (`base64 -d | sh`, `r''m`, `$x -rf`, python `shutil.rmtree`)
defeats content matching; obfuscation-*indicator* alert rules make attempts
loud but can't stop them. Harness-level hooks remain the enforcement point
inside TUI agents; v2 path is tiny harness reporters (Pi extension / Claude
Code hook) POSTing tool calls to the guard for unified audit+policy.

## Architecture

Stack: **plain ESM Node.js (>= 20), zero runtime deps**, bash shims in the
manifest. Same stack as herdr-swarm / herdr-browser.

```text
herdr-guard/
  herdr-plugin.toml
  scripts/*.sh            # manifest entrypoint shims
  src/
    watcher.mjs           # long-running guard process (the Guard pane)
    herdr-socket.mjs      # NDJSON socket client: connect, request, subscribe, reconnect
    policy.mjs            # pure policy engine: load/merge config, validate, match -> decisions
    rules-default.json    # shipped default policy (seeded into config dir)
    audit.mjs             # JSONL append, redaction, sanitization, partitioned rotation
    render.mjs            # dashboard rendering (ANSI, sanitized)
  tests/*.test.mjs        # node:test — policy engine + socket client (fake NDJSON server)
```

### The Guard pane (watcher)

One long-running `[[panes]]` entrypoint (`placement = "split"`). Lifecycle:

1. **Bootstrap**: `session.snapshot` → live panes (excluding own plugin
   panes by plugin id, never by process name).
2. **Subscribe-first, reconcile-after** (per pane): open ONE
   `pane.output_matched` subscription with a single combined alternation
   regex (`source: "recent_unwrapped"`, `lines: 5` for interrupt rules,
   `strip_ansi: true`), THEN `pane.read` for a baseline. **Replay
   suppression is content-based**: drop events whose matched lines are a
   subset of the post-subscribe read; the 500ms-arrival window is only a
   fallback heuristic. Never act on suppressed events — an `interrupt`
   replay would ctrl+c whatever the pane is doing now.
3. **Global subscriptions**: `pane.created` (async subscribe-first per
   step 2 — never block the event loop on baselining), `pane.closed` /
   `pane.exited` (cleanup + **post-mortem sweep**: final `pane.read` of the
   dying pane, locally matched, so split-run-close attacks at least get
   audited after the fact). Events arriving with the ack are baseline, not
   transitions.
4. **On match event**: herdr-side matching is edge-triggered, so the guard
   re-scans the event's `read.text` locally against all rules. Dedupe is:
   time-bounded (suppress identical repeats only within ~2s), LRU-capped
   (256 entries/pane), keyed on (pane, line, action_taken) — and
   **interrupt-class rules are never deduped across interrupt events** (a
   rule severe enough to ctrl+c once is severe enough to ctrl+c twice;
   this kills the pre-seeding attack).
5. **Sweep backstop**: `pane.read` per pane, scheduled per-pane
   since-last-sweep (~10s each, bounded concurrency — NOT a global
   round-robin cycle that degrades with pane count), locally matched +
   deduped. Push path is the primary record; eviction racing the sweep is
   a documented limitation.
6. **Rate limits**: max 10 actions/min/pane; beyond that, one coalesced
   "N suppressed matches for rule X" audit entry per minute. Notifications
   coalesce by rule id. Flooding cannot evict real history: severity-
   partitioned files — `audit.interrupt.jsonl` rotates separately from
   `audit.jsonl` (10MB × 3 generations each, 0600 preserved).
7. **Decide and act** (highest matching severity wins):
   - all tiers: audit-log `{ts, pane_id, workspace, rule_id, matched_text,
     process_argv, cwd, pane_type, action_taken}`
   - `alert` / `interrupt`: `notification.show` (best-effort; the audit
     entry is the reliable record)
   - `interrupt`: `pane.send_keys` ctrl+c **to the event's own pane_id
     only**. Pinned invariant: pane_id comes from the event, never from
     matched text or config. TOCTOU acknowledged: the ctrl+c lands on
     whatever is in the pane now.
8. **`prompt_only` matching**: rules with `prompt_only: true` (DEFAULT ON
   for interrupt rules) only fire when the matched line looks like a
   prompt line (leading `❯`/`$`/`%`/`╰─` glyph). Prevents ctrl+c-ing vim,
   less, build logs, and `cat RUNBOOK.md` — and prevents FP-storm
   alert-fatigue attacks that train users to pause the guard. Trade-off:
   heredoc bodies and script text don't trigger interrupt; they still
   audit.
9. **Enrichment**: `pane.process_info` for foreground argv/cwd; classify
   pane_type from process name + terminal title. Override cache is keyed
   by pane cwd and **invalidated on cwd change**, not just mtime.
10. **Fail-visible**: on socket drop, dashboard shows
    `DISCONNECTED — NOT ENFORCING` + notification; reconnect with backoff,
    then full re-bootstrap (snapshot → subscribe-first → reconcile).
11. **Self-healing watchdog**: `[[events]]` hooks on `pane.closed` AND
    `pane.exited` — if the Guard pane died, the hook auto-reopens it via
    `plugin.pane.open` and notifies. A sibling-session check enumerates
    `~/.config/herdr/sessions/*/herdr.sock` and alerts on sessions the
    guard isn't watching. Residual (documented, unfixable in v1):
    `herdr plugin disable`, `pkill`, `herdr server stop` — the guard is
    advisory against agents with socket access. Upstream ask: socket ACL /
    read-only token, popup visibility in pane API.
12. **Dashboard**: policy state (active/paused/disconnected), panes
    watched, rules loaded, matches today, last N audit entries. ANSI
    clear+reprint on event/resize. All event-derived strings stripped of
    C0/C1/OSC/U+2028/U+2029 before rendering — and the same sanitization
    applies to audit-log writes.

### Policy config

- Main: `$HERDR_PLUGIN_CONFIG_DIR/rules.json`. Seeded from shipped
  `rules-default.json` on first run or via `guard reset-rules` (backup
  first). State dir `0700`; audit + rules files `0600`.
- Format:

  ```json
  {
    "version": 1,
    "enforcement": "active",
    "allow_project_override": false,
    "rules": [
      {
        "id": "rm-rf-root",
        "severity": "interrupt",
        "match": "regex",
        "prompt_only": true,
        "pattern": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\\s+(/|~|/\\*|\\$HOME)",
        "reason": "Recursive force delete near filesystem root"
      }
    ]
  }
  ```

  `match` is `regex` (RE2-safe — herdr evaluates with the Rust regex
  crate) or `substring`.
- **Rule rules**: no `^` anchors (matched lines carry prompt glyphs);
  validator at load: cap length 512, reject backrefs, reject unparseable
  regex (log + notify on rejection).
- **Default rules** (from pi damage-control, pi-library sp-damage-control
  - safe-mode, red-team additions):
  - *interrupt*: `rm -rf` rootish paths, `dd of=/dev`, `mkfs`,
    `git push --force` / `reset --hard` (alert or interrupt — ship alert),
    `terraform destroy`, `kubectl delete` prod-ish contexts
  - *alert*: `sudo`, `curl|sh` / `wget|sh`, `cat .env*` / `security
    find-generic-password -w`, `npm publish`, `aws s3 rm|sync --delete`,
    `docker system prune -a`, exfil (`scp|rsync` of `~/.ssh`, `~/.aws`,
    `~/fsw-bid-data`), **evasion indicators**: `stty -echo`, `stty raw`,
    `tmux.*(-d|-b)`, `screen -dm`, `disown`, `base64 -d` piped to shell,
    `eval $(`, `sh -c "$(`
  - *audit*: everything above plus git destructive variants
- **Project override**: `<workspace cwd>/.herdr-guard.json`, merged lazily
  per pane cwd.
  - May **add** rules (`substring` only — repo-controlled regex never
    reaches the herdr server) and may **raise** severity **to `alert` at
    most** (raise-to-interrupt is self-DoS with no defensive value).
  - May **never disable or lower** config-dir rules unless
    `"allow_project_override": true`. Every applied override is
    audit-logged with its workspace path.
- **Writes are atomic** (tmp + rename). On parse error: keep last-good
  config + alert. Never fall back to empty.

### Enforcement changes are privileged events

`pause` / `resume` flip `enforcement` (watcher mtime-polls, 2s). Every
enforcement flip, config reload, and rule-set change is audit-logged
(before/after counts) AND fires `notification.show`. `pause` takes an
optional TTL (default 15min) after which enforcement auto-resumes.

### Audit log

`$HERDR_PLUGIN_STATE_DIR/audit.jsonl` + `audit.interrupt.jsonl`, `0600`,
10MB × 3 generations, partitioned so floods can't evict interrupt history.
Before writing: `matched_text` truncated to 200 chars, redacted
(`KEY=VALUE`, bearer/`sk-`/`ghp_` token shapes), sanitized
(C0/C1/OSC/U+2028/U+2029). The audit log is sensitive data; README says so.

### Manifest surface

- `[[panes]] guard` (split) — watcher + dashboard.
- `[[actions]] open` — open/focus the Guard pane.
- `[[actions]] pause [ttl]` / `resume` — enforcement control (audited).
- `[[actions]] test` — popup prompt: type a command string; shows matching
  rules + verdict, using realistic prompt-decorated lines (dry-run).
- `[[actions]] reset-rules` — reseed config (backup first).
- `[[startup]]` — seed config if missing, then idempotently
  `plugin.pane.open` the guard entrypoint (check `session.snapshot`
  first). Without this the guard watches nothing until manually opened.
- `[[events]] on = "pane.closed"` and `on = "pane.exited"` — self-healing
  watchdog (reopen guard pane + notify).

## Known limitations (README material, accepted for v1)

- `herdr plugin disable` / `pkill` / `herdr server stop` — guard is
  advisory against socket-privileged agents. Upstream ask: socket ACL.
- Popup panes are invisible execution channels. Upstream ask: popup API.
- Semantic obfuscation defeats content matching.
- Sibling named sessions run separate sockets (guard alerts on them,
  doesn't watch them).
- Raw-mode/no-echo shells hide typed input (alert rule on `stty -echo`
  is the mitigation).
- Nested-mux detached execution (`tmux new-window -d`, `screen -dm`,
  nohup+disown) — launcher line may alert; execution is invisible.
- Interrupt TOCTOU: ctrl+c lands on whatever is currently foreground.
- Scrollback eviction can beat the sweep; push path is the primary record.
- Smoke-test matrix required before publish: user scrolled up in
  scrollback, terminal resize, OSC8/DCS/APC/bracketed-paste ANSI
  correctness of `strip_ansi`, named sessions.

## Testing

- `node:test` for `policy.mjs`: load, merge precedence, override
  add/raise-capped-at-alert enforcement, pattern validator, severity
  routing, redaction/sanitization, prompt_only gating, rate limiting,
  time-bounded dedupe incl. interrupt no-dedupe.
- `herdr-socket.mjs` against a fake NDJSON server: bootstrap,
  subscribe-first/reconcile, content-based replay suppression,
  edge-trigger local re-scan, post-mortem sweep, reconnect → re-bootstrap.
- Manual smoke: `herdr plugin link .` → Guard pane auto-opens on restart →
  type (don't submit) `rm -rf /` in a shell pane → line cancelled, audit
  entry, notification → repeat immediately → cancelled AGAIN (no dedupe) →
  `guard test` shows the same match → close Guard pane → watchdog reopens
  it with a notification.

## Publish

Repo `StructuPath/herdr-guard`, topics `herdr-plugin`, `herdr`, `security`.
MIT license. README leads with the coverage-matrix table and the known-
limitations list. Honesty is the differentiator.

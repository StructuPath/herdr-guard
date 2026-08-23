# Show HN submission

## Title

Show HN: herdr-guard – Command policy for multi-agent terminals

## URL

<https://github.com/StructuPath/herdr-guard>

## First comment

I built herdr-guard after I started running several coding agents and ordinary
shells in the same Herdr session. The agents had their own permission systems,
but I had no shared place to answer a simpler question: did any pane just type
or print a command I would want to notice before it ran?

herdr-guard is a Herdr plugin that applies one text policy across those panes.
Rules can audit a match, send an alert, or attempt to interrupt an interactive
shell by requesting Ctrl+C in the pane that produced the event. Guard records
whether Herdr accepted that request, but prevention remains unknown. The
default policy is 54 rules covering destructive filesystem, git, cloud, and
database commands, secret and credential reads, publishing, exfiltration
indicators, guard tampering, and common attempts to hide execution — and every
rule ships with hit and near-miss tests, because false positives train people
to pause the guard.

The same policy now also enforces before execution. The guard listens on a
local unix socket, and a bundled Claude Code PreToolUse hook reports each tool
call and honors the verdict: interrupt-tier rules deny the call, alert-tier
rules turn into a permission prompt, and everything is audited in one place.
The hook is strictly fail-open — a stopped guard never breaks the harness —
and the protocol is one NDJSON line, so other harnesses can wire in the same
way. Pane-watching stays the cross-agent backstop; the hook is where
prevention actually exists.

The implementation is plain ESM Node.js 20 with no runtime dependencies. It
connects to Herdr's NDJSON socket, takes a pane snapshot, subscribes to
`pane.output_matched`, and uses periodic `pane.read` calls as a backstop. One of
the less obvious problems was replay: a new subscription can include matching
scrollback, and blindly treating that as a new command could send Ctrl+C to
whatever is running now. The watcher therefore subscribes first, reads a
baseline, and suppresses events attributable to that baseline before acting on
new matches.

I also made interrupt rules prompt-only by default, restricted repository-local
rules to substring matching with a maximum severity of `alert`, and kept
interrupts outside deduplication and lower-severity rate limiting. Audit files
are private, rotated, partitioned by severity, sanitized, and redacted before
writing. Socket disconnects are visible and trigger reconnect plus a complete
re-bootstrap.

This is not a sandbox or an intent detector. On the pane side, interactive
Bash and Zsh input is the strongest case because canonical terminal echo
exposes text before Enter; commands executed internally by Pi, Claude Code,
or Codex TUIs are usually not visible unless the TUI renders them — which is
exactly the gap the reporter hook closes for Claude Code. Raw/no-echo shells,
popup panes, nested multiplexers, and semantic obfuscation remain blind spots,
and a process with the user's privileges can still stop the guard (the hook
fails open by design; tampering attempts are alert rules).

You can try the tagged release without an account or service. It requires
Herdr 0.7.5+, Node.js 20+, and macOS or Linux:

```sh
herdr plugin install StructuPath/herdr-guard --ref v0.2.0
```

The repository includes the policy, manifest, an honest coverage matrix, the
Claude Code hook, a reproducible demo, and a fake-socket/runtime regression
suite. I would especially value feedback on false-positive tradeoffs, useful
default rules, and whether the next step should be reporters for more
harnesses (Pi, Codex), shell pre-exec approval, or upstream Herdr
capabilities such as popup visibility and socket ACLs.

## Posting notes

- Submit the repository URL, not this document. Show HN is for something readers
  can run; the write-up above belongs in the first comment.
- Use the title exactly as written or keep the `Show HN:` prefix if editing it.
- Be available after posting to answer implementation and security-boundary
  questions.
- Do not ask anyone to upvote or coordinate comments.

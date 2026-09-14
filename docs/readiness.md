# Readiness and upgrades

Guard's runtime and manifest remain **0.2.0**. The readiness tooling does not
change the shipped rules, severity mapping, hook installation, or enforcement
behavior. The implementation uses plain Node ESM without runtime dependencies.

## Build and validation

Run `npm run doctor`, then `npm run validate` before linking the plugin.
Doctor checks Node, the platform lock utility, Python's TOML parser, and the
selected Herdr binary. It does not connect to a session or inspect private
configuration. A successful doctor check proves prerequisites only, not live
pane or harness operation.

Minimums are Node 20.10, Python 3.11, and Herdr 0.7.5. macOS needs `lockf`;
Linux needs `flock`. Bash is used by plugin entrypoints and syntax validation.
If several Herdr binaries are installed,
`HERDR_BIN_PATH=/absolute/path/to/herdr npm run doctor` checks the selected executable.
Start Herdr and link the plugin using that same executable.

The full validation checks every JavaScript and shell file, manifest commands,
release consistency, and tests using isolated temporary files and local Unix
sockets. The reporter tests run the actual Claude Code hook process against a
local reporter server. They verify decision JSON; they do not prove that a
particular installed Claude Code version honors the decision. Dangerous test
commands are strings and are never executed.

Validation recorded on 2026-09-13: 132 tests passed on Node 20.20.2, 24.18.0,
and 26.4.0 on macOS. Build checked 27 JavaScript/shell files and 10 manifest
entrypoints. Doctor accepted the installed Herdr 0.8.2 and rejected 0.7.1
against the declared 0.7.5 minimum. These checks do not establish live Herdr
0.8.2 integration coverage.

## Upgrading from 0.1.1

0.2.0 adds the harness reporter and expands the default policy from 26 to 52
rules. Existing `rules.json` files are preserved. Upgrading the plugin does
not automatically add the new defaults to a customized policy. Compare your
configuration with `src/rules-default.json` before choosing which new rules
to adopt. The `structupath.guard.reset-rules` action replaces the current rules
with defaults and creates a timestamped backup; use it only when that reset
is intended. The reset audit records old and new rule counts.

The reporter rendezvous is `$XDG_STATE_HOME/herdr-guard/reporter.sock`, falling
back to `~/.local/state/herdr-guard/reporter.sock`. It is separate from
`HERDR_PLUGIN_STATE_DIR`. To override it, give the Guard process and the harness
hook the same nonempty `HERDR_GUARD_REPORTER_SOCKET`. Only one Guard process
serves a given reporter socket; another session leaves a live owner alone.

The bundled hook must be configured explicitly in the harness. Its responses
are advisory verdicts: interrupt-tier becomes `deny`, alert-tier becomes
`warn`, audit or unmatched becomes `allow`. The Claude Code adapter emits
`permissionDecision: "deny"` or `"ask"`; an unavailable or malformed reporter
response fails open. Paused enforcement still audits and returns `allow`.
Neither this protocol nor pane interrupts prove prevention.

## Next improvements

1. Repeat isolated live-session smoke tests on each supported Herdr release,
   including pane restart, duplicate startup, reconnect, and named sessions.
2. Verify the opt-in Claude Code hook against the installed harness version
   using harmless fixture commands before relying on its decisions.
3. Add a policy migration preview that compares existing rules with new
   defaults while preserving user edits; keep applying changes explicit.
4. Add additional harness adapters only with protocol and lifecycle tests.
   Popup visibility and per-plugin socket permissions require upstream Herdr
   support and remain limitations.

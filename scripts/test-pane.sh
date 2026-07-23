#!/usr/bin/env bash
set -euo pipefail
printf 'Command to test: '
IFS= read -r command || true
exec node "$HERDR_PLUGIN_ROOT/src/command.mjs" test "$command"

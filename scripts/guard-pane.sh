#!/usr/bin/env bash
set -euo pipefail
exec node "$HERDR_PLUGIN_ROOT/src/watcher.mjs"

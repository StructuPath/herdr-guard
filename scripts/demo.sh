#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
COMMAND_TEXT=${1:-}

if [[ -z "$COMMAND_TEXT" ]]; then
	printf 'usage: %s "command"\n' "$0" >&2
	exit 2
fi

DEMO_DIR=$(mktemp -d "${TMPDIR:-/tmp}/herdr-guard-demo.XXXXXX")
trap 'rm -rf "$DEMO_DIR"' EXIT

RESULT=$(
	HERDR_PLUGIN_CONFIG_DIR="$DEMO_DIR/config" \
		HERDR_PLUGIN_STATE_DIR="$DEMO_DIR/state" \
		node "$ROOT_DIR/src/command.mjs" test "$COMMAND_TEXT"
)

IFS=$'\t' read -r SEVERITY RULE_ID REASON <<<"$RESULT"

printf '\n'
printf '  \033[1;38;5;75mherdr-guard\033[0m \033[2mv0.1.0\033[0m    \033[1;32m● ACTIVE\033[0m\n'
printf '  \033[2mCross-agent command policy for Herdr\033[0m\n'

case "$SEVERITY" in
interrupt)
	COLOR='\033[1;31m'
	ICON='⛔'
	ACTION='Ctrl+C → shell pane'
	;;
alert)
	COLOR='\033[1;33m'
	ICON='⚠'
	ACTION='Desktop notification'
	;;
*)
	COLOR='\033[1;36m'
	ICON='●'
	ACTION='Audit log entry'
	;;
esac

printf '\n'
printf '  \033[2mPOLICY DRY RUN\033[0m\n'
printf '  %b%s  %s\033[0m\n' "$COLOR" "$ICON" "${SEVERITY^^}"
printf '\n'
REASON_DISPLAY=${REASON/root-level or home path/root or home}
printf '  \033[2mCommand\033[0m   %s\n' "$COMMAND_TEXT"
printf '  \033[2mRule\033[0m      %s\n' "$RULE_ID"
printf '  \033[2mReason\033[0m    %s\n' "$REASON_DISPLAY"
printf '  \033[2mRuntime\033[0m   %s\n' "$ACTION"
printf '  \033[2mAudit\033[0m     Written with secret redaction\n'
printf '\n'
printf '  \033[1;32m✓ command would be cancelled before execution\033[0m\n'

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
printf '  \033[1;38;5;75mherdr-guard\033[0m \033[2mv0.1.1\033[0m    \033[1;32m● ACTIVE\033[0m\n'
printf '  \033[2mCross-agent command policy for Herdr\033[0m\n'

case "$SEVERITY" in
interrupt)
	COLOR='\033[1;31m'
	ICON='⛔'
	LABEL='INTERRUPT'
	DECISION='request-interrupt (classified shell panes only)'
	REQUEST='not-requested (dry run; runtime records accepted or failed)'
	AUDIT='Would write with secret redaction at runtime'
	OUTCOME='Runtime would request Ctrl+C in a classified shell; prevention is not observed.'
	;;
alert)
	COLOR='\033[1;33m'
	ICON='⚠'
	LABEL='ALERT'
	DECISION='request-notification'
	REQUEST='not-requested'
	AUDIT='Would write with secret redaction at runtime'
	OUTCOME='Runtime would request a notification and would not request Ctrl+C.'
	;;
audit)
	COLOR='\033[1;36m'
	ICON='●'
	LABEL='AUDIT'
	DECISION='log-only'
	REQUEST='not-requested'
	AUDIT='Would write with secret redaction at runtime'
	OUTCOME='Runtime would log this match only.'
	;;
*)
	COLOR='\033[2m'
	ICON='○'
	LABEL='NO MATCH'
	RULE_ID='none'
	REASON='No active policy rule matched this text'
	DECISION='none'
	REQUEST='not-requested'
	AUDIT='No match audit would be written'
	OUTCOME='No policy rule matched; this dry run makes no safety claim.'
	;;
esac

printf '\n'
printf '  \033[2mPOLICY DRY RUN\033[0m\n'
printf '  %b%s  %s\033[0m\n' "$COLOR" "$ICON" "$LABEL"
printf '\n'
REASON_DISPLAY=${REASON/root-level or home path/root or home}
printf '  \033[2mCommand\033[0m             %s\n' "$COMMAND_TEXT"
printf '  \033[2mRule\033[0m                %s\n' "$RULE_ID"
printf '  \033[2mReason\033[0m              %s\n' "$REASON_DISPLAY"
printf '  \033[2mDecision\033[0m            %s\n' "$DECISION"
printf '  \033[2mInterrupt request\033[0m    %s\n' "$REQUEST"
printf '  \033[2mPrevention\033[0m          unknown\n'
printf '  \033[2mAudit\033[0m               %s\n' "$AUDIT"
printf '\n'
printf '  \033[1m%s\033[0m\n' "$OUTCOME"

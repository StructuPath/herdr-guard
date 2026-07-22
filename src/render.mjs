// render.mjs — ANSI dashboard for the Guard pane. Pure function of state;
// every dynamic string arrives already sanitized by audit/policy, and is
// sanitized again here (defense in depth — panes can emit terminal escapes).

import { sanitizeString } from "./policy.mjs";

const RESET = "[0m";
const BOLD = "[1m";
const DIM = "[2m";
const RED = "[31m";
const GREEN = "[32m";
const YELLOW = "[33m";
const CYAN = "[36m";

function paint(color, text) {
	return `${color}${text}${RESET}`;
}

function stateLine(state) {
	if (!state.connected) {
		return paint(
			RED,
			`${BOLD}● DISCONNECTED — NOT ENFORCING${RESET}${DIM} (reconnecting…)${RESET}`,
		);
	}
	if (state.enforcement === "paused") {
		const remaining = Math.max(
			0,
			Math.ceil(((state.pausedUntil ?? 0) - state.now) / 1000),
		);
		const ttl = state.pausedUntil ? ` — auto-resume in ${remaining}s` : "";
		return paint(YELLOW, `${BOLD}● PAUSED${RESET}${DIM}${ttl}${RESET}`);
	}
	return paint(GREEN, `${BOLD}● ACTIVE${RESET}`);
}

/**
 * state: {
 *   connected, enforcement, pausedUntil, now, panesWatched, rulesLoaded,
 *   rejectedRules, matchesToday, lastEntries[], version
 * }
 */
export function renderDashboard(state, { width = 80, height = 24 } = {}) {
	const lines = [];
	lines.push(paint(CYAN, `${BOLD} herdr-guard ${state.version ?? ""}${RESET}`));
	lines.push("");
	lines.push(` ${stateLine(state)}`);
	lines.push(
		` ${DIM}panes watched:${RESET} ${state.panesWatched}   ` +
			`${DIM}rules:${RESET} ${state.rulesLoaded}` +
			(state.rejectedRules
				? paint(YELLOW, ` (+${state.rejectedRules} rejected)`)
				: "") +
			`   ${DIM}matches today:${RESET} ${state.matchesToday}`,
	);
	lines.push("");
	lines.push(` ${BOLD}recent activity${RESET}`);
	lines.push(` ${DIM}${"─".repeat(Math.min(width - 2, 60))}${RESET}`);

	const recent = state.lastEntries.slice(-Math.max(3, height - 8));
	for (const entry of recent) {
		const sev = entry.severity ?? "audit";
		const color = sev === "interrupt" ? RED : sev === "alert" ? YELLOW : DIM;
		const ts = entry.ts
			? new Date(entry.ts).toTimeString().slice(0, 8)
			: "??:??:??";
		const text = sanitizeString(entry.matched_text ?? entry.note ?? "");
		const room = Math.max(10, width - 32);
		const clipped = text.length > room ? `${text.slice(0, room)}…` : text;
		lines.push(
			` ${DIM}${ts}${RESET} ${paint(color, sev.padEnd(9))} ${DIM}${sanitizeString(entry.pane_id ?? "").padEnd(6)}${RESET} ${clipped}`,
		);
	}
	if (recent.length === 0) lines.push(` ${DIM}no matches yet${RESET}`);

	return `[2J[H${lines.join("\n")}\n`;
}

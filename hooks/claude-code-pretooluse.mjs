#!/usr/bin/env node
// claude-code-pretooluse.mjs — herdr-guard reporter for Claude Code.
//
// Wire it as a PreToolUse hook (settings.json):
//
//   {
//     "hooks": {
//       "PreToolUse": [
//         {
//           "matcher": "Bash",
//           "hooks": [
//             {
//               "type": "command",
//               "command": "node /path/to/herdr-guard/hooks/claude-code-pretooluse.mjs"
//             }
//           ]
//         }
//       ]
//     }
//   }
//
// The hook reports the tool call's command string to the guard's reporter
// socket and maps the verdict onto Claude Code's PreToolUse decision:
// deny (interrupt-tier rule) -> permissionDecision "deny", warn (alert-tier)
// -> "ask", allow -> no output. This is the one path where the guard's
// policy is enforced BEFORE execution rather than best-effort after.
//
// FAIL-OPEN, ALWAYS: guard not running, socket missing, timeout, malformed
// response — the hook exits 0 with no output and the tool call proceeds.
// The guard is an advisory layer; a broken guard must never break the
// harness. (Consequence: killing the guard silences this path. The guard's
// own tamper rules make that loud on the pane side.)

import net from "node:net";
import os from "node:os";
import path from "node:path";

const TOTAL_DEADLINE_MS = 500;

function reporterSocketPath() {
	if (process.env.HERDR_GUARD_REPORTER_SOCKET)
		return process.env.HERDR_GUARD_REPORTER_SOCKET;
	const stateHome =
		process.env.XDG_STATE_HOME && process.env.XDG_STATE_HOME.length > 0
			? process.env.XDG_STATE_HOME
			: path.join(os.homedir(), ".local", "state");
	return path.join(stateHome, "herdr-guard", "reporter.sock");
}

function readStdin() {
	return new Promise((resolve) => {
		let data = "";
		process.stdin.setEncoding("utf8");
		process.stdin.on("data", (chunk) => {
			data += chunk;
		});
		process.stdin.on("end", () => resolve(data));
		process.stdin.on("error", () => resolve(data));
	});
}

function askGuard(request) {
	return new Promise((resolve) => {
		const socket = net.connect(reporterSocketPath());
		let buffer = "";
		const finish = (value) => {
			socket.destroy();
			resolve(value);
		};
		const deadline = setTimeout(() => finish(null), TOTAL_DEADLINE_MS);
		deadline.unref?.();
		socket.on("error", () => finish(null));
		socket.on("connect", () => {
			socket.write(`${JSON.stringify(request)}\n`);
		});
		socket.on("data", (chunk) => {
			buffer += chunk.toString("utf8");
			const newline = buffer.indexOf("\n");
			if (newline === -1) return;
			try {
				finish(JSON.parse(buffer.slice(0, newline)));
			} catch {
				finish(null);
			}
		});
		socket.on("close", () => finish(null));
	});
}

function emitDecision(permissionDecision, verdict) {
	const detail = verdict.rule_id
		? `${verdict.reason} (rule ${verdict.rule_id})`
		: (verdict.reason ?? "policy match");
	process.stdout.write(
		`${JSON.stringify({
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision,
				permissionDecisionReason: `herdr-guard: ${detail}`,
			},
		})}\n`,
	);
}

async function main() {
	let payload;
	try {
		payload = JSON.parse(await readStdin());
	} catch {
		return; // not a hook invocation we understand — allow
	}
	const command = payload?.tool_input?.command;
	if (typeof command !== "string" || command.length === 0) return;

	const verdict = await askGuard({
		v: 1,
		kind: "tool_call",
		agent: "claude-code",
		tool: payload.tool_name ?? null,
		command,
		cwd: payload.cwd ?? null,
		session: payload.session_id ?? null,
	});
	if (!verdict || verdict.ok !== true) return; // fail-open
	if (verdict.verdict === "deny") emitDecision("deny", verdict);
	else if (verdict.verdict === "warn") emitDecision("ask", verdict);
}

// Success either way (fail-open), but let stdout drain naturally: a forced
// process.exit() can truncate the decision JSON before Claude Code reads it.
main().then(
	() => {
		process.exitCode = 0;
		process.stdin.destroy();
	},
	() => {
		process.exitCode = 0;
		process.stdin.destroy();
	},
);

// Harness reporter ingest: Guard.handleReport verdicts, the NDJSON unix
// socket server, and the shipped Claude Code PreToolUse hook end-to-end.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Guard } from "../src/watcher.mjs";
import { ReporterServer, probeSocket } from "../src/reporter.mjs";
import { compileRule } from "../src/policy.mjs";

const HOOK_PATH = path.resolve(
	path.dirname(fileURLToPath(import.meta.url)),
	"..",
	"hooks",
	"claude-code-pretooluse.mjs",
);

const RULES = [
	compileRule({
		id: "danger-interrupt",
		severity: "interrupt",
		match: "substring",
		pattern: "rm -rf /",
		reason: "recursive delete at root",
	}),
	compileRule({
		id: "danger-alert",
		severity: "alert",
		match: "substring",
		pattern: "npm publish",
		reason: "publishing a package",
	}),
	compileRule({
		id: "danger-audit",
		severity: "audit",
		match: "substring",
		pattern: "git stash drop",
		reason: "discarding stashed work",
	}),
];

function makeGuard({ enforcement = "active", pausedUntil = null } = {}) {
	const entries = [];
	const notifications = [];
	const guard = new Guard({
		socket: {
			on: () => {},
			request: async (method, params) => {
				if (method === "notification.show") notifications.push(params);
				return {};
			},
		},
		configStore: { load: () => ({}), reloadIfChanged: () => ({}) },
		auditLog: { write: (entry) => entries.push(entry), tail: () => entries },
		now: () => 1_000,
	});
	guard.config = {
		enforcement,
		paused_until: pausedUntil,
		allow_project_override: false,
		rules: RULES,
	};
	return { guard, entries, notifications };
}

test("handleReport maps severities to deny/warn/allow and audits with harness source", () => {
	const { guard, entries, notifications } = makeGuard();

	// interrupt-tier: prompt_only defaults ON, yet a raw harness command (no
	// prompt glyph) must still be denied — reports bypass prompt gating.
	const deny = guard.handleReport({
		agent: "claude-code",
		tool: "Bash",
		command: "rm -rf / --no-preserve-root",
		cwd: "/tmp",
		session: "s1",
	});
	assert.equal(deny.ok, true);
	assert.equal(deny.verdict, "deny");
	assert.equal(deny.rule_id, "danger-interrupt");
	assert.equal(deny.enforcement, "active");

	const warn = guard.handleReport({
		agent: "claude-code",
		command: "npm publish",
	});
	assert.equal(warn.verdict, "warn");
	assert.equal(warn.rule_id, "danger-alert");

	const auditOnly = guard.handleReport({
		agent: "claude-code",
		command: "git stash drop",
	});
	assert.equal(auditOnly.verdict, "allow");
	assert.equal(auditOnly.rule_id, "danger-audit");

	const clean = guard.handleReport({
		agent: "claude-code",
		command: "ls -la",
	});
	assert.equal(clean.verdict, "allow");
	assert.equal(clean.rule_id, null);

	assert.equal(guard.reportsThisRun, 4);
	const denyEntry = entries.find((e) => e.rule_id === "danger-interrupt");
	assert.equal(denyEntry.source, "harness:claude-code");
	assert.equal(denyEntry.decision, "advise-deny");
	assert.equal(denyEntry.interrupt_request, "not-requested");
	assert.equal(denyEntry.prevention, "unknown");
	assert.equal(denyEntry.tool, "Bash");
	assert.equal(denyEntry.session_id, "s1");
	assert.equal(
		entries.find((e) => e.rule_id === "danger-alert").decision,
		"advise-warn",
	);
	assert.equal(
		entries.find((e) => e.rule_id === "danger-audit").decision,
		"log-only",
	);
	// alert and interrupt notify (coalesced per rule); audit/clean do not.
	assert.equal(notifications.length, 2);
});

test("handleReport rejects malformed reports and multi-line commands use the worst line", () => {
	const { guard } = makeGuard();
	assert.equal(guard.handleReport(null).ok, false);
	assert.equal(guard.handleReport({}).ok, false);
	assert.equal(guard.handleReport({ command: 42 }).ok, false);

	const verdict = guard.handleReport({
		agent: "claude-code",
		command: "echo starting\nnpm publish\nrm -rf /",
	});
	assert.equal(verdict.verdict, "deny");
	assert.equal(verdict.rule_id, "danger-interrupt");
});

test("paused enforcement allows but still audits harness reports", () => {
	const { guard, entries, notifications } = makeGuard({
		enforcement: "paused",
		pausedUntil: 999_999,
	});
	const verdict = guard.handleReport({
		agent: "claude-code",
		command: "rm -rf /",
	});
	assert.equal(verdict.verdict, "allow");
	assert.equal(verdict.enforcement, "paused");
	assert.equal(verdict.rule_id, "danger-interrupt");
	assert.equal(entries[0].decision, "log-only-enforcement-paused");
	assert.equal(notifications.length, 0);
});

test("handleReport applies project overrides from the reported cwd", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-report-override-"));
	fs.writeFileSync(
		path.join(dir, ".herdr-guard.json"),
		JSON.stringify({
			rules: [
				{
					id: "project-secret-tool",
					severity: "alert",
					match: "substring",
					pattern: "deploy-prod.sh",
					reason: "project deploy script",
				},
			],
		}),
	);
	const { guard } = makeGuard();
	const inProject = guard.handleReport({
		agent: "claude-code",
		command: "./deploy-prod.sh",
		cwd: dir,
	});
	assert.equal(inProject.verdict, "warn");
	assert.equal(inProject.rule_id, "project-secret-tool");
	const elsewhere = guard.handleReport({
		agent: "claude-code",
		command: "./deploy-prod.sh",
	});
	assert.equal(elsewhere.verdict, "allow");
});

async function ask(socketPath, request) {
	return new Promise((resolve, reject) => {
		const socket = net.connect(socketPath);
		let buffer = "";
		socket.on("error", reject);
		socket.on("connect", () => socket.write(`${JSON.stringify(request)}\n`));
		socket.on("data", (chunk) => {
			buffer += chunk.toString("utf8");
			const newline = buffer.indexOf("\n");
			if (newline === -1) return;
			socket.destroy();
			resolve(JSON.parse(buffer.slice(0, newline)));
		});
	});
}

test("ReporterServer serves verdicts over the unix socket and reclaims stale files", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-reporter-"));
	const socketPath = path.join(dir, "reporter.sock");
	// A leftover non-listening file must be reclaimed, not fatal.
	fs.writeFileSync(socketPath, "");
	assert.equal(await probeSocket(socketPath), "stale");

	const { guard } = makeGuard();
	const server = new ReporterServer({
		socketPath,
		handleReport: (report) => guard.handleReport(report),
	});
	await server.start();
	try {
		assert.equal(await probeSocket(socketPath), "live");
		const verdict = await ask(socketPath, {
			agent: "pi",
			command: "rm -rf /",
		});
		assert.equal(verdict.verdict, "deny");

		const malformed = await new Promise((resolve, reject) => {
			const socket = net.connect(socketPath);
			let buffer = "";
			socket.on("error", reject);
			socket.on("connect", () => socket.write("not json\n"));
			socket.on("data", (chunk) => {
				buffer += chunk.toString("utf8");
				if (buffer.includes("\n")) {
					socket.destroy();
					resolve(JSON.parse(buffer.slice(0, buffer.indexOf("\n"))));
				}
			});
		});
		assert.equal(malformed.ok, false);

		// A second guard must refuse to fight over a live socket — and its
		// shutdown must NOT delete the surviving guard's socket or lock.
		const second = new ReporterServer({
			socketPath,
			handleReport: () => ({ ok: true, verdict: "allow" }),
		});
		await assert.rejects(() => second.start(), /already serving/);
		second.close();
		assert.equal(await probeSocket(socketPath), "live");
		const stillWorks = await ask(socketPath, {
			agent: "pi",
			command: "rm -rf /",
		});
		assert.equal(stillWorks.verdict, "deny");
	} finally {
		server.close();
	}
	assert.equal(fs.existsSync(socketPath), false);
	assert.equal(fs.existsSync(`${socketPath}.lock`), false);
});

test("ReporterServer reclaims a lock left by a dead process but honors a live one", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-reporter-lock-"));
	const socketPath = path.join(dir, "reporter.sock");
	// A crashed guard leaves a lock naming a pid that no longer exists.
	fs.writeFileSync(`${socketPath}.lock`, "999999999");
	const server = new ReporterServer({
		socketPath,
		handleReport: () => ({ ok: true, verdict: "allow" }),
	});
	await server.start();
	try {
		assert.equal(await probeSocket(socketPath), "live");
		// A lock naming a live pid (ours) blocks a would-be claimant even if
		// its socket probe raced to "stale".
		const contender = new ReporterServer({
			socketPath: path.join(dir, "other.sock"),
			handleReport: () => ({ ok: true, verdict: "allow" }),
		});
		fs.writeFileSync(`${contender.socketPath}.lock`, String(process.pid));
		await assert.rejects(() => contender.start(), /holds/);
	} finally {
		server.close();
	}
});

function runHook(input, env = {}) {
	return new Promise((resolve) => {
		const child = spawn(process.execPath, [HOOK_PATH], {
			env: { ...process.env, ...env },
			stdio: ["pipe", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => {
			stdout += chunk;
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
		});
		child.on("close", (code) => resolve({ code, stdout, stderr }));
		child.stdin.write(JSON.stringify(input));
		child.stdin.end();
	});
}

test("claude-code hook denies interrupt-tier commands and asks on alert-tier", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-hook-"));
	const socketPath = path.join(dir, "reporter.sock");
	const { guard } = makeGuard();
	const server = new ReporterServer({
		socketPath,
		handleReport: (report) => guard.handleReport(report),
	});
	await server.start();
	try {
		const deny = await runHook(
			{
				tool_name: "Bash",
				tool_input: { command: "rm -rf /" },
				cwd: "/tmp",
				session_id: "s1",
			},
			{ HERDR_GUARD_REPORTER_SOCKET: socketPath },
		);
		assert.equal(deny.code, 0);
		const denyOut = JSON.parse(deny.stdout);
		assert.equal(denyOut.hookSpecificOutput.permissionDecision, "deny");
		assert.match(
			denyOut.hookSpecificOutput.permissionDecisionReason,
			/herdr-guard: recursive delete at root \(rule danger-interrupt\)/,
		);

		const warn = await runHook(
			{ tool_name: "Bash", tool_input: { command: "npm publish" } },
			{ HERDR_GUARD_REPORTER_SOCKET: socketPath },
		);
		const warnOut = JSON.parse(warn.stdout);
		assert.equal(warnOut.hookSpecificOutput.permissionDecision, "ask");

		const clean = await runHook(
			{ tool_name: "Bash", tool_input: { command: "ls" } },
			{ HERDR_GUARD_REPORTER_SOCKET: socketPath },
		);
		assert.equal(clean.stdout, "");
		assert.equal(clean.code, 0);
	} finally {
		server.close();
	}
});

test("claude-code hook fails open when the guard is unreachable or input is odd", async () => {
	const missing = path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), "guard-hook-missing-")),
		"absent.sock",
	);
	const down = await runHook(
		{ tool_name: "Bash", tool_input: { command: "rm -rf /" } },
		{ HERDR_GUARD_REPORTER_SOCKET: missing },
	);
	assert.equal(down.code, 0);
	assert.equal(down.stdout, "");

	const notBash = await runHook(
		{ tool_name: "Read", tool_input: { file_path: "/etc/hosts" } },
		{ HERDR_GUARD_REPORTER_SOCKET: missing },
	);
	assert.equal(notBash.code, 0);
	assert.equal(notBash.stdout, "");
});

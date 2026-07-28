import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { ConfigStore, scanText } from "./policy.mjs";
import { HerdrSocket } from "./herdr-socket.mjs";
import { AuditLog } from "./audit.mjs";
import { ensureGuardSessionStateDir } from "./session-state.mjs";
const root =
	process.env.HERDR_PLUGIN_ROOT ??
	path.resolve(new URL("..", import.meta.url).pathname);
const configDir =
	process.env.HERDR_PLUGIN_CONFIG_DIR ??
	path.join(process.env.HOME ?? ".", ".config/herdr-guard");
const stateDir =
	process.env.HERDR_PLUGIN_STATE_DIR ??
	path.join(process.env.HOME ?? ".", ".local/state/herdr-guard");
const store = () =>
	new ConfigStore({
		configDir,
		defaultsPath: path.join(root, "src/rules-default.json"),
	});
const herdr = process.env.HERDR_BIN_PATH ?? "herdr";
function runExecutable(
	executable,
	args,
	{ detached = false, timeoutCode = 124, timeoutMs = 15_000 } = {},
) {
	return new Promise((resolve) => {
		let settled = false;
		let timedOut = false;
		let killTimer = null;
		const finish = (code) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			if (killTimer) clearTimeout(killTimer);
			resolve(timedOut ? timeoutCode : code);
		};
		const child = spawn(executable, args, { detached, stdio: "inherit" });
		const signal = (name) => {
			try {
				if (detached && child.pid) process.kill(-child.pid, name);
				else child.kill(name);
			} catch {}
		};
		const timer = setTimeout(() => {
			timedOut = true;
			signal("SIGTERM");
			killTimer = setTimeout(() => signal("SIGKILL"), 2000);
		}, timeoutMs);
		child.once("error", () => finish(1));
		child.once("close", (code) => finish(code ?? 1));
	});
}
function run(args) {
	return runExecutable(herdr, args);
}
function runCapture(args) {
	return new Promise((resolve) => {
		let out = "";
		let settled = false;
		const finish = (code) => {
			if (settled) return;
			settled = true;
			resolve({ code, out });
		};
		const child = spawn(herdr, args, {
			stdio: ["ignore", "pipe", "inherit"],
		});
		child.stdout.on("data", (data) => {
			out += data;
		});
		child.once("error", () => finish(1));
		child.once("close", (code) => finish(code ?? 1));
	});
}
function sessionLockInvocation(lockPath, action) {
	const commandArgs = [process.execPath, process.argv[1], action];
	if (process.platform === "darwin")
		return {
			executable: "/usr/bin/lockf",
			args: ["-t", "35", lockPath, ...commandArgs],
		};
	if (process.platform === "linux")
		return {
			executable: "flock",
			args: ["-w", "35", lockPath, ...commandArgs],
		};
	throw new Error(`unsupported session lock platform: ${process.platform}`);
}
async function runSessionLockedAction(action) {
	const sessionStateDir = ensureGuardSessionStateDir(
		stateDir,
		process.env.HERDR_SOCKET_PATH,
	);
	const lockPath = path.join(sessionStateDir, "guard-pane.lock");
	fs.closeSync(fs.openSync(lockPath, "a", 0o600));
	fs.chmodSync(lockPath, 0o600);
	const invocation = sessionLockInvocation(lockPath, action);
	return runExecutable(invocation.executable, invocation.args, {
		detached: true,
		timeoutCode: 1,
		timeoutMs: 70_000,
	});
}
function writeWatchdogMarker(markerPath, record) {
	const tempPath = `${markerPath}.tmp-${process.pid}-${Date.now()}`;
	let descriptor = null;
	try {
		descriptor = fs.openSync(tempPath, "wx", 0o600);
		fs.writeFileSync(descriptor, JSON.stringify(record));
		fs.fsyncSync(descriptor);
		fs.closeSync(descriptor);
		descriptor = null;
		fs.renameSync(tempPath, markerPath);
		const directory = fs.openSync(path.dirname(markerPath), "r");
		try {
			fs.fsyncSync(directory);
		} finally {
			fs.closeSync(directory);
		}
	} finally {
		if (descriptor !== null) fs.closeSync(descriptor);
		fs.rmSync(tempPath, { force: true });
	}
}
function ensureState() {
	fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
	fs.chmodSync(stateDir, 0o700);
}
function seed() {
	const s = store();
	s.seedIfMissing();
	return s;
}
function configuredRuleCount(file) {
	try {
		const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
		return Array.isArray(parsed?.rules) ? parsed.rules.length : null;
	} catch {
		return null;
	}
}
function parseDurationMs(value) {
	if (!value) return 15 * 60 * 1000;
	const match = /^(\d+)([smh]?)$/.exec(value);
	if (!match) return null;
	const amount = Number(match[1]);
	const multiplier =
		match[2] === "h" ? 3_600_000 : match[2] === "m" ? 60_000 : 1_000;
	return amount > 0 ? amount * multiplier : null;
}
async function openTestPopup() {
	const socketPath = process.env.HERDR_SOCKET_PATH;
	if (!socketPath) return { ok: false, error: "HERDR_SOCKET_PATH is not set" };
	const socket = new HerdrSocket(socketPath);
	try {
		await socket.connect();
		await socket.request("plugin.pane.open", {
			plugin_id: "structupath.guard",
			entrypoint: "test",
			placement: "popup",
			focus: true,
		});
		return { ok: true };
	} catch (error) {
		return { ok: false, error: error.message };
	} finally {
		socket.close();
	}
}
const action = process.argv[2] ?? "status";
if (action === "startup")
	process.exit(await runSessionLockedAction("startup-locked"));
if (action === "startup-locked") {
	seed();
	const sessionStateDir = ensureGuardSessionStateDir(
		stateDir,
		process.env.HERDR_SOCKET_PATH,
	);
	const snapshot = await runCapture(["api", "snapshot"]);
	if (snapshot.code !== 0) process.exit(snapshot.code);
	let panes = [];
	try {
		const parsed = JSON.parse(snapshot.out);
		panes =
			parsed?.result?.snapshot?.panes ??
			parsed?.snapshot?.panes ??
			parsed?.panes ??
			[];
	} catch {
		console.error("invalid herdr snapshot response");
		process.exit(1);
	}
	let storedPaneId = null;
	try {
		storedPaneId = fs
			.readFileSync(path.join(sessionStateDir, "guard-pane.id"), "utf8")
			.trim();
	} catch {}
	const own = storedPaneId
		? panes.find((pane) => pane?.pane_id === storedPaneId)
		: null;
	if (!own) {
		const marker = path.join(sessionStateDir, "watchdog-reopen");
		const markerPaneId = storedPaneId ?? "startup";
		writeWatchdogMarker(marker, {
			pane_id: markerPaneId,
			status: "opening",
			ts: Date.now(),
		});
		const status = await run([
			"plugin",
			"pane",
			"open",
			"--plugin",
			"structupath.guard",
			"--entrypoint",
			"guard",
			"--placement",
			"split",
		]);
		if (status !== 0) {
			writeWatchdogMarker(marker, {
				pane_id: markerPaneId,
				status: "needs_attention",
				ts: Date.now(),
			});
			process.exit(status === 124 ? 1 : status);
		}
		const deadline = Date.now() + 5000;
		while (Date.now() < deadline) {
			let currentPaneId = null;
			try {
				currentPaneId = fs
					.readFileSync(path.join(sessionStateDir, "guard-pane.id"), "utf8")
					.trim();
			} catch {}
			if (currentPaneId && currentPaneId !== storedPaneId) {
				writeWatchdogMarker(marker, {
					pane_id: markerPaneId,
					status: "opened",
					ts: Date.now(),
				});
				process.exit(0);
			}
			await new Promise((resolve) => setTimeout(resolve, 25));
		}
		writeWatchdogMarker(marker, {
			pane_id: markerPaneId,
			status: "needs_attention",
			ts: Date.now(),
		});
		console.error("guard startup identity transition timed out");
		process.exit(1);
	}
	process.exit(0);
}
if (action === "watchdog")
	process.exit(await runSessionLockedAction("watchdog-locked"));
if (action === "watchdog-locked") {
	const sessionStateDir = ensureGuardSessionStateDir(
		stateDir,
		process.env.HERDR_SOCKET_PATH,
	);
	const payload = process.env.HERDR_PLUGIN_EVENT_JSON ?? "";
	let eventId = null;
	try {
		const parsed = JSON.parse(payload);
		eventId = parsed?.data?.pane_id ?? parsed?.pane_id;
	} catch {}
	if (!eventId) process.exit(0);

	let paneId = null;
	try {
		paneId = fs
			.readFileSync(path.join(sessionStateDir, "guard-pane.id"), "utf8")
			.trim();
	} catch {}
	if (!paneId || eventId !== paneId) process.exit(0);

	const marker = path.join(sessionStateDir, "watchdog-reopen");
	if (fs.existsSync(marker)) {
		let previous;
		try {
			previous = JSON.parse(fs.readFileSync(marker, "utf8"));
		} catch {
			console.error("watchdog reopen state is corrupt");
			process.exit(1);
		}
		if (previous.pane_id === paneId && previous.status === "opened")
			process.exit(0);
		if (
			previous.pane_id === paneId &&
			(previous.status === "opening" ||
				previous.status === "needs_attention")
		) {
			console.error("watchdog reopen requires manual reconciliation");
			process.exit(1);
		}
	}

	writeWatchdogMarker(marker, {
		pane_id: paneId,
		status: "opening",
		ts: Date.now(),
	});
	let status = await run([
		"plugin",
		"pane",
		"open",
		"--plugin",
		"structupath.guard",
		"--entrypoint",
		"guard",
		"--placement",
		"split",
	]);
	if (status !== 0) {
		writeWatchdogMarker(marker, {
			pane_id: paneId,
			status: "needs_attention",
			ts: Date.now(),
		});
		console.error("watchdog reopen failed; manual reconciliation required");
		process.exit(status === 124 ? 1 : status);
	}

	const deadline = Date.now() + 5000;
	let nextPaneId = null;
	while (Date.now() < deadline) {
		try {
			nextPaneId = fs
				.readFileSync(path.join(sessionStateDir, "guard-pane.id"), "utf8")
				.trim();
		} catch {}
		if (nextPaneId && nextPaneId !== paneId) break;
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
	if (!nextPaneId || nextPaneId === paneId) {
		writeWatchdogMarker(marker, {
			pane_id: paneId,
			status: "needs_attention",
			ts: Date.now(),
		});
		console.error("watchdog reopen identity transition timed out");
		process.exit(1);
	}
	writeWatchdogMarker(marker, {
		pane_id: paneId,
		status: "opened",
		ts: Date.now(),
	});
	status = await run([
		"notification",
		"show",
		"herdr-guard",
		"--body",
		"Guard pane exited; reopened it.",
	]);
	process.exit(status);
}
if (action === "open")
	process.exit(
		await run([
			"plugin",
			"pane",
			"open",
			"--plugin",
			"structupath.guard",
			"--entrypoint",
			"guard",
			"--placement",
			"split",
			"--focus",
		]),
	);
const s = seed();
if (action === "pause" || action === "resume") {
	const loaded = s.load();
	if (!loaded.config || loaded.error) {
		console.error(loaded.error ?? "no valid configuration");
		process.exit(1);
	}
	const ttlMs = action === "pause" ? parseDurationMs(process.argv[3]) : null;
	if (action === "pause" && ttlMs === null) {
		console.error(
			"pause TTL must be seconds or use s/m/h, for example 300 or 5m",
		);
		process.exit(2);
	}
	const until = action === "pause" ? Date.now() + ttlMs : null;
	const result = s.setEnforcement(action === "pause" ? "paused" : "active", {
		pausedUntil: until,
	});
	if (result.error) {
		console.error(result.error);
		process.exit(1);
	}
	ensureState();
	new AuditLog(stateDir).write({
		ts: Date.now(),
		action_taken:
			action === "pause" ? "enforcement-paused" : "enforcement-resumed",
		source: "command",
		note:
			action === "pause"
				? `manual pause until ${new Date(until).toISOString()}`
				: "manual resume",
	});
	await run([
		"notification",
		"show",
		"herdr-guard",
		"--body",
		`enforcement ${action === "pause" ? "paused" : "resumed"}`,
	]);
	console.log(
		`${action}: enforcement ${action === "pause" ? "paused" : "active"}`,
	);
	process.exit(0);
}
if (action === "reset-rules") {
	const previousRuleCount = configuredRuleCount(s.file);
	let backupCreated = false;
	if (fs.existsSync(s.file)) {
		const backup = `${s.file}.backup-${Date.now()}`;
		fs.copyFileSync(s.file, backup);
		fs.chmodSync(backup, 0o600);
		backupCreated = true;
	}
	fs.rmSync(s.file, { force: true });
	s.seedIfMissing();
	const nextRuleCount = configuredRuleCount(s.file);
	const count = (value) => (value === null ? "unknown" : String(value));
	const note =
		`rules ${count(previousRuleCount)} -> ${count(nextRuleCount)}; ` +
		`backup ${backupCreated ? "created" : "not-needed"}`;
	ensureState();
	new AuditLog(stateDir).write({
		ts: Date.now(),
		action_taken: "rules-reset",
		source: "command",
		note,
	});
	await run([
		"notification",
		"show",
		"herdr-guard",
		"--body",
		`guard rules reset: ${note}`,
	]);
	console.log(`rules reset in ${s.file}`);
	process.exit(0);
}
if (action === "test") {
	const input = process.argv.slice(3).join(" ");
	if (!input) {
		const result = await openTestPopup();
		if (!result.ok) {
			console.error(result.error);
			process.exit(1);
		}
		process.exit(0);
	}
	const loaded = s.load();
	for (const match of scanText(`$ ${input}`, loaded.config?.rules ?? []))
		console.log(
			`${match.rule.severity}\t${match.rule.id}\t${match.rule.reason}`,
		);
	process.exit(0);
}
console.error(`unknown action: ${action}`);
process.exit(2);

import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { ConfigStore, scanText } from "./policy.mjs";
import { HerdrSocket } from "./herdr-socket.mjs";
import { AuditLog } from "./audit.mjs";
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
function run(args) {
	return new Promise((resolve) => {
		const p = spawn(herdr, args, { stdio: "inherit" });
		p.on("close", (code) => resolve(code ?? 1));
	});
}
function runCapture(args) {
	return new Promise((resolve) => {
		const p = spawn(herdr, args, { stdio: ["ignore", "pipe", "inherit"] });
		let out = "";
		p.stdout.on("data", (d) => {
			out += d;
		});
		p.on("close", (code) => resolve({ code: code ?? 1, out }));
	});
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
if (action === "startup") {
	seed();
	ensureState();
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
			.readFileSync(path.join(stateDir, "guard-pane.id"), "utf8")
			.trim();
	} catch {}
	const own = storedPaneId
		? panes.find((pane) => pane?.pane_id === storedPaneId)
		: null;
	if (!own)
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
			]),
		);
	process.exit(0);
}
if (action === "watchdog") {
	ensureState();
	const payload = process.env.HERDR_PLUGIN_EVENT_JSON ?? "";
	let id = null;
	try {
		id = fs.readFileSync(path.join(stateDir, "guard-pane.id"), "utf8").trim();
	} catch {}
	let eventId = null;
	try {
		const p = JSON.parse(payload);
		eventId = p?.data?.pane_id ?? p?.pane_id;
	} catch {}
	if (id && eventId === id) {
		const marker = path.join(stateDir, "watchdog-reopen");
		let recent = false;
		try {
			recent = Date.now() - Number(fs.readFileSync(marker, "utf8")) < 2000;
		} catch {}
		if (!recent) {
			fs.writeFileSync(marker, String(Date.now()), { mode: 0o600 });
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
			]);
			await run([
				"notification",
				"show",
				"herdr-guard",
				"--body",
				"Guard pane exited; reopened it.",
			]);
		}
	}
	process.exit(0);
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
	if (fs.existsSync(s.file)) {
		const backup = `${s.file}.backup-${Date.now()}`;
		fs.copyFileSync(s.file, backup);
		fs.chmodSync(backup, 0o600);
	}
	fs.rmSync(s.file, { force: true });
	s.seedIfMissing();
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

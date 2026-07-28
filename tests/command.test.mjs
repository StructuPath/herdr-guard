import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
	guardSessionStateDir,
	recordGuardPaneId,
} from "../src/session-state.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const command = path.join(root, "src", "command.mjs");
const watcher = path.join(root, "src", "watcher.mjs");

function fixture() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "herdr-guard-command-"));
	const configDir = path.join(dir, "config");
	const stateDir = path.join(dir, "state");
	const log = path.join(dir, "herdr.log");
	const fake = path.join(dir, "herdr-fake.mjs");
	fs.writeFileSync(
		fake,
		`#!/usr/bin/env node\nimport fs from "node:fs";\nconst args=process.argv.slice(2);\nfs.appendFileSync(process.env.FAKE_HERDR_LOG, JSON.stringify(args)+"\\n");\nif(process.env.FAKE_OPEN_PANE_ID_PATH&&args[0]==="plugin") fs.writeFileSync(process.env.FAKE_OPEN_PANE_ID_PATH,process.env.FAKE_OPEN_PANE_ID);
if(process.env.FAKE_IGNORE_SIGTERM) process.on("SIGTERM",()=>{});
if(process.env.FAKE_PLUGIN_DELAY_MS&&args[0]==="plugin") await new Promise(resolve=>setTimeout(resolve,Number(process.env.FAKE_PLUGIN_DELAY_MS)));
if(process.env.FAKE_NOTIFICATION_DELAY_MS&&args[0]==="notification") await new Promise(resolve=>setTimeout(resolve,Number(process.env.FAKE_NOTIFICATION_DELAY_MS)));
if(process.env.FAKE_PLUGIN_EXIT&&args[0]==="plugin") process.exit(Number(process.env.FAKE_PLUGIN_EXIT));
if(args[0]==="api"&&args[1]==="snapshot") console.log(process.env.FAKE_SNAPSHOT);\n`,
		{ mode: 0o700 },
	);
	const env = {
		...process.env,
		HERDR_BIN_PATH: fake,
		HERDR_PLUGIN_ROOT: root,
		HERDR_PLUGIN_CONFIG_DIR: configDir,
		HERDR_PLUGIN_STATE_DIR: stateDir,
		HERDR_SOCKET_PATH: path.join(dir, "default.sock"),
		FAKE_HERDR_LOG: log,
		FAKE_SNAPSHOT: JSON.stringify({
			id: "snapshot",
			result: { type: "session_snapshot", snapshot: { panes: [] } },
		}),
	};
	return { dir, configDir, stateDir, log, env };
}

function runCommand(args, env) {
	return spawnSync(process.execPath, [command, ...args], {
		env,
		encoding: "utf8",
	});
}
function runCommandAsync(args, env) {
	return new Promise((resolve) => {
		const child = spawn(process.execPath, [command, ...args], {
			env,
			stdio: "ignore",
		});
		child.once("error", () => resolve(1));
		child.once("close", (code) => resolve(code ?? 1));
	});
}

function calls(log) {
	if (!fs.existsSync(log)) return [];
	return fs
		.readFileSync(log, "utf8")
		.trim()
		.split("\n")
		.filter(Boolean)
		.map(JSON.parse);
}

test("startup opens once when stored guard pane is absent and skips when present", () => {
	const f = fixture();
	const sessionStateDir = guardSessionStateDir(
		f.stateDir,
		f.env.HERDR_SOCKET_PATH,
	);
	const paneIdPath = path.join(sessionStateDir, "guard-pane.id");
	const startupEnv = {
		...f.env,
		FAKE_OPEN_PANE_ID: "p1",
		FAKE_OPEN_PANE_ID_PATH: paneIdPath,
	};
	let result = runCommand(["startup"], startupEnv);
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(calls(f.log)[0], ["api", "snapshot"]);
	assert.deepEqual(calls(f.log)[1].slice(0, 5), [
		"plugin",
		"pane",
		"open",
		"--plugin",
		"structupath.guard",
	]);

	fs.writeFileSync(f.log, "");
	const env = {
		...f.env,
		FAKE_SNAPSHOT: JSON.stringify({
			id: "snapshot",
			result: { snapshot: { panes: [{ pane_id: "p1", label: null }] } },
		}),
	};
	result = runCommand(["startup"], env);
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(calls(f.log), [["api", "snapshot"]]);
	assert.equal(
		fs.readFileSync(path.join(sessionStateDir, "guard-pane.id"), "utf8"),
		"p1",
	);
});

test("watchdog reopens only the exact guard pane and dedupes closed/exited pair", () => {
	const f = fixture();
	const sessionStateDir = guardSessionStateDir(
		f.stateDir,
		f.env.HERDR_SOCKET_PATH,
	);
	const paneIdPath = recordGuardPaneId(
		f.stateDir,
		f.env.HERDR_SOCKET_PATH,
		"p1",
	);
	const event = (paneId, nextPaneId) => ({
		...f.env,
		FAKE_OPEN_PANE_ID: nextPaneId,
		FAKE_OPEN_PANE_ID_PATH: paneIdPath,
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: paneId } }),
	});
	assert.equal(runCommand(["watchdog"], event("p1", "p2")).status, 0);
	const first = calls(f.log);
	assert.equal(first.filter((args) => args[0] === "plugin").length, 1);
	assert.equal(first.filter((args) => args[0] === "notification").length, 1);
	assert.equal(runCommand(["watchdog"], event("p1", "p2")).status, 0);
	assert.equal(calls(f.log).length, first.length);

	assert.equal(runCommand(["watchdog"], event("p2", "p3")).status, 0);
	const second = calls(f.log);
	assert.equal(second.filter((args) => args[0] === "plugin").length, 2);
	assert.equal(second.filter((args) => args[0] === "notification").length, 2);
	assert.equal(
		JSON.parse(
			fs.readFileSync(path.join(sessionStateDir, "watchdog-reopen"), "utf8"),
		).pane_id,
		"p2",
	);

	assert.equal(
		runCommand(["watchdog"], event("unrelated", "ignored")).status,
		0,
	);
	assert.equal(calls(f.log).length, second.length);
});

test("concurrent watchdog events share one kernel-locked reopen", async () => {
	const f = fixture();
	recordGuardPaneId(f.stateDir, f.env.HERDR_SOCKET_PATH, "p1");
	const env = {
		...f.env,
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p1" } }),
	};
	const runs = [
		runCommandAsync(["watchdog"], env),
		runCommandAsync(["watchdog"], env),
	];
	for (
		let attempt = 0;
		attempt < 100 &&
		calls(f.log).filter((args) => args[0] === "plugin").length === 0;
		attempt++
	)
		await new Promise((resolve) => setTimeout(resolve, 20));
	await new Promise((resolve) => setTimeout(resolve, 100));
	recordGuardPaneId(f.stateDir, f.env.HERDR_SOCKET_PATH, "p2");
	assert.deepEqual(await Promise.all(runs), [0, 0]);
	assert.equal(calls(f.log).filter((args) => args[0] === "plugin").length, 1);
	assert.equal(calls(f.log).filter((args) => args[0] === "notification").length, 1);
});

test("next-generation event waits for the prior notification lock", async () => {
	const f = fixture();
	const paneIdPath = recordGuardPaneId(
		f.stateDir,
		f.env.HERDR_SOCKET_PATH,
		"p1",
	);
	const first = runCommandAsync(["watchdog"], {
		...f.env,
		FAKE_NOTIFICATION_DELAY_MS: "2500",
		FAKE_OPEN_PANE_ID: "p2",
		FAKE_OPEN_PANE_ID_PATH: paneIdPath,
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p1" } }),
	});
	for (
		let attempt = 0;
		attempt < 100 &&
		calls(f.log).filter((args) => args[0] === "notification").length === 0;
		attempt++
	)
		await new Promise((resolve) => setTimeout(resolve, 20));
	const second = runCommandAsync(["watchdog"], {
		...f.env,
		FAKE_OPEN_PANE_ID: "p3",
		FAKE_OPEN_PANE_ID_PATH: paneIdPath,
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p2" } }),
	});
	await new Promise((resolve) => setTimeout(resolve, 300));
	assert.equal(calls(f.log).filter((args) => args[0] === "plugin").length, 1);
	assert.deepEqual(await Promise.all([first, second]), [0, 0]);
	assert.equal(calls(f.log).filter((args) => args[0] === "plugin").length, 2);
	assert.equal(calls(f.log).filter((args) => args[0] === "notification").length, 2);
});

test("startup and watchdog serialize and recheck pane identity", async () => {
	const f = fixture();
	const paneIdPath = recordGuardPaneId(
		f.stateDir,
		f.env.HERDR_SOCKET_PATH,
		"p1",
	);
	const env = { ...f.env };
	const startup = runCommandAsync(["startup"], env);
	for (
		let attempt = 0;
		attempt < 100 &&
		calls(f.log).filter((args) => args[0] === "plugin").length === 0;
		attempt++
	)
		await new Promise((resolve) => setTimeout(resolve, 20));
	const watchdog = runCommandAsync(["watchdog"], {
		...env,
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p1" } }),
	});
	await new Promise((resolve) => setTimeout(resolve, 100));
	recordGuardPaneId(f.stateDir, f.env.HERDR_SOCKET_PATH, "p2");
	assert.deepEqual(await Promise.all([startup, watchdog]), [0, 0]);
	assert.equal(calls(f.log).filter((args) => args[0] === "plugin").length, 1);
	assert.equal(fs.readFileSync(paneIdPath, "utf8"), "p2");
});

test("owner death after reopen intent requires manual reconciliation", async () => {
	const f = fixture();
	recordGuardPaneId(f.stateDir, f.env.HERDR_SOCKET_PATH, "p1");
	const sessionStateDir = guardSessionStateDir(
		f.stateDir,
		f.env.HERDR_SOCKET_PATH,
	);
	const lockPath = path.join(sessionStateDir, "guard-pane.lock");
	const marker = path.join(sessionStateDir, "watchdog-reopen");
	fs.closeSync(fs.openSync(lockPath, "a", 0o600));
	const eventEnv = {
		...f.env,
		FAKE_PLUGIN_DELAY_MS: "10000",
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p1" } }),
	};
	const lockedCommand = [process.execPath, command, "watchdog-locked"];
	const holder =
		process.platform === "darwin"
			? spawn("/usr/bin/lockf", ["-t", "1", lockPath, ...lockedCommand], {
					detached: true,
					env: eventEnv,
					stdio: "ignore",
				})
			: spawn("flock", ["-w", "1", lockPath, ...lockedCommand], {
					detached: true,
					env: eventEnv,
					stdio: "ignore",
				});
	const holderClosed = new Promise((resolve) => holder.once("close", resolve));
	for (
		let attempt = 0;
		attempt < 100 &&
		(!fs.existsSync(marker) ||
			JSON.parse(fs.readFileSync(marker, "utf8")).status !== "opening");
		attempt++
	)
		await new Promise((resolve) => setTimeout(resolve, 20));
	assert.equal(JSON.parse(fs.readFileSync(marker, "utf8")).status, "opening");
	for (
		let attempt = 0;
		attempt < 100 &&
		calls(f.log).filter((args) => args[0] === "plugin").length === 0;
		attempt++
	)
		await new Promise((resolve) => setTimeout(resolve, 20));
	assert.equal(calls(f.log).filter((args) => args[0] === "plugin").length, 1);
	process.kill(-holder.pid, "SIGKILL");
	await holderClosed;

	delete eventEnv.FAKE_PLUGIN_DELAY_MS;
	const result = runCommand(["watchdog"], eventEnv);
	assert.equal(result.status, 1, result.stderr);
	assert.equal(calls(f.log).filter((args) => args[0] === "plugin").length, 1);
});

test("watchdog failures require reconciliation instead of replay", () => {
	const f = fixture();
	recordGuardPaneId(f.stateDir, f.env.HERDR_SOCKET_PATH, "p1");
	const event = {
		...f.env,
		FAKE_PLUGIN_EXIT: "7",
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p1" } }),
	};
	const failed = runCommand(["watchdog"], event);
	assert.equal(failed.status, 7, failed.stderr);
	assert.equal(calls(f.log).filter((args) => args[0] === "notification").length, 0);
	const marker = path.join(
		guardSessionStateDir(f.stateDir, f.env.HERDR_SOCKET_PATH),
		"watchdog-reopen",
	);
	assert.equal(JSON.parse(fs.readFileSync(marker, "utf8")).status, "needs_attention");

	delete event.FAKE_PLUGIN_EXIT;
	assert.equal(runCommand(["watchdog"], event).status, 1);
	assert.equal(calls(f.log).filter((args) => args[0] === "plugin").length, 1);
	assert.equal(calls(f.log).filter((args) => args[0] === "notification").length, 0);

	const spawnFailure = fixture();
	recordGuardPaneId(
		spawnFailure.stateDir,
		spawnFailure.env.HERDR_SOCKET_PATH,
		"p1",
	);
	const missingBinary = runCommand(["watchdog"], {
		...spawnFailure.env,
		HERDR_BIN_PATH: path.join(spawnFailure.dir, "missing-herdr"),
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p1" } }),
	});
	assert.equal(missingBinary.status, 1, missingBinary.stderr);
	assert.equal(
		JSON.parse(
			fs.readFileSync(
				path.join(
					guardSessionStateDir(
						spawnFailure.stateDir,
						spawnFailure.env.HERDR_SOCKET_PATH,
					),
					"watchdog-reopen",
				),
				"utf8",
			),
		).status,
		"needs_attention",
	);
});

test("watchdog timeout escalates and blocks automatic replay", () => {
	const f = fixture();
	recordGuardPaneId(f.stateDir, f.env.HERDR_SOCKET_PATH, "p1");
	const event = {
		...f.env,
		FAKE_IGNORE_SIGTERM: "1",
		FAKE_PLUGIN_DELAY_MS: "20000",
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p1" } }),
	};
	const startedAt = Date.now();
	const timedOut = runCommand(["watchdog"], event);
	const elapsed = Date.now() - startedAt;
	assert.equal(timedOut.status, 1, timedOut.stderr);
	assert.ok(elapsed >= 16_500, `watchdog returned early after ${elapsed}ms`);
	assert.ok(elapsed < 20_000, `watchdog did not escalate after ${elapsed}ms`);
	const marker = path.join(
		guardSessionStateDir(f.stateDir, f.env.HERDR_SOCKET_PATH),
		"watchdog-reopen",
	);
	assert.equal(JSON.parse(fs.readFileSync(marker, "utf8")).status, "needs_attention");

	delete event.FAKE_IGNORE_SIGTERM;
	delete event.FAKE_PLUGIN_DELAY_MS;
	assert.equal(runCommand(["watchdog"], event).status, 1);
	assert.equal(calls(f.log).filter((args) => args[0] === "plugin").length, 1);
});

test("session-scoped commands fail closed without a socket identity", () => {
	const f = fixture();
	const result = runCommand(["watchdog"], {
		...f.env,
		HERDR_SOCKET_PATH: "",
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p1" } }),
	});
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /HERDR_SOCKET_PATH is not set/);
	assert.deepEqual(calls(f.log), []);
});

test("watcher publishes identity before a stalled bootstrap", async () => {
	const f = fixture();
	fs.mkdirSync(f.configDir, { recursive: true });
	fs.copyFileSync(
		path.join(root, "src", "rules-default.json"),
		path.join(f.configDir, "rules.json"),
	);
	const sockets = new Set();
	const server = net.createServer((socket) => {
		sockets.add(socket);
		socket.once("close", () => sockets.delete(socket));
	});
	await new Promise((resolve) => server.listen(f.env.HERDR_SOCKET_PATH, resolve));
	const paneIdPath = path.join(
		guardSessionStateDir(f.stateDir, f.env.HERDR_SOCKET_PATH),
		"guard-pane.id",
	);
	const child = spawn(process.execPath, [watcher], {
		env: { ...f.env, HERDR_PANE_ID: "producer-pane" },
		stdio: "ignore",
	});
	const closed = new Promise((resolve) => child.once("close", resolve));
	try {
		for (
			let attempt = 0;
			attempt < 100 && (!fs.existsSync(paneIdPath) || sockets.size === 0);
			attempt++
		)
			await new Promise((resolve) => setTimeout(resolve, 20));
		assert.equal(fs.readFileSync(paneIdPath, "utf8"), "producer-pane");
		assert.ok(sockets.size > 0, "watcher bootstrap did not stall on the socket");
		assert.equal(child.exitCode, null);
		assert.equal(fs.existsSync(path.join(f.stateDir, "guard-pane.id")), false);
	} finally {
		child.kill("SIGTERM");
		await closed;
		for (const socket of sockets) socket.destroy();
		await new Promise((resolve) => server.close(resolve));
	}

	const result = runCommand(["watchdog"], {
		...f.env,
		FAKE_OPEN_PANE_ID: "reopened-pane",
		FAKE_OPEN_PANE_ID_PATH: paneIdPath,
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({
			data: { pane_id: "producer-pane" },
		}),
	});
	assert.equal(result.status, 0, result.stderr);
	assert.equal(calls(f.log).filter((args) => args[0] === "plugin").length, 1);
});

test("watchdog pane identity and dedupe are isolated by Herdr socket", () => {
	const f = fixture();
	const namedSocket = path.join(f.dir, "sessions", "named", "herdr.sock");
	const defaultState = guardSessionStateDir(
		f.stateDir,
		f.env.HERDR_SOCKET_PATH,
	);
	const namedState = guardSessionStateDir(f.stateDir, namedSocket);
	assert.notEqual(defaultState, namedState);
	assert.match(path.basename(defaultState), /^[a-f0-9]{64}$/);
	assert.match(path.basename(namedState), /^[a-f0-9]{64}$/);
	const defaultPanePath = recordGuardPaneId(
		f.stateDir,
		f.env.HERDR_SOCKET_PATH,
		"default-pane",
	);
	const namedPanePath = recordGuardPaneId(
		f.stateDir,
		namedSocket,
		"named-pane",
	);
	assert.equal(defaultPanePath, path.join(defaultState, "guard-pane.id"));
	assert.equal(namedPanePath, path.join(namedState, "guard-pane.id"));
	const event = (socketPath, paneId, nextPaneId, paneIdPath) => ({
		...f.env,
		FAKE_OPEN_PANE_ID: nextPaneId,
		FAKE_OPEN_PANE_ID_PATH: paneIdPath,
		HERDR_SOCKET_PATH: socketPath,
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: paneId } }),
	});

	assert.equal(
		runCommand(
			["watchdog"],
			event(
				f.env.HERDR_SOCKET_PATH,
				"default-pane",
				"default-next",
				defaultPanePath,
			),
		).status,
		0,
	);
	assert.equal(
		runCommand(
			["watchdog"],
			event(namedSocket, "named-pane", "named-next", namedPanePath),
		).status,
		0,
	);
	assert.equal(
		calls(f.log).filter((args) => args[0] === "plugin").length,
		2,
	);
	assert.ok(fs.existsSync(path.join(defaultState, "watchdog-reopen")));
	assert.ok(fs.existsSync(path.join(namedState, "watchdog-reopen")));

	const before = calls(f.log).length;
	assert.equal(
		runCommand(
			["watchdog"],
			event(
				f.env.HERDR_SOCKET_PATH,
				"named-pane",
				"ignored",
				defaultPanePath,
			),
		).status,
		0,
	);
	assert.equal(
		runCommand(
			["watchdog"],
			event(namedSocket, "default-pane", "ignored", namedPanePath),
		).status,
		0,
	);
	assert.equal(calls(f.log).length, before);
});

test("pause refuses malformed config without modifying it and accepts TTL", () => {
	const f = fixture();
	fs.mkdirSync(f.configDir, { recursive: true });
	const rules = path.join(f.configDir, "rules.json");
	fs.writeFileSync(rules, "{");
	let result = runCommand(["pause", "5m"], f.env);
	assert.equal(result.status, 1);
	assert.equal(fs.readFileSync(rules, "utf8"), "{");

	fs.copyFileSync(path.join(root, "src", "rules-default.json"), rules);
	const before = Date.now();
	result = runCommand(["pause", "5m"], f.env);
	assert.equal(result.status, 0, result.stderr);
	const paused = JSON.parse(fs.readFileSync(rules, "utf8"));
	assert.equal(paused.enforcement, "paused");
	assert.ok(paused.paused_until >= before + 299_000);
	assert.ok(paused.paused_until <= Date.now() + 301_000);
	const audit = fs.readFileSync(path.join(f.stateDir, "audit.jsonl"), "utf8");
	assert.match(audit, /enforcement-paused/);
	assert.ok(
		calls(f.log).some(
			(args) =>
				args[0] === "notification" && args.includes("enforcement paused"),
		),
	);
});

test("reset-rules audits bounded counts and requests a notification", () => {
	const f = fixture();
	fs.mkdirSync(f.configDir, { recursive: true });
	const rules = path.join(f.configDir, "rules.json");
	const custom = JSON.parse(
		fs.readFileSync(path.join(root, "src", "rules-default.json"), "utf8"),
	);
	custom.rules = custom.rules.slice(0, 2);
	fs.writeFileSync(rules, JSON.stringify(custom), { mode: 0o600 });

	const result = runCommand(["reset-rules"], f.env);
	assert.equal(result.status, 0, result.stderr);
	const defaults = JSON.parse(
		fs.readFileSync(path.join(root, "src", "rules-default.json"), "utf8"),
	);
	assert.equal(JSON.parse(fs.readFileSync(rules, "utf8")).rules.length, defaults.rules.length);
	const backups = fs
		.readdirSync(f.configDir)
		.filter((name) => name.startsWith("rules.json.backup-"));
	assert.equal(backups.length, 1);
	const audit = fs
		.readFileSync(path.join(f.stateDir, "audit.jsonl"), "utf8")
		.trim()
		.split("\n")
		.map(JSON.parse);
	assert.equal(audit.at(-1).action_taken, "rules-reset");
	assert.match(audit.at(-1).note, new RegExp(`rules 2 -> ${defaults.rules.length}`));
	assert.ok(
		calls(f.log).some(
			(args) =>
				args[0] === "notification" &&
				args.includes("herdr-guard") &&
				args.some((arg) => arg.includes("guard rules reset")),
		),
	);
});

test("test action without text requests the declared popup pane", async () => {
	const f = fixture();
	const target = path.join(f.dir, "herdr.sock");
	let request;
	const server = net.createServer((connection) => {
		let buffer = "";
		connection.setEncoding("utf8");
		connection.on("data", (chunk) => {
			buffer += chunk;
			const index = buffer.indexOf("\n");
			if (index < 0) return;
			request = JSON.parse(buffer.slice(0, index));
			connection.write(
				`${JSON.stringify({ id: request.id, result: { type: "ok" } })}\n`,
			);
		});
	});
	await new Promise((resolve) => server.listen(target, resolve));
	const child = spawn(process.execPath, [command, "test"], {
		env: { ...f.env, HERDR_SOCKET_PATH: target },
		stdio: "ignore",
	});
	const status = await new Promise((resolve) => child.on("close", resolve));
	assert.equal(status, 0);
	assert.equal(request.method, "plugin.pane.open");
	assert.deepEqual(request.params, {
		plugin_id: "structupath.guard",
		entrypoint: "test",
		placement: "popup",
		focus: true,
	});
	await new Promise((resolve) => server.close(resolve));
});

test("manifest declares required lifecycle and executable entrypoints", () => {
	const manifest = fs.readFileSync(
		path.join(root, "herdr-plugin.toml"),
		"utf8",
	);
	assert.match(manifest, /min_herdr_version = "0\.7\.5"/);
	for (const value of [
		'id = "open"',
		'id = "pause"',
		'id = "resume"',
		'id = "test"',
		'id = "reset-rules"',
		'id = "guard"',
		'on = "pane.closed"',
		'on = "pane.exited"',
	])
		assert.match(
			manifest,
			new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
		);
	for (const script of fs.readdirSync(path.join(root, "scripts"))) {
		assert.ok(
			fs.statSync(path.join(root, "scripts", script)).mode & 0o100,
			script,
		);
	}
});

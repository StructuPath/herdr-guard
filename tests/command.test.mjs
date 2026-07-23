import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const command = path.join(root, "src", "command.mjs");

function fixture() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "herdr-guard-command-"));
	const configDir = path.join(dir, "config");
	const stateDir = path.join(dir, "state");
	const log = path.join(dir, "herdr.log");
	const fake = path.join(dir, "herdr-fake.mjs");
	fs.writeFileSync(
		fake,
		`#!/usr/bin/env node\nimport fs from "node:fs";\nconst args=process.argv.slice(2);\nfs.appendFileSync(process.env.FAKE_HERDR_LOG, JSON.stringify(args)+"\\n");\nif(args[0]==="api"&&args[1]==="snapshot") console.log(process.env.FAKE_SNAPSHOT);\n`,
		{ mode: 0o700 },
	);
	const env = {
		...process.env,
		HERDR_BIN_PATH: fake,
		HERDR_PLUGIN_ROOT: root,
		HERDR_PLUGIN_CONFIG_DIR: configDir,
		HERDR_PLUGIN_STATE_DIR: stateDir,
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
	let result = runCommand(["startup"], f.env);
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(calls(f.log)[0], ["api", "snapshot"]);
	assert.deepEqual(calls(f.log)[1].slice(0, 5), [
		"plugin",
		"pane",
		"open",
		"--plugin",
		"structupath.guard",
	]);

	fs.mkdirSync(f.stateDir, { recursive: true });
	fs.writeFileSync(path.join(f.stateDir, "guard-pane.id"), "p1\n");
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
		fs.readFileSync(path.join(f.stateDir, "guard-pane.id"), "utf8"),
		"p1\n",
	);
});

test("watchdog reopens only the exact guard pane and dedupes closed/exited pair", () => {
	const f = fixture();
	fs.mkdirSync(f.stateDir, { recursive: true });
	fs.writeFileSync(path.join(f.stateDir, "guard-pane.id"), "p1\n");
	const exact = {
		...f.env,
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p1" } }),
	};
	assert.equal(runCommand(["watchdog"], exact).status, 0);
	const first = calls(f.log);
	assert.equal(first.filter((args) => args[0] === "plugin").length, 1);
	assert.equal(first.filter((args) => args[0] === "notification").length, 1);
	assert.equal(runCommand(["watchdog"], exact).status, 0);
	assert.equal(calls(f.log).length, first.length);

	const unrelated = {
		...f.env,
		HERDR_PLUGIN_EVENT_JSON: JSON.stringify({ data: { pane_id: "p2" } }),
	};
	assert.equal(runCommand(["watchdog"], unrelated).status, 0);
	assert.equal(calls(f.log).length, first.length);
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

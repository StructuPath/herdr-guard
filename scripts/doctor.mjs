#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { parseManifest } from "./check-manifest.mjs";

export function versionAtLeast(actual, minimum) {
	const parse = (value) =>
		/^(?:v|herdr\s+)?(\d+)\.(\d+)(?:\.(\d+))?(?:\s.*)?$/.exec(value.trim());
	const have = parse(actual);
	const need = parse(minimum);
	if (!have || !need) return false;
	for (let i = 1; i <= 3; i += 1) {
		const difference = Number(have[i] ?? 0) - Number(need[i] ?? 0);
		if (difference !== 0) return difference > 0;
	}
	return true;
}

function main() {
	const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
	const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
	let failed = false;
	const report = (ok, message) => {
		console.log(`${ok ? "PASS" : "FAIL"} ${message}`);
		if (!ok) failed = true;
	};
	report(
		versionAtLeast(process.version, pkg.engines.node.replace(/^>=/, "")),
		`Node ${process.version}; requires ${pkg.engines.node}`,
	);
	report(
		["darwin", "linux"].includes(process.platform),
		`Platform ${process.platform}; supports macOS and Linux`,
	);
	const lock = process.platform === "darwin" ? "/usr/bin/lockf" : "flock";
	const lockCheck = spawnSync("/bin/sh", [
		"-c", 'command -v "$1" >/dev/null', "doctor", lock,
	]);
	report(!lockCheck.error && lockCheck.status === 0, `Lock utility ${lock}`);
	try {
		const manifest = parseManifest(path.join(root, "herdr-plugin.toml"));
		report(true, "Python 3.11+ TOML parser available");
		const herdr = process.env.HERDR_BIN_PATH || "herdr";
		const result = spawnSync(herdr, ["--version"], {
			encoding: "utf8",
			timeout: 5000,
		});
		const version = result.stdout?.trim() || "unavailable";
		report(
			!result.error && result.status === 0 && versionAtLeast(version, manifest.min_herdr_version),
			`${version}; requires Herdr >=${manifest.min_herdr_version} (HERDR_BIN_PATH or PATH)`,
		);
	} catch (error) {
		report(false, error.message);
	}
	console.log(
		"Read-only checks only; run npm run validate for source checks and tests. No panes, hooks, or policy files changed.",
	);
	process.exitCode = failed ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
	main();

#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let checked = 0;
for (const directory of ["src", "scripts", "hooks", "tests"]) {
	for (const name of fs.readdirSync(path.join(root, directory)).sort()) {
		const file = path.join(root, directory, name);
		if (!fs.statSync(file).isFile()) continue;
		const command = name.endsWith(".mjs")
			? [process.execPath, ["--check", file]]
			: name.endsWith(".sh") ? ["bash", ["-n", file]] : null;
		if (!command) continue;
		const result = spawnSync(command[0], command[1], { stdio: "inherit" });
		if (result.error || result.status !== 0) {
			console.error(`Syntax check failed: ${directory}/${name}${result.error ? `: ${result.error.message}` : ""}`);
			process.exit(1);
		}
		checked += 1;
	}
}
console.log(`Syntax valid: ${checked} JavaScript and shell files.`);

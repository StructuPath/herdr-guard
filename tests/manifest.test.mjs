import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateRepository } from "../scripts/check-manifest.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fixture() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "herdr-guard-manifest-"));
	fs.mkdirSync(path.join(dir, "scripts"));
	fs.writeFileSync(
		path.join(dir, "package.json"),
		JSON.stringify({ version: "1.2.3" }),
	);
	fs.writeFileSync(
		path.join(dir, "herdr-plugin.toml"),
		'version = "1.2.3"\n[[actions]]\nid = "open"\ncommand = ["bash", "scripts/open.sh"]\n',
	);
	fs.writeFileSync(path.join(dir, "scripts", "open.sh"), "#!/bin/sh\n", {
		mode: 0o755,
	});
	return dir;
}

test("repository manifest passes CI validation", () => {
	assert.deepEqual(validateRepository(root).errors, []);
});

test("manifest validation reports version, entrypoint, and executable-bit failures", () => {
	const dir = fixture();
	fs.writeFileSync(
		path.join(dir, "package.json"),
		JSON.stringify({ version: "9.9.9" }),
	);
	fs.rmSync(path.join(dir, "scripts", "open.sh"));
	fs.writeFileSync(path.join(dir, "scripts", "other.sh"), "#!/bin/sh\n", {
		mode: 0o644,
	});

	const { errors } = validateRepository(dir);
	assert.ok(errors.some((error) => error.startsWith("version mismatch:")));
	assert.ok(
		errors.some((error) => error.includes("entrypoint does not exist")),
	);
	assert.ok(errors.some((error) => error.includes("script is not executable")));
});

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demo = path.join(root, "scripts", "demo.sh");
const ANSI_RE = /\x1b\[[0-?]*[ -/]*[@-~]/g;

function runDemo(command) {
	const result = spawnSync("bash", [demo, command], {
		cwd: root,
		encoding: "utf8",
	});
	assert.equal(result.status, 0, result.stderr);
	return result.stdout.replace(ANSI_RE, "");
}

function assertTruthfulVocabulary(output) {
	assert.match(output, /Interrupt request\s+not-requested/);
	assert.match(output, /Prevention\s+unknown/);
	assert.doesNotMatch(output, /cancel(?:led|ed)|prevented/i);
	assert.doesNotMatch(output, /Audit\s+Written/i);
}

test("interrupt demo describes a request dry-run without claiming prevention", () => {
	const output = runDemo("rm -rf /");
	assert.match(output, /INTERRUPT/);
	assert.match(output, /Decision\s+request-interrupt/);
	assert.match(output, /runtime records accepted or failed/);
	assert.match(output, /would request Ctrl\+C in a classified shell/i);
	assert.match(output, /prevention is not observed/i);
	assert.match(output, /Audit\s+Would write/);
	assertTruthfulVocabulary(output);
});

test("alert demo describes notification request only", () => {
	const output = runDemo("npm publish");
	assert.match(output, /ALERT/);
	assert.match(output, /Decision\s+request-notification/);
	assert.match(output, /would not request Ctrl\+C/i);
	assertTruthfulVocabulary(output);
});

test("audit demo describes logging only", () => {
	const output = runDemo("git clean -f scratch.txt");
	assert.match(output, /AUDIT/);
	assert.match(output, /Decision\s+log-only/);
	assert.match(output, /would log this match only/i);
	assertTruthfulVocabulary(output);
});

test("unmatched demo is explicit and makes no safety claim", () => {
	const output = runDemo("printf hello");
	assert.match(output, /NO MATCH/);
	assert.match(output, /Decision\s+none/);
	assert.match(output, /No match audit would be written/);
	assert.match(output, /makes no safety claim/i);
	assertTruthfulVocabulary(output);
});

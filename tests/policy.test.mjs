import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AuditLog } from "../src/audit.mjs";
import defaultRules from "../src/rules-default.json" with { type: "json" };
import {
	ConfigStore,
	Dedupe,
	RateLimiter,
	buildCombinedPattern,
	compileRule,
	mergeProjectOverride,
	scanText,
	sanitizeString,
	redactSecrets,
} from "../src/policy.mjs";

const dangerous = () => "rm -rf /";
const rule = (extra = {}) => ({
	id: "danger",
	severity: "interrupt",
	match: "substring",
	pattern: dangerous(),
	reason: "danger",
	...extra,
});

test("default interrupt and sudo rules match canonical end-of-line commands", () => {
	const rules = defaultRules.rules.map((item) => compileRule(item));
	for (const line of ["$ sudo rm", "❯ sudo rm", "% sudo rm", "╰─ sudo rm"]) {
		assert.equal(scanText(line, rules).length, 1, line);
	}
	for (const line of [
		"$ terraform destroy",
		"$ kubectl delete pod --all",
		"$ kubectl --context=prod delete pod",
		"$ rm -r -f /",
		"$ rm -f -r /",
	]) {
		assert.equal(scanText(line, rules).at(0)?.rule.severity, "interrupt", line);
	}
});

test("audit tail includes rotated generations", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-"));
	const log = new AuditLog(dir);
	for (const [i, suffix] of enumerate(["", ".1", ".2", ".3"]))
		fs.writeFileSync(
			path.join(dir, `audit.jsonl${suffix}`),
			JSON.stringify({ ts: i + 1, note: `g${i}` }) + "\n",
		);
	assert.deepEqual(
		log.tail(4).map((x) => x.note),
		["g0", "g1", "g2", "g3"],
	);
});

function* enumerate(values) {
	let i = 0;
	for (const value of values) yield [i++, value];
}

test("prompt-only matching and combined patterns", () => {
	const compiled = [compileRule(rule())];
	assert.equal(scanText(`output ${dangerous()}`, compiled).length, 0);
	assert.equal(scanText(`$ ${dangerous()}`, compiled).length, 1);
	assert.match(
		buildCombinedPattern([
			compileRule(rule({ match: "regex", pattern: "npm\\s+publish" })),
		]),
		/npm/,
	);
});

test("project overrides stay substring-only and cap severity", () => {
	const base = [compileRule(rule({ severity: "alert" }))];
	const result = mergeProjectOverride(
		base,
		{
			rules: [
				{
					id: "local",
					severity: "interrupt",
					match: "substring",
					pattern: "wipe",
					reason: "local",
				},
				{
					id: "regex-local",
					severity: "alert",
					match: "regex",
					pattern: "wipe.*all",
					reason: "regex",
				},
			],
			raise: { danger: "interrupt" },
		},
		{ allowProjectOverride: true },
	);
	assert.equal(result.rules.find((r) => r.id === "danger").severity, "alert");
	assert.equal(result.rules.find((r) => r.id === "local").severity, "alert");
	assert.equal(
		result.rules.some((r) => r.id === "regex-local"),
		false,
	);
	assert.ok(result.rejected.some((entry) => entry.rule === "regex-local"));
	assert.ok(result.rejected.some((entry) => entry.rule === "danger"));
});

test("dedupe never suppresses interrupts and rate limits", () => {
	const d = new Dedupe({ windowMs: 100 });
	assert.equal(d.seen("p", "x", "a", "interrupt", 1), false);
	assert.equal(d.seen("p", "x", "a", "interrupt", 2), false);
	assert.equal(d.seen("p", "x", "a", "alert", 1), false);
	assert.equal(d.seen("p", "x", "a", "alert", 2), true);
	const r = new RateLimiter({ maxPerMinute: 2, windowMs: 100 });
	assert.equal(r.allow("p", 1), true);
	assert.equal(r.allow("p", 2), true);
	assert.equal(r.allow("p", 3), false);
	r.suppress("p", "danger", 3);
	assert.equal(r.flushCoalesced(50).length, 0);
	assert.equal(r.flushCoalesced(104).length, 1);
});

test("sanitizes controls and redacts secrets", () => {
	assert.equal(
		sanitizeString("ok\x1b]8;;https://evil\x07shown\x1b\\\n"),
		"okshown\n",
	);
	assert.match(redactSecrets("TOKEN=secret sk-abcdefghijk"), /\[REDACTED\]/);
});

test("ConfigStore keeps last good config after invalid JSON or enforcement", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-config-"));
	const defaults = path.join(dir, "defaults.json");
	fs.writeFileSync(defaults, JSON.stringify({ version: 1, rules: [rule()] }));
	const store = new ConfigStore({ configDir: dir, defaultsPath: defaults });
	const first = store.load().config;
	assert.ok(first);
	fs.writeFileSync(path.join(dir, "rules.json"), "{");
	assert.equal(store.load({ seedIfMissing: false }).config, first);
	fs.writeFileSync(
		path.join(dir, "rules.json"),
		JSON.stringify({ enforcement: "disabled", rules: [rule()] }),
	);
	const invalid = store.load({ seedIfMissing: false });
	assert.equal(invalid.config, first);
	assert.match(invalid.error, /enforcement must be active\|paused/);
});

test("audit log enforces modes, partitions, rotates, and removes secrets/control bytes", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-audit-"));
	const log = new AuditLog(dir, { maxBytes: 80, generations: 3 });
	log.write({
		ts: 1,
		severity: "interrupt",
		matched_text: `$ TOKEN=secret sk-abcdefghijk\x1b]8;;https://evil\x07${"x".repeat(300)}\x1b\\`,
		pane_id: "p",
	});
	for (let ts = 2; ts <= 8; ts++) {
		log.write({
			ts,
			severity: "alert",
			matched_text: `npm publish ${ts}`,
			pane_id: "p",
		});
	}
	assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
	for (const file of ["audit.jsonl", "audit.interrupt.jsonl"]) {
		assert.equal(fs.statSync(path.join(dir, file)).mode & 0o777, 0o600);
	}
	const interrupt = fs.readFileSync(
		path.join(dir, "audit.interrupt.jsonl"),
		"utf8",
	);
	assert.match(interrupt, /REDACTED/);
	assert.doesNotMatch(interrupt, /secret|sk-abcdefghijk|https:\/\/evil|\x1b/);
	const parsed = JSON.parse(interrupt.trim());
	assert.ok(parsed.matched_text.length <= 200);
	assert.ok(fs.existsSync(path.join(dir, "audit.jsonl.1")));
	assert.ok(log.tail(20).some((entry) => entry.severity === "interrupt"));
	assert.ok(log.tail(20).some((entry) => entry.severity === "alert"));
});

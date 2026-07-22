import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AuditLog } from "../src/audit.mjs";
import { ConfigStore, Dedupe, RateLimiter, buildCombinedPattern, compileRule, mergeProjectOverride, scanText, sanitizeString, redactSecrets } from "../src/policy.mjs";

const dangerous = () => "rm -rf /";
const rule = (extra = {}) => ({ id: "danger", severity: "interrupt", match: "substring", pattern: dangerous(), reason: "danger", ...extra });

test("prompt-only matching and combined patterns", () => {
  const compiled = [compileRule(rule())];
  assert.equal(scanText(`output ${dangerous()}`, compiled).length, 0);
  assert.equal(scanText(`$ ${dangerous()}`, compiled).length, 1);
  assert.match(buildCombinedPattern([compileRule(rule({match:"regex", pattern:"npm\\s+publish"}))]), /npm/);
});

test("project overrides add rules and cap severity", () => {
  const base = [compileRule(rule({severity:"alert"}))];
  const result = mergeProjectOverride(base, {rules:[{id:"local",severity:"interrupt",match:"substring",pattern:"wipe",reason:"local"}],raise:{danger:"interrupt"}});
  assert.equal(result.rules.length, 2);
  assert.equal(result.rules.find((r)=>r.id === "danger").severity, "alert");
  assert.equal(result.rejected.length, 1);
});

test("dedupe never suppresses interrupts and rate limits", () => {
  const d = new Dedupe({windowMs: 100});
  assert.equal(d.seen("p", "x", "a", "interrupt", 1), false);
  assert.equal(d.seen("p", "x", "a", "interrupt", 2), false);
  assert.equal(d.seen("p", "x", "a", "alert", 1), false);
  assert.equal(d.seen("p", "x", "a", "alert", 2), true);
  const r = new RateLimiter({maxPerMinute: 2, windowMs: 100});
  assert.equal(r.allow("p", 1), true); assert.equal(r.allow("p", 2), true); assert.equal(r.allow("p", 3), false);
  r.suppress("p", "danger", 3); assert.equal(r.flushCoalesced(50).length, 0); assert.equal(r.flushCoalesced(104).length, 1);
});

test("sanitizes controls and redacts secrets", () => {
  assert.equal(sanitizeString("ok\x1b]8;;https://evil\x07shown\x1b\\\n"), "okshown\n");
  assert.match(redactSecrets("TOKEN=secret sk-abcdefghijk"), /\[REDACTED\]/);
});

test("ConfigStore keeps last good config after invalid JSON", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-config-"));
  const defaults = path.join(dir, "defaults.json"); fs.writeFileSync(defaults, JSON.stringify({version:1,rules:[rule()]}));
  const store = new ConfigStore({configDir:dir, defaultsPath:defaults});
  assert.ok(store.load().config); fs.writeFileSync(path.join(dir,"rules.json"), "{");
  assert.ok(store.load({seedIfMissing:false}).config);
});

test("audit log partitions interrupt entries and redacts fields", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-audit-")); const log = new AuditLog(dir);
  log.write({ts:1,severity:"interrupt",matched_text:"$ TOKEN=secret",pane_id:"p"});
  log.write({ts:2,severity:"alert",matched_text:"npm publish",pane_id:"p"});
  assert.match(fs.readFileSync(path.join(dir,"audit.interrupt.jsonl"),"utf8"), /REDACTED/);
  assert.equal(log.tail(2).length, 2);
});

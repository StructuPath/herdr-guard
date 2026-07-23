// policy.mjs — pure policy engine for herdr-guard.
// No I/O on the matching path; ConfigStore owns the (small) file I/O.
// Every mechanism here exists because a design reviewer demonstrated a
// concrete attack without it — see docs/SPEC.md.

import fs from "node:fs";
import path from "node:path";

export const SEVERITIES = ["audit", "alert", "interrupt"];
export const PROMPT_GLYPH_RE = /^\s*(?:❯|╰─|\$|%)\s*/;
export const MAX_PATTERN_LENGTH = 512;
export const TRUNCATE_AT = 200;
export const DEDUPE_WINDOW_MS = 2000;
export const DEDUPE_CAP_PER_PANE = 256;
export const RATE_LIMIT_PER_MINUTE = 10;

export function severityRank(severity) {
	return SEVERITIES.indexOf(severity);
}

// ---------------------------------------------------------------------------
// Rule validation + compilation
// ---------------------------------------------------------------------------

const RULE_ID_RE = /^[a-z0-9][a-z0-9-]*$/;
const BACKREF_RE = /\\[1-9]/;

/**
 * Validate a raw rule object.
 * allowRegex=false is the project-override path: repo-controlled regex must
 * never reach the herdr server's matcher (a hostile repo could plant a
 * pathological pattern herdr-side).
 */
export function validateRule(rule, { allowRegex = true } = {}) {
	const errors = [];
	if (!rule || typeof rule !== "object")
		return { errors: ["rule is not an object"] };
	if (typeof rule.id !== "string" || !RULE_ID_RE.test(rule.id)) {
		errors.push(`id must match ${RULE_ID_RE} (got ${JSON.stringify(rule.id)})`);
	}
	if (!SEVERITIES.includes(rule.severity)) {
		errors.push(
			`severity must be one of ${SEVERITIES.join("/")} (got ${JSON.stringify(rule.severity)})`,
		);
	}
	if (rule.match !== "regex" && rule.match !== "substring") {
		errors.push(
			`match must be "regex" or "substring" (got ${JSON.stringify(rule.match)})`,
		);
	}
	if (rule.match === "regex" && !allowRegex) {
		errors.push("project overrides may only add substring rules");
	}
	if (typeof rule.pattern !== "string" || rule.pattern.length === 0) {
		errors.push("pattern must be a non-empty string");
	} else {
		if (rule.pattern.length > MAX_PATTERN_LENGTH) {
			errors.push(`pattern exceeds ${MAX_PATTERN_LENGTH} chars`);
		}
		if (rule.match === "regex") {
			if (
				/(\(\?[=!<]|\(\?<[^=!]|\\k<|\\[1-9]|\(\?<[A-Za-z_])/.test(rule.pattern)
			) {
				errors.push("regex uses constructs unsupported by Rust regex");
			}
			if (rule.pattern.startsWith("^")) {
				errors.push("no ^ anchors — matched lines carry prompt glyphs");
			}
			if (BACKREF_RE.test(rule.pattern)) {
				errors.push("backreferences are not allowed (RE2-safety)");
			}
			try {
				new RegExp(rule.pattern);
			} catch (err) {
				errors.push(`unparseable regex: ${err.message}`);
			}
		}
	}
	if (rule.prompt_only !== undefined && typeof rule.prompt_only !== "boolean") {
		errors.push("prompt_only must be a boolean");
	}
	if (typeof rule.reason !== "string" || rule.reason.length === 0) {
		errors.push("reason is required (it is shown in notifications)");
	}
	return { errors };
}

/**
 * Compile a validated rule. prompt_only defaults: ON for interrupt rules
 * (ctrl+c-ing vim over a runbook is how guards get disabled), off otherwise.
 */
export function compileRule(rule, { allowRegex = true } = {}) {
	const { errors } = validateRule(rule, { allowRegex });
	if (errors.length > 0) {
		const err = new Error(
			`invalid rule ${JSON.stringify(rule?.id)}: ${errors.join("; ")}`,
		);
		err.validationErrors = errors;
		throw err;
	}
	return {
		id: rule.id,
		severity: rule.severity,
		match: rule.match,
		pattern: rule.pattern,
		reason: rule.reason,
		prompt_only: rule.prompt_only ?? rule.severity === "interrupt",
		re: rule.match === "regex" ? new RegExp(rule.pattern) : null,
		needle: rule.match === "substring" ? rule.pattern : null,
	};
}

/**
 * Compile a rule list, collecting per-rule rejections instead of failing the
 * whole set — one bad rule must never silently drop the rest of the policy.
 */
export function compileRules(rawRules, { allowRegex = true } = {}) {
	const rules = [];
	const rejected = [];
	for (const raw of Array.isArray(rawRules) ? rawRules : []) {
		try {
			rules.push(compileRule(raw, { allowRegex }));
		} catch (err) {
			rejected.push({
				rule: raw?.id ?? null,
				errors: err.validationErrors ?? [err.message],
			});
		}
	}
	return { rules, rejected };
}

/** Build the single combined alternation regex used for one herdr-side
 * `pane.output_matched` subscription per pane. Includes escaped substring
 * literals so push matching covers every rule.
 */
export function buildCombinedPattern(rules) {
	const parts = rules.map((r) =>
		r.match === "regex"
			? `(?:${r.pattern})`
			: escapeRegex(r.needle ?? r.pattern),
	);
	return parts.length > 0 ? parts.join("|") : null;
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

function escapeRegex(value) {
	return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function lineMatchesRule(line, rule, { paneType = null } = {}) {
	if (
		rule.prompt_only &&
		!PROMPT_GLYPH_RE.test(line) &&
		!(rule.severity === "interrupt" && paneType && paneType !== "shell")
	)
		return false;
	return rule.re ? rule.re.test(line) : line.includes(rule.needle);
}

/** Highest-severity matching rule for one line, or null. */
export function matchLine(line, rules, options = {}) {
	let best = null;
	for (const rule of rules) {
		if (!lineMatchesRule(line, rule, options)) continue;
		if (!best || severityRank(rule.severity) > severityRank(best.severity)) {
			best = rule;
		}
	}
	return best ? { rule: best, line } : null;
}

/** All highest-severity-per-line matches in a text blob. */
export function scanText(text, rules, options = {}) {
	const matches = [];
	for (const line of String(text ?? "").split("\n")) {
		const m = matchLine(line, rules, options);
		if (m) matches.push(m);
	}
	return matches;
}

// ---------------------------------------------------------------------------
// Sanitization, redaction, truncation (audit + render share these)
// ---------------------------------------------------------------------------

// ANSI escape sequences: CSI, OSC (BEL or ST terminated), DCS/APC/PM/SOS,
// and two-character Fe/Fp sequences. Built from escaped code points so no
// raw control bytes ever live in the source file.
const ESC = "\\x1b";
const ESCAPE_RE = new RegExp(
	ESC +
		"(?:\\[[0-?]*[ -/]*[@-~]|\\].*?(?:\\x07|" +
		ESC +
		"\\\\)|[PX^_].*?" +
		ESC +
		"\\\\|[@-Z\\\\-_]|\\([0-9A-B])",
	"g",
);
// C0 (except none kept), DEL, and C1 — panes can emit terminal escapes and
// neither the audit log nor the dashboard may ever echo them live.
const CONTROL_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]/g;

export function sanitizeString(value) {
	return String(value ?? "")
		.replace(ESCAPE_RE, "")
		.replace(CONTROL_RE, "")
		.replace(/[\u2028\u2029]/g, " ");
}

const REDACTIONS = [
	// KEY=VALUE where the key names a secret (including exact TOKEN/SECRET).
	{
		re: /\b((?:[A-Za-z_][A-Za-z0-9_]*?(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|AUTH|CREDENTIALS?|PRIVATE)[A-Z0-9_]*|TOKEN|SECRET|PASSWORD|API_?KEY)=)(\S+)/gi,
		replace: "$1[REDACTED]",
	},
	// Authorization: bearer <token>
	{ re: /\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, replace: "$1[REDACTED]" },
	// Well-known token shapes
	{
		re: /\b(sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|gho_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{12,})\b/g,
		replace: "[REDACTED]",
	},
];

export function redactSecrets(value) {
	let out = String(value ?? "");
	for (const { re, replace } of REDACTIONS) out = out.replace(re, replace);
	return out;
}

export function truncate(value, max = TRUNCATE_AT) {
	const s = String(value ?? "");
	return s.length > max ? `${s.slice(0, max)}…` : s;
}

/** Full pipeline for any event-derived string before it is logged or shown. */
export function cleanField(value, max = TRUNCATE_AT) {
	return truncate(redactSecrets(sanitizeString(value)), max);
}

// ---------------------------------------------------------------------------
// Config loading (ConfigStore owns keep-last-good semantics)
// ---------------------------------------------------------------------------

export function writeJsonAtomic(file, value, mode = 0o600) {
	const tmp = `${file}.tmp-${process.pid}`;
	fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode });
	fs.renameSync(tmp, file);
	fs.chmodSync(file, mode);
}

export function normalizeConfig(raw) {
	const errors = [];
	if (!raw || typeof raw !== "object") {
		return { config: null, errors: ["config is not an object"] };
	}
	const enforcement = raw.enforcement ?? "active";
	if (enforcement !== "active" && enforcement !== "paused") {
		errors.push(
			`enforcement must be active|paused (got ${JSON.stringify(raw.enforcement)})`,
		);
	}
	const { rules, rejected } = compileRules(raw.rules);
	for (const r of rejected)
		errors.push(`rule ${r.rule}: ${r.errors.join("; ")}`);
	if (rules.length === 0) errors.push("no valid rules");
	const config = {
		version: raw.version ?? 1,
		enforcement,
		paused_until:
			typeof raw.paused_until === "number" ? raw.paused_until : null,
		allow_project_override: raw.allow_project_override === true,
		auto_reopen: raw.auto_reopen !== false,
		rules,
		raw,
	};
	if (errors.length > 0 && rules.length === 0) return { config: null, errors };
	return { config, errors };
}

export class ConfigStore {
	constructor({ configDir, defaultsPath }) {
		this.configDir = configDir;
		this.defaultsPath = defaultsPath;
		this.file = path.join(configDir, "rules.json");
		this.lastGood = null;
		this.lastMtimeMs = 0;
	}

	/** Seed rules.json from the shipped defaults if it does not exist. */
	seedIfMissing() {
		fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
		fs.chmodSync(this.configDir, 0o700);
		if (fs.existsSync(this.file)) {
			fs.chmodSync(this.file, 0o600);
			return false;
		}
		const defaults = JSON.parse(fs.readFileSync(this.defaultsPath, "utf8"));
		writeJsonAtomic(this.file, defaults);
		return true;
	}

	/**
	 * Load (and seed if asked). On parse/validation failure returns the last
	 * good config with an error — never an empty/active-by-default policy.
	 */
	load({ seedIfMissing = true } = {}) {
		let seeded = false;
		try {
			seeded = seedIfMissing ? this.seedIfMissing() : false;
		} catch (err) {
			return {
				config: this.lastGood,
				seeded: false,
				error: `seed failed: ${err.message}`,
				warnings: [],
			};
		}
		let rawText;
		try {
			rawText = fs.readFileSync(this.file, "utf8");
		} catch (err) {
			return {
				config: this.lastGood,
				seeded,
				error: `read failed: ${err.message}`,
				warnings: [],
			};
		}
		let raw;
		try {
			raw = JSON.parse(rawText);
		} catch (err) {
			return {
				config: this.lastGood,
				seeded,
				error: `parse failed: ${err.message}`,
				warnings: [],
			};
		}
		const { config, errors } = normalizeConfig(raw);
		if (!config) {
			return {
				config: this.lastGood,
				seeded,
				error: errors.join("; "),
				warnings: [],
			};
		}
		this.lastGood = config;
		try {
			this.lastMtimeMs = fs.statSync(this.file).mtimeMs;
		} catch {
			this.lastMtimeMs = 0;
		}
		return { config, seeded, error: null, warnings: errors };
	}

	/** Reload only when the file changed on disk (watcher mtime poll). */
	reloadIfChanged() {
		let mtimeMs;
		try {
			mtimeMs = fs.statSync(this.file).mtimeMs;
		} catch {
			return { changed: false };
		}
		if (mtimeMs === this.lastMtimeMs) return { changed: false };
		const result = this.load({ seedIfMissing: false });
		return { changed: true, ...result };
	}

	/** Flip enforcement, preserving every other field. Used by pause/resume. */
	setEnforcement(enforcement, { pausedUntil = null } = {}) {
		if (
			!this.lastGood ||
			!Array.isArray(this.lastGood.rules) ||
			this.lastGood.rules.length === 0
		) {
			return {
				config: null,
				error: "refusing enforcement change without a valid loaded config",
			};
		}
		const base = this.lastGood.raw ?? {};
		const next = { ...base, enforcement };
		if (enforcement === "paused") next.paused_until = pausedUntil;
		else delete next.paused_until;
		writeJsonAtomic(this.file, next);
		return this.load({ seedIfMissing: false });
	}
}

// ---------------------------------------------------------------------------
// Project overrides — add / raise-to-alert-only; never disable or lower
// ---------------------------------------------------------------------------

/**
 * Merge a workspace's .herdr-guard.json over the compiled base rules.
 * Returns merged COMPILED rules plus applied/rejected journals — every
 * applied override is audit-logged by the caller with its workspace path.
 */
export function mergeProjectOverride(
	baseRules,
	override,
	{ allowProjectOverride = false } = {},
) {
	const applied = [];
	const rejected = [];
	if (!override || typeof override !== "object") {
		return { rules: baseRules, applied, rejected };
	}

	const baseById = new Map(baseRules.map((r) => [r.id, r]));
	const merged = new Map(baseById);

	// Added rules
	for (const raw of Array.isArray(override.rules) ? override.rules : []) {
		if (baseById.has(raw?.id) && !allowProjectOverride) {
			rejected.push({
				kind: "add",
				rule: raw?.id ?? null,
				reason: "id collides with a config-dir rule",
			});
			continue;
		}
		try {
			const compiled = compileRule(raw, { allowRegex: false });
			merged.set(compiled.id, compiled);
			applied.push({ kind: "add", rule: compiled.id });
		} catch (err) {
			rejected.push({
				kind: "add",
				rule: raw?.id ?? null,
				reason: (err.validationErrors ?? [err.message]).join("; "),
			});
		}
	}

	// Severity raises — capped at alert. Raise-to-interrupt is self-DoS.
	const raises =
		override.raise && typeof override.raise === "object" ? override.raise : {};
	for (const [id, target] of Object.entries(raises)) {
		const base = merged.get(id);
		if (!base) {
			rejected.push({ kind: "raise", rule: id, reason: "unknown rule id" });
			continue;
		}
		const cap = "alert";
		if (
			!SEVERITIES.includes(target) ||
			severityRank(target) > severityRank(cap)
		) {
			rejected.push({
				kind: "raise",
				rule: id,
				reason: `raise target capped at ${cap}`,
			});
			continue;
		}
		if (
			severityRank(target) <= severityRank(base.severity) &&
			!allowProjectOverride
		) {
			rejected.push({
				kind: "raise",
				rule: id,
				reason: "lowering severity is not allowed",
			});
			continue;
		}
		merged.set(id, { ...base, severity: target });
		applied.push({ kind: "raise", rule: id, from: base.severity, to: target });
	}

	// Disables — only when the config-dir file explicitly allows overrides.
	for (const id of Array.isArray(override.disable) ? override.disable : []) {
		if (!allowProjectOverride) {
			rejected.push({
				kind: "disable",
				rule: id,
				reason: "allow_project_override is false",
			});
			continue;
		}
		if (merged.delete(id)) applied.push({ kind: "disable", rule: id });
	}

	return { rules: [...merged.values()], applied, rejected };
}

// ---------------------------------------------------------------------------
// Dedupe — time-bounded, LRU-capped, interrupt rules NEVER deduped
// (the pre-seeding attack: cancel once, retype, hit Enter — must cancel again)
// ---------------------------------------------------------------------------

export class Dedupe {
	constructor({ windowMs = DEDUPE_WINDOW_MS, cap = DEDUPE_CAP_PER_PANE } = {}) {
		this.windowMs = windowMs;
		this.cap = cap;
		this.panes = new Map(); // paneId -> Map(key -> ts)
	}

	seen(paneId, line, action, severity, now = Date.now()) {
		if (severity === "interrupt") return false; // never deduped
		let pane = this.panes.get(paneId);
		if (!pane) {
			pane = new Map();
			this.panes.set(paneId, pane);
		}
		const key = JSON.stringify([line, action]);
		const ts = pane.get(key);
		if (ts !== undefined && now - ts < this.windowMs) return true;
		pane.set(key, now);
		// LRU eviction: Map preserves insertion order
		while (pane.size > this.cap) {
			pane.delete(pane.keys().next().value);
		}
		return false;
	}

	clearPane(paneId) {
		this.panes.delete(paneId);
	}
}

// ---------------------------------------------------------------------------
// Rate limiter — 10 actions/min/pane, coalesced suppression entries so a
// flood cannot evict real history or spam notifications
// ---------------------------------------------------------------------------

export class RateLimiter {
	constructor({
		maxPerMinute = RATE_LIMIT_PER_MINUTE,
		windowMs = 60_000,
	} = {}) {
		this.maxPerMinute = maxPerMinute;
		this.windowMs = windowMs;
		this.hits = new Map(); // paneId -> number[]
		this.suppressed = new Map(); // `${paneId}${ruleId}` -> {paneId, ruleId, count, firstTs}
	}

	allow(paneId, now = Date.now()) {
		let list = this.hits.get(paneId);
		if (!list) {
			list = [];
			this.hits.set(paneId, list);
		}
		while (list.length > 0 && now - list[0] >= this.windowMs) list.shift();
		if (list.length >= this.maxPerMinute) return false;
		list.push(now);
		return true;
	}

	suppress(paneId, ruleId, now = Date.now()) {
		const key = JSON.stringify([paneId, ruleId]);
		const entry = this.suppressed.get(key) ?? {
			paneId,
			ruleId,
			count: 0,
			firstTs: now,
		};
		entry.count += 1;
		this.suppressed.set(key, entry);
	}

	/** Drain coalesced entries older than one window (caller audits them). */
	flushCoalesced(now = Date.now()) {
		const drained = [];
		for (const [key, entry] of this.suppressed) {
			if (now - entry.firstTs >= this.windowMs) {
				drained.push(entry);
				this.suppressed.delete(key);
			}
		}
		return drained;
	}

	clearPane(paneId) {
		this.hits.delete(paneId);
		for (const [key, entry] of this.suppressed) {
			if (entry.paneId === paneId) this.suppressed.delete(key);
		}
	}
}

// ---------------------------------------------------------------------------
// Pane classification (drives honest expectations per pane type)
// ---------------------------------------------------------------------------

const SHELL_RE = /^(zsh|bash|sh|fish|dash|ksh|tcsh|nu|xonsh)(-?[0-9.]*)?$/i;
const TUI_AGENT_RE =
	/^(pi|claude|codex|opencode|opencode-go|gemini|kimi|aider|amp|cursor-agent|crush|goose)/i;

export function classifyPane(processName, terminalTitle = "") {
	const name =
		String(processName ?? "")
			.split("/")
			.pop() ?? "";
	if (SHELL_RE.test(name)) return "shell";
	if (TUI_AGENT_RE.test(name) || TUI_AGENT_RE.test(String(terminalTitle)))
		return "tui-agent";
	return "output";
}

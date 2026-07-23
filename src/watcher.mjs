// watcher.mjs — the Guard pane process. Implements the spec lifecycle:
// bootstrap → subscribe-first/reconcile-after per pane → content-based replay
// suppression → edge-trigger local re-scan with time-bounded dedupe → sweep
// backstop → rate-limited, prompt-gated, audited actions → fail-visible
// reconnect with full re-bootstrap.

import fs from "node:fs";
import path from "node:path";
import { HerdrSocket } from "./herdr-socket.mjs";
import { AuditLog } from "./audit.mjs";
import {
	ConfigStore,
	Dedupe,
	RateLimiter,
	buildCombinedPattern,
	classifyPane,
	cleanField,
	mergeProjectOverride,
	scanText,
	severityRank,
} from "./policy.mjs";
import { renderDashboard } from "./render.mjs";

const VERSION = "0.1.0";
const REPLAY_WINDOW_MS = 500;
const SWEEP_INTERVAL_MS = 10_000;
const SWEEP_TICK_MS = 1_000;
const SWEEP_MAX_PER_TICK = 2;
const CONFIG_POLL_MS = 2_000;
const COALESCE_FLUSH_MS = 30_000;
const RENDER_DEBOUNCE_MS = 100;
const SWEEP_SEEN_CAP = 256;

// --- Tolerant payload extractors (socket shapes vary by herdr version) ------

function extractText(payload) {
	if (payload == null) return "";
	if (typeof payload === "string") return payload;
	return (
		payload.text ??
		payload.read?.text ??
		payload.read?.content ??
		payload.content ??
		payload.output ??
		""
	);
}

function extractPaneId(payload) {
	return (
		payload?.pane_id ?? payload?.pane?.pane_id ?? payload?.pane?.id ?? null
	);
}

function extractPanes(snapshot) {
	snapshot = snapshot?.snapshot ?? snapshot;
	if (Array.isArray(snapshot?.panes)) return snapshot.panes;
	if (Array.isArray(snapshot?.pane_records)) return snapshot.pane_records;
	// Fallback: first array whose items look like pane records
	for (const value of Object.values(snapshot ?? {})) {
		if (Array.isArray(value) && value.length > 0 && value[0]?.pane_id)
			return value;
	}
	return [];
}

function eventPayload(msg) {
	if (typeof msg?.event === "string")
		return { ...(msg.data ?? {}), type: msg.event };
	return msg?.event ?? msg?.result ?? msg;
}

// -----------------------------------------------------------------------------

export class Guard {
	constructor({
		socket,
		configStore,
		auditLog,
		ownPaneId = null,
		now = () => Date.now(),
		onRender = null,
		overrideDir = (cwd) => path.join(cwd, ".herdr-guard.json"),
	}) {
		this.socket = socket;
		this.configStore = configStore;
		this.audit = auditLog;
		this.ownPaneId = ownPaneId;
		this.now = now;
		this.onRender = onRender;
		this.overrideDir = overrideDir;

		this.config = null;
		this.panes = new Map(); // paneId -> watch entry
		this.dedupe = new Dedupe();
		this.rateLimiter = new RateLimiter();
		this.overrideCache = new Map(); // cwd -> {mtimeMs, rules, appliedLogged}
		this.matchesToday = 0;
		this.today = new Date(now()).toDateString();
		this.connected = false;
		this.timers = [];
		this.renderTimer = null;
		this.stopped = false;
	}

	// --- lifecycle ----------------------------------------------------------

	async start() {
		const { config, seeded, error, warnings } = this.configStore.load();
		if (!config) throw new Error(`no usable config: ${error ?? "unknown"}`);
		this.config = config;
		if (seeded)
			this.logSystem(
				"config",
				`seeded default rules (${config.rules.length} rules)`,
			);
		if (error)
			this.notify("herdr-guard", `config error (kept last good): ${error}`);
		if (warnings?.length)
			this.notify(
				"herdr-guard",
				`${warnings.length} rule warning(s) — see audit log`,
			);
		for (const w of warnings ?? []) this.logSystem("config-warning", w);

		this.socket.on("disconnected", () => {
			this.connected = false;
			this.scheduleRender();
		});
		this.socket.on("reconnected", () => {
			this.connected = true;
			this.bootstrap().catch(() => {});
		});

		await this.bootstrap();

		this.timers.push(setInterval(() => this.sweepTick(), SWEEP_TICK_MS));
		this.timers.push(setInterval(() => this.configTick(), CONFIG_POLL_MS));
		this.timers.push(
			setInterval(() => this.flushCoalesced(), COALESCE_FLUSH_MS),
		);
		for (const t of this.timers) t.unref?.();
		this.scheduleRender();
	}

	async bootstrap() {
		// Re-bootstrap is full: drop all prior watch state (server does not
		// resume subscriptions after reconnect).
		this.panes.clear();
		this.dedupe = new Dedupe();
		this.rateLimiter = new RateLimiter();

		const snapshot = await this.socket.request("session.snapshot", {});
		this.connected = true;

		// Global lifecycle: new panes, closing panes (post-mortem), exits.
		await this.socket.subscribe(
			[
				{ type: "pane.created" },
				{ type: "pane.closed" },
				{ type: "pane.exited" },
			],
			(msg) => this.onLifecycle(msg),
		);

		const panes = extractPanes(snapshot);
		// Subscribe-first/reconcile is async per pane; never serialize the whole
		// bootstrap on one slow pane.
		await Promise.allSettled(panes.map((pane) => this.watchPane(pane)));
		this.scheduleRender();
	}

	stop() {
		this.stopped = true;
		for (const t of this.timers) clearInterval(t);
		if (this.renderTimer) clearTimeout(this.renderTimer);
		this.socket.close?.();
	}

	// --- pane watching --------------------------------------------------------

	isOwnPane(pane) {
		if (!pane) return false;
		if (this.ownPaneId && pane.pane_id === this.ownPaneId) return true;
		return (
			pane.plugin_id === "structupath.guard" ||
			pane.plugin === "structupath.guard"
		);
	}

	async watchPane(pane) {
		const paneId = pane?.pane_id;
		if (
			!paneId ||
			this.panes.has(paneId) ||
			this.isOwnPane(pane) ||
			this.stopped
		)
			return;
		const entry = {
			id: paneId,
			workspace: pane.workspace_id ?? null,
			cwd: pane.cwd ?? pane.foreground_cwd ?? null,
			baseline: new Set(),
			queued: [],
			reconciled: false,
			sweepSeen: new Set(),
			paneType: pane.pane_type ?? "output",
			subscribedAt: 0,
			lastSweep: 0,
			sweeping: false,
		};
		this.panes.set(paneId, entry);

		// 1) Subscribe FIRST with one combined alternation regex (edge-triggered
		//    server-side). Replayed scrollback matches land right after the ack.
		const combined = buildCombinedPattern(this.config.rules);
		if (combined) {
			try {
				await this.socket.subscribe(
					[
						{
							type: "pane.output_matched",
							pane_id: paneId,
							source: "recent_unwrapped",
							lines: 5,
							strip_ansi: true,
							match: { type: "regex", value: combined },
						},
					],
					(msg) => this.onPush(paneId, msg),
				);
				entry.subscribedAt = this.now();
			} catch (err) {
				this.logSystem("subscribe-error", `${paneId}: ${err.message}`);
			}
		}

		// Resolve process metadata before releasing queued replay events, so the first
		// real shell interrupt is classified correctly.
		await this.refreshPaneInfo(entry);

		// 2) THEN reconcile: baseline read. Content-based replay suppression
		//    compares push events against this set.
		try {
			const text = await this.readPane(paneId);
			entry.baseline = new Set(text.split("\n").filter(Boolean));
		} catch {
			/* pane may already be gone */
		}
		entry.reconciled = true;
		const queued = entry.queued.splice(0);
		for (const queuedMsg of queued) this.onPush(paneId, queuedMsg);
		this.scheduleRender();
	}

	async refreshPaneInfo(entry) {
		try {
			const info = await this.socket.request("pane.process_info", { pane_id: entry.id }, { timeoutMs: 3_000 });
			const fg = info?.result?.process_info?.foreground_processes?.[0] ?? info?.process_info?.foreground_processes?.[0] ?? null;
			if (!fg) return;
			entry.paneType = classifyPane(fg.process_name ?? fg.name ?? fg.argv0 ?? "", fg.terminal_title ?? "");
			const cwd = fg.cwd ?? null;
			if (cwd && cwd !== entry.cwd) { this.overrideCache.delete(entry.cwd); entry.cwd = cwd; }
		} catch { /* metadata is best effort */ }
	}

	async readPane(paneId, lines = 120) {
		const result = await this.socket.request(
			"pane.read",
			{ pane_id: paneId, source: "recent_unwrapped", lines },
			{ timeoutMs: 5_000 },
		);
		return extractText(result);
	}

	// --- event handling -------------------------------------------------------

	onPush(paneId, msg) {
		const entry = this.panes.get(paneId);
		if (!entry || this.stopped) return;
		if (!entry.reconciled) {
			entry.queued.push(msg);
			return;
		}
		const payload = eventPayload(msg);
		const eventPaneId = extractPaneId(payload);
		if (eventPaneId && eventPaneId !== paneId) return;
		const text = extractText(payload);
		if (!text) return;

		const matches = scanText(text, this.rulesFor(entry));
		if (matches.length === 0) return;

		// Content-based replay suppression: events arriving within the replay
		// window whose matched lines were already in the baseline are stale
		// scrollback, not new offenses. Never act on them — an interrupt replay
		// would ctrl+c whatever the pane is doing NOW.
		const withinReplay = this.now() - entry.subscribedAt < REPLAY_WINDOW_MS;
		if (withinReplay) {
			const allStale = matches.every((m) => entry.baseline.has(m.line));
			if (allStale) return;
		}

		for (const match of matches) {
			this.handleMatch(entry, match, "push").catch(() => {});
		}
	}

	onLifecycle(msg) {
		const payload = eventPayload(msg);
		const type = payload?.type ?? msg?.type ?? "";
		if (type === "pane.created") {
			const pane = payload?.pane ?? payload;
			this.watchPane(pane).catch(() => {});
			return;
		}
		if (type === "pane.closed" || type === "pane.exited") {
			const paneId = extractPaneId(payload);
			if (paneId && this.panes.has(paneId)) {
				this.postMortem(paneId).catch(() => {});
			}
		}
	}

	/** Final read of a dying pane: split-run-close attacks get audited. */
	async postMortem(paneId) {
		const entry = this.panes.get(paneId);
		this.panes.delete(paneId);
		this.dedupe.clearPane(paneId);
		this.rateLimiter.clearPane(paneId);
		try {
			const text = await this.readPane(paneId, 200);
			const matches = scanText(text, this.rulesFor(entry ?? { cwd: null }));
			for (const match of matches) {
				this.audit.write({
					ts: this.now(),
					pane_id: paneId,
					workspace_id: entry?.workspace,
					rule_id: match.rule.id,
					severity: match.rule.severity,
					matched_text: match.line,
					cwd: entry?.cwd,
					action_taken: "post-mortem",
					source: "post-mortem",
				});
				this.bumpMatches();
			}
		} catch {
			/* pane already reaped — nothing left to read */
		}
		this.scheduleRender();
	}

	// --- matching pipeline ----------------------------------------------------

	/** Base rules merged with the pane-cwd project override (cached per cwd). */
	rulesFor(entry) {
		const base = this.config.rules;
		const cwd = entry?.cwd;
		if (!cwd) return base;
		let mtimeMs = 0;
		try {
			mtimeMs = fs.statSync(this.overrideDir(cwd)).mtimeMs;
		} catch {
			return base; // no override file
		}
		const cached = this.overrideCache.get(cwd);
		if (cached && cached.mtimeMs === mtimeMs) return cached.rules;

		let parsed;
		try {
			parsed = JSON.parse(fs.readFileSync(this.overrideDir(cwd), "utf8"));
		} catch (err) {
			this.logSystem("override-error", `${cwd}: ${err.message}`);
			return base;
		}
		const { rules, applied, rejected } = mergeProjectOverride(base, parsed, {
			allowProjectOverride: this.config.allow_project_override,
		});
		// Every applied override is audit-logged with its workspace path.
		for (const a of applied) {
			this.audit.write({
				ts: this.now(),
				workspace_id: entry.workspace,
				cwd,
				rule_id: a.rule,
				action_taken: `override-${a.kind}`,
				source: "override",
				note: `${a.kind} ${a.rule}${a.to ? ` -> ${a.to}` : ""} (from ${cwd}/.herdr-guard.json)`,
			});
		}
		for (const r of rejected) {
			this.logSystem(
				"override-rejected",
				`${r.kind} ${r.rule}: ${r.reason} (${cwd})`,
			);
		}
		this.overrideCache.set(cwd, { mtimeMs, rules });
		return rules;
	}

	async handleMatch(entry, match, source) {
		const paneId = entry.id;
		const { rule, line } = match;
		const severity = rule.severity;
		const now = this.now();

		// Enforcement gate — pause never stops the AUDIT record, only actions.
		if (this.config.enforcement === "paused") {
			if (this.config.paused_until && now >= this.config.paused_until) {
				await this.resume("ttl-expired");
			} else {
				this.audit.write({
					ts: now,
					pane_id: paneId,
					workspace_id: entry.workspace,
					rule_id: rule.id,
					severity,
					matched_text: line,
					cwd: entry.cwd,
					action_taken: "enforcement-paused",
					source,
				});
				this.bumpMatches();
				this.scheduleRender();
				return;
			}
		}

		// Dedupe (interrupt-class is never deduped — the pre-seeding attack).
		if (this.dedupe.seen(paneId, line, `match:${rule.id}`, severity, now))
			return;

		// Rate limit with coalescing.
		if (!this.rateLimiter.allow(paneId, now)) {
			this.rateLimiter.suppress(paneId, rule.id, now);
			return;
		}

		// Interrupt first: never await enrichment or notification before ctrl+c.
		let action = "logged";
		if (severity === "interrupt" && entry.paneType === "shell") {
			const sent = await this.sendKeys(paneId, ["ctrl+c"]);
			action = sent ? "interrupted" : "interrupt-failed";
		}
		// Enrichment, best-effort.
		let processArgv = null;
		let paneType = entry.paneType ?? "output";
		try {
			const info = await this.socket.request(
				"pane.process_info",
				{ pane_id: paneId },
				{ timeoutMs: 3_000 },
			);
			const fg =
				info?.result?.process_info?.foreground_processes?.[0] ??
				info?.process_info?.foreground_processes?.[0] ??
				info?.foreground_processes?.[0] ??
				info?.foreground?.[0] ??
				info?.processes?.[0] ??
				null;
			processArgv = Array.isArray(fg?.process_argv)
				? fg.process_argv.join(" ")
				: (fg?.argv?.join(" ") ?? fg?.cmdline ?? fg?.name ?? null);
			paneType = classifyPane(
				fg?.process_name ?? fg?.name ?? "",
				fg?.terminal_title ?? "",
			);
			if (fg?.cwd && fg.cwd !== entry.cwd) {
				this.overrideCache.delete(entry.cwd);
				entry.cwd = fg.cwd;
			}
		} catch {
			/* enrichment is optional */
		}

		if (severityRank(severity) >= severityRank("alert")) {
			const notified = await this.notify(
				`herdr-guard: ${severity}`,
				`${rule.reason}\n${paneId}: ${line.slice(0, 120)}`,
			);
			if (notified && action === "logged") action = "notified";
		}
		entry.paneType = paneType;
		if (severity === "interrupt" && paneType !== "shell")
			action = "logged-non-shell";

		this.audit.write({
			ts: now,
			pane_id: paneId,
			workspace_id: entry.workspace,
			rule_id: rule.id,
			severity,
			matched_text: line,
			process_argv: processArgv,
			cwd: entry.cwd,
			pane_type: paneType,
			action_taken: action,
			source,
		});
		this.bumpMatches();
		this.scheduleRender();
	}

	// --- sweep backstop ---------------------------------------------------------

	sweepTick() {
		if (this.stopped || !this.connected) return;
		let started = 0;
		for (const entry of this.panes.values()) {
			if (started >= SWEEP_MAX_PER_TICK) break;
			if (entry.sweeping || this.now() - entry.lastSweep < SWEEP_INTERVAL_MS)
				continue;
			entry.sweeping = true;
			started++;
			this.sweepPane(entry)
				.catch(() => {})
				.finally(() => {
					entry.sweeping = false;
					entry.lastSweep = this.now();
				});
		}
	}

	async sweepPane(entry) {
		const text = await this.readPane(entry.id);
		const matches = scanText(text, this.rulesFor(entry));
		for (const match of matches) {
			// Sweep re-reads the same screen every interval — only act on lines
			// not seen by a previous sweep, or a static dangerous line would
			// re-alert every 10s forever.
			if (entry.sweepSeen.has(match.line)) continue;
			entry.sweepSeen.add(match.line);
			if (entry.sweepSeen.size > SWEEP_SEEN_CAP) {
				entry.sweepSeen.delete(entry.sweepSeen.values().next().value);
			}
			await this.handleMatch(entry, match, "sweep");
		}
	}

	// --- config / enforcement ---------------------------------------------------

	configTick() {
		if (this.stopped) return;
		// Pause TTL auto-resume — a forgotten or abused pause self-heals.
		if (
			this.config.enforcement === "paused" &&
			this.config.paused_until &&
			this.now() >= this.config.paused_until
		) {
			this.resume("ttl-expired").catch(() => {});
			return;
		}
		const result = this.configStore.reloadIfChanged();
		if (!result.changed) return;
		if (result.error) {
			this.notify(
				"herdr-guard",
				`config error (kept last good): ${result.error}`,
			);
			this.logSystem("config-error", result.error);
			return;
		}
		const prev = this.config;
		this.config = result.config;
		this.overrideCache.clear();
		this.connected = false;
		this.bootstrap().catch(() => {});
		this.audit.write({
			ts: this.now(),
			action_taken: "config-change",
			source: "config",
			note: `enforcement ${prev.enforcement} -> ${this.config.enforcement}; rules ${prev.rules.length} -> ${this.config.rules.length}`,
		});
		this.notify(
			"herdr-guard",
			`config reloaded: enforcement=${this.config.enforcement}, rules=${this.config.rules.length}`,
		);
		this.scheduleRender();
	}

	async resume(reason) {
		const result = this.configStore.setEnforcement("active");
		if (result.config) this.config = result.config;
		this.audit.write({
			ts: this.now(),
			action_taken: "enforcement-resumed",
			source: "config",
			note: reason,
		});
		await this.notify("herdr-guard", `enforcement resumed (${reason})`);
		this.scheduleRender();
	}

	flushCoalesced() {
		for (const entry of this.rateLimiter.flushCoalesced(this.now())) {
			this.audit.write({
				ts: this.now(),
				pane_id: entry.paneId,
				rule_id: entry.ruleId,
				action_taken: "rate-limited",
				source: "rate-limiter",
				note: `${entry.count} suppressed matches in one minute`,
			});
		}
	}

	// --- actions (best-effort wrappers) -----------------------------------------

	async notify(title, body) {
			const safeTitle = cleanField(String(title)).slice(0, 200);
			const safeBody = cleanField(String(body)).slice(0, 200);
			try {
				await this.socket.request(
				"notification.show",
				{ title: safeTitle, body: safeBody, sound: "request" },
				{ timeoutMs: 5_000 },
			);
			return true;
		} catch {
			return false;
		}
	}

	async sendKeys(paneId, keys) {
		try {
			await this.socket.request(
				"pane.send_keys",
				{ pane_id: paneId, keys: Array.isArray(keys) ? keys : [keys] },
				{ timeoutMs: 5_000 },
			);
			return true;
		} catch {
			return false;
		}
	}

	logSystem(kind, note) {
		this.audit.write({
			ts: this.now(),
			action_taken: kind,
			source: "guard",
			note,
		});
	}

	bumpMatches() {
		const today = new Date(this.now()).toDateString();
		if (today !== this.today) {
			this.today = today;
			this.matchesToday = 0;
		}
		this.matchesToday += 1;
	}

	// --- render -------------------------------------------------------------------

	scheduleRender() {
		if (!this.onRender || this.renderTimer || this.stopped) return;
		this.renderTimer = setTimeout(() => {
			this.renderTimer = null;
			this.onRender(this.renderState());
		}, RENDER_DEBOUNCE_MS);
		this.renderTimer.unref?.();
	}

	renderState() {
		const rejectedRules = this.config.raw ? null : 0;
		return {
			version: VERSION,
			connected: this.connected,
			enforcement: this.config.enforcement,
			pausedUntil: this.config.paused_until,
			now: this.now(),
			panesWatched: this.panes.size,
			rulesLoaded: this.config.rules.length,
			rejectedRules: rejectedRules ?? 0,
			matchesToday: this.matchesToday,
			lastEntries: this.audit.tail(12),
		};
	}
}

// --- main (only when executed as the pane process) ----------------------------

function isMain() {
	return import.meta.url === `file://${process.argv[1]}`;
}

async function main() {
	const env = process.env;
	const socketPath = env.HERDR_SOCKET_PATH;
	const pluginRoot =
		env.HERDR_PLUGIN_ROOT ??
		path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
	const configDir =
		env.HERDR_PLUGIN_CONFIG_DIR ??
		path.join(env.HOME ?? "~", ".config", "herdr-guard");
	const stateDir =
		env.HERDR_PLUGIN_STATE_DIR ??
		path.join(env.HOME ?? "~", ".local", "state", "herdr-guard");

	if (!socketPath) {
		console.log(
			"herdr-guard: HERDR_SOCKET_PATH is not set — run this as a herdr plugin pane.",
		);
		setInterval(() => {}, 60_000);
		return;
	}

	fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
	fs.chmodSync(stateDir, 0o700);

	const configStore = new ConfigStore({
		configDir,
		defaultsPath: path.join(pluginRoot, "src", "rules-default.json"),
	});
	const auditLog = new AuditLog(stateDir);
	const socket = new HerdrSocket(socketPath);

	const render = (state) => {
		const width = process.stdout.columns ?? 80;
		const height = process.stdout.rows ?? 24;
		process.stdout.write(renderDashboard(state, { width, height }));
	};

	const guard = new Guard({
		socket,
		configStore,
		auditLog,
		ownPaneId: env.HERDR_PANE_ID ?? null,
		onRender: render,
	});

	await socket.connect();
	await guard.start();

	// Record our pane id so the watchdog event hook can recognize our death.
	if (env.HERDR_PANE_ID) {
		try {
			fs.writeFileSync(
				path.join(stateDir, "guard-pane.id"),
				env.HERDR_PANE_ID,
				{ mode: 0o600 },
			);
		} catch {
			/* best-effort */
		}
	}

	// Sibling-session awareness: other named sessions have their own sockets
	// and are NOT guarded.
	try {
		const configHome = path.dirname(socketPath);
		const sessionsDir = fs.existsSync(path.join(configHome, "sessions"))
			? path.join(configHome, "sessions")
			: path.join(path.dirname(configHome), "sessions");
		const others = fs
			.readdirSync(sessionsDir)
			.map((name) => path.join(sessionsDir, name, "herdr.sock"))
			.filter((sock) => fs.existsSync(sock) && sock !== socketPath);
		if (others.length > 0) {
			guard.notify(
				"herdr-guard",
				`${others.length} other herdr session(s) are running unguarded`,
			);
			guard.logSystem(
				"sibling-sessions",
				`${others.length} unguarded: ${others.join(", ")}`,
			);
		}
	} catch {
		/* no sibling sessions dir — fine */
	}

	process.stdout.on("resize", () => guard.scheduleRender());
	const shutdown = () => {
		guard.stop();
		process.exit(0);
	};
	process.on("SIGTERM", shutdown);
	process.on("SIGINT", shutdown);
}

if (isMain()) {
	main().catch((err) => {
		console.error(`herdr-guard: fatal: ${err.message}`);
		// Never exit instantly in a pane — keep the error readable.
		setInterval(() => {}, 60_000);
	});
}

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import { Guard } from "../src/watcher.mjs";
import { ConfigStore, compileRule, scanText } from "../src/policy.mjs";
import { renderDashboard } from "../src/render.mjs";

const interruptRuleInput = {
	id: "danger",
	severity: "interrupt",
	match: "substring",
	pattern: "danger",
	prompt_only: true,
	reason: "dangerous command",
};
const interruptRule = compileRule(interruptRuleInput);

class FakeSocket extends EventEmitter {
	constructor({
		baseline = "$ danger",
		paneName = "zsh",
		paneCwd = "/tmp",
	} = {}) {
		super();
		this.baseline = baseline;
		this.paneName = paneName;
		this.paneCwd = paneCwd;
		this.panes = [{ pane_id: "p1", workspace_id: "w1", cwd: paneCwd }];
		this.calls = [];
		this.lifecycleCallback = null;
		this.outputCallback = null;
		this.resetCount = 0;
		this.snapshotCount = 0;
		this.clearCount = 0;
		this.unsubscribed = [];
		this.nextSubscriptionId = 1;
		this.activeSubscriptions = new Map();
		this.connected = true;
	}

	async request(method, params = {}) {
		this.calls.push({ method, params });
		if (method === "session.snapshot") {
			this.snapshotCount += 1;
			return {
				type: "session_snapshot",
				snapshot: { panes: this.panes },
			};
		}
		if (method === "pane.process_info") {
			return {
				type: "pane_process_info",
				process_info: {
					foreground_processes: [
						{
							name: this.paneName,
							argv0: this.paneName,
							cwd: this.paneCwd,
						},
					],
				},
			};
		}
		if (method === "pane.read") return { read: { text: this.baseline } };
		if (method === "pane.send_keys") return { type: "ok" };
		if (method === "notification.show") return { shown: true };
		return { type: "ok" };
	}

	async subscribe(subscriptions, callback) {
		this.calls.push({ method: "events.subscribe", params: { subscriptions } });
		if (subscriptions[0]?.type === "pane.created") {
			this.lifecycleCallback = callback;
		}
		if (subscriptions[0]?.type === "pane.output_matched") {
			this.outputCallback = callback;
			// Herdr replays matching scrollback immediately around the ack.
			callback({
				event: "pane.output_matched",
				data: {
					pane_id: "p1",
					matched_line: this.baseline,
					read: { text: this.baseline },
				},
			});
		}
		const subscriptionId = `sub-${this.nextSubscriptionId++}`;
		this.activeSubscriptions.set(subscriptionId, subscriptions);
		return {
			subscriptionId,
			ack: { type: "subscription_ack" },
		};
	}

	async resetConnection() {
		this.resetCount += 1;
		this.connected = true;
	}

	clearSubscriptions() {
		this.clearCount += 1;
		for (const subscriptionId of this.activeSubscriptions.keys())
			this.unsubscribe(subscriptionId);
	}

	unsubscribe(subscriptionId) {
		this.unsubscribed.push(subscriptionId);
		this.activeSubscriptions.delete(subscriptionId);
	}

	close() {}
}

function makeGuard(
	socket,
	{
		now = () => 1_000,
		paneName = "zsh",
		onDisconnect = null,
		bootstrapRetryMs = 1_000,
		projectSubscriptionRetryMs = 1_000,
		configStore = null,
	} = {},
) {
	socket.paneName = paneName;
	const entries = [];
	const guard = new Guard({
		socket,
		configStore: configStore ?? {
			load: () => ({
				config: {
					enforcement: "active",
					paused_until: null,
					rules: [interruptRule],
				},
				warnings: [],
			}),
			reloadIfChanged: () => ({ changed: false }),
		},
		auditLog: { write: (entry) => entries.push(entry), tail: () => entries },
		now,
		onDisconnect,
		bootstrapRetryMs,
		projectSubscriptionRetryMs,
	});
	guard.config = {
		enforcement: "active",
		paused_until: null,
		rules: [interruptRule],
	};
	return { guard, entries };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

test("bootstrap unwraps snapshot and suppresses replay queued before reconciliation", async () => {
	const socket = new FakeSocket();
	const { guard, entries } = makeGuard(socket);
	await guard.bootstrap();
	assert.equal(guard.connected, true);
	assert.equal(guard.panes.get("p1").paneType, "shell");
	assert.equal(
		socket.calls.some((call) => call.method === "pane.send_keys"),
		false,
	);
	assert.equal(
		entries.some((entry) => entry.rule_id === "danger"),
		false,
	);
});

test("superseded bootstrap cannot install streams or publish readiness", async () => {
	const socket = new FakeSocket({ baseline: "" });
	let releaseOlderSnapshot;
	let markOlderStarted;
	const olderStarted = new Promise((resolve) => {
		markOlderStarted = resolve;
	});
	const request = socket.request.bind(socket);
	let snapshotAttempt = 0;
	socket.request = async (method, params) => {
		if (method === "session.snapshot" && snapshotAttempt++ === 0) {
			markOlderStarted();
			return new Promise((resolve) => {
				releaseOlderSnapshot = () =>
					resolve({
						type: "session_snapshot",
						snapshot: { panes: socket.panes },
					});
			});
		}
		return request(method, params);
	};
	const { guard } = makeGuard(socket);

	const older = guard.bootstrap();
	await olderStarted;
	await guard.bootstrap();
	assert.equal(guard.connected, true);
	releaseOlderSnapshot();
	await assert.rejects(older, /bootstrap superseded/);

	const active = [...socket.activeSubscriptions.values()];
	assert.equal(
		active.filter((subscriptions) => subscriptions[0]?.type === "pane.created")
			.length,
		1,
	);
	assert.equal(
		active.filter(
			(subscriptions) => subscriptions[0]?.type === "pane.output_matched",
		).length,
		1,
	);
	assert.equal(guard.panes.size, 1);
	assert.equal(guard.connected, true);
});

test("a new bootstrap cancels a stale scheduled retry", async () => {
	const socket = new FakeSocket({ baseline: "" });
	const { guard } = makeGuard(socket, { bootstrapRetryMs: 60_000 });
	guard.scheduleBootstrapRetry(new Error("temporary failure"));
	assert.ok(guard.bootstrapRetryTimer);

	const bootstrap = guard.bootstrap();
	assert.equal(guard.bootstrapRetryTimer, null);
	await bootstrap;
	assert.equal(guard.connected, true);
	guard.stop();
});

test("live underscore lifecycle events add newly created panes", async () => {
	const socket = new FakeSocket({ baseline: "" });
	const { guard } = makeGuard(socket);
	await guard.bootstrap();
	socket.panes.push({ pane_id: "p2", workspace_id: "w1", cwd: "/tmp" });

	socket.lifecycleCallback({
		event: "pane_created",
		data: {
			pane: { pane_id: "p2", workspace_id: "w1", cwd: "/tmp" },
		},
	});
	await new Promise((resolve) => setTimeout(resolve, 80));

	assert.equal(guard.panes.has("p2"), true);
});

test("replayed lifecycle events ignore panes absent from the live snapshot", async () => {
	const socket = new FakeSocket({ baseline: "" });
	const { guard } = makeGuard(socket);
	await guard.bootstrap();

	socket.lifecycleCallback({
		event: "pane_created",
		data: {
			pane: { pane_id: "p2", workspace_id: "w1", cwd: "/tmp" },
		},
	});
	await new Promise((resolve) => setTimeout(resolve, 80));

	assert.equal(guard.panes.has("p2"), false);
});

test("lifecycle replay bursts coalesce into one live snapshot", async () => {
	const socket = new FakeSocket({ baseline: "" });
	const { guard } = makeGuard(socket);
	await guard.bootstrap();
	const snapshotsBefore = socket.snapshotCount;

	for (let index = 0; index < 20; index++) {
		socket.lifecycleCallback({
			event: "pane_created",
			data: {
				pane: { pane_id: `stale-${index}`, workspace_id: "w1" },
			},
		});
	}
	await new Promise((resolve) => setTimeout(resolve, 80));

	assert.equal(socket.snapshotCount, snapshotsBefore + 1);
});

test("failed subscriptions do not leave stale panes counted", async () => {
	const socket = new FakeSocket({ baseline: "" });
	const subscribe = socket.subscribe.bind(socket);
	socket.subscribe = async (subscriptions, callback) => {
		if (subscriptions[0]?.pane_id === "p2") throw new Error("socket closed");
		return subscribe(subscriptions, callback);
	};
	const { guard } = makeGuard(socket);
	await guard.bootstrap();

	await assert.rejects(
		guard.watchPane({ pane_id: "p2", workspace_id: "w1", cwd: "/tmp" }),
		/socket closed/,
	);
	assert.equal(guard.panes.has("p2"), false);
});

test("project subscription failure removes the base stream and pane", async () => {
	const socket = new FakeSocket({ baseline: "" });
	const { guard } = makeGuard(socket);
	await guard.bootstrap();
	guard.ensureProjectSubscription = async () => {
		throw new Error("project subscription failed");
	};

	await assert.rejects(
		guard.watchPane({ pane_id: "p2", workspace_id: "w1", cwd: "/tmp" }),
		/project subscription failed/,
	);
	assert.equal(guard.panes.has("p2"), false);
	assert.equal(socket.unsubscribed.length > 0, true);
});

test("project subscription ownership replaces policy and cwd streams, including no pattern", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "guard-project-stream-"));
	const cwdA = path.join(root, "a");
	const cwdB = path.join(root, "b");
	const cwdNone = path.join(root, "none");
	for (const cwd of [cwdA, cwdB, cwdNone]) fs.mkdirSync(cwd);
	const overridePath = (cwd) => path.join(cwd, ".herdr-guard.json");
	const writeOverride = (cwd, id, pattern, mtimeOffset = 0) => {
		const file = overridePath(cwd);
		fs.writeFileSync(
			file,
			JSON.stringify({
				rules: [
					{
						id,
						severity: "alert",
						match: "substring",
						pattern,
						reason: id,
					},
				],
			}),
		);
		const timestamp = new Date(Date.now() + mtimeOffset);
		fs.utimesSync(file, timestamp, timestamp);
	};
	writeOverride(cwdA, "project-a", "alpha");
	writeOverride(cwdB, "project-b", "bravo");

	const socket = new FakeSocket({ baseline: "", paneCwd: cwdA });
	const { guard } = makeGuard(socket);
	guard.overrideDir = overridePath;
	await guard.bootstrap();
	const entry = guard.panes.get("p1");
	const baseSubscriptionId = entry.baseSubscriptionId;
	const firstProjectId = entry.projectSubscriptionId;
	assert.ok(firstProjectId);
	assert.match(entry.projectPattern, /alpha/);

	writeOverride(cwdA, "project-a2", "alpine", 2_000);
	await guard.refreshPaneInfo(entry);
	const secondProjectId = entry.projectSubscriptionId;
	assert.notEqual(secondProjectId, firstProjectId);
	assert.ok(socket.unsubscribed.includes(firstProjectId));
	assert.match(entry.projectPattern, /alpine/);

	socket.paneCwd = cwdB;
	await guard.refreshPaneInfo(entry);
	const thirdProjectId = entry.projectSubscriptionId;
	assert.notEqual(thirdProjectId, secondProjectId);
	assert.ok(socket.unsubscribed.includes(secondProjectId));
	assert.match(entry.projectPattern, /bravo/);

	socket.paneCwd = cwdNone;
	await guard.refreshPaneInfo(entry);
	assert.equal(entry.projectSubscriptionId, null);
	assert.equal(entry.projectPattern, null);
	assert.ok(socket.unsubscribed.includes(thirdProjectId));
	assert.equal(socket.unsubscribed.includes(baseSubscriptionId), false);
});

test("rejected project replacement retains the old stream, audits, and retries", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "guard-project-retry-"));
	const override = path.join(root, ".herdr-guard.json");
	const writeOverride = (id, pattern, offset) => {
		fs.writeFileSync(
			override,
			JSON.stringify({
				rules: [
					{
						id,
						severity: "alert",
						match: "substring",
						pattern,
						reason: id,
					},
				],
			}),
		);
		const timestamp = new Date(Date.now() + offset);
		fs.utimesSync(override, timestamp, timestamp);
	};
	writeOverride("project-alpha", "alpha", 0);
	const socket = new FakeSocket({ baseline: "", paneCwd: root });
	const subscribe = socket.subscribe.bind(socket);
	let rejectBravo = false;
	socket.subscribe = async (subscriptions, callback) => {
		const pattern = subscriptions[0]?.match?.value ?? "";
		if (rejectBravo && pattern.includes("bravo")) {
			rejectBravo = false;
			throw new Error("replacement rejected");
		}
		return subscribe(subscriptions, callback);
	};
	const { guard, entries } = makeGuard(socket, {
		projectSubscriptionRetryMs: 5,
	});
	guard.overrideDir = () => override;
	await guard.bootstrap();
	const entry = guard.panes.get("p1");
	const originalId = entry.projectSubscriptionId;
	assert.ok(socket.activeSubscriptions.has(originalId));

	writeOverride("project-bravo", "bravo", 2_000);
	rejectBravo = true;
	await assert.rejects(
		guard.ensureProjectSubscription(entry),
		/replacement rejected/,
	);
	assert.equal(entry.projectSubscriptionId, originalId);
	assert.match(entry.projectPattern, /alpha/);
	assert.ok(socket.activeSubscriptions.has(originalId));
	assert.equal(socket.unsubscribed.includes(originalId), false);
	assert.ok(
		entries.some(
			(item) =>
				item.action_taken === "subscribe-error" &&
				item.note.includes("retained after replacement failed"),
		),
	);

	await new Promise((resolve) => setTimeout(resolve, 20));
	assert.notEqual(entry.projectSubscriptionId, originalId);
	assert.match(entry.projectPattern, /bravo/);
	assert.ok(socket.unsubscribed.includes(originalId));
	assert.equal(entry.projectSubscriptionRetryTimer, null);
});

test("partial bootstrap failure clears successful subscriptions and pane state", async () => {
	const socket = new FakeSocket({ baseline: "" });
	const subscribe = socket.subscribe.bind(socket);
	socket.subscribe = async (subscriptions, callback) => {
		if (subscriptions[0]?.type === "pane.output_matched")
			throw new Error("subscription failed");
		return subscribe(subscriptions, callback);
	};
	const { guard } = makeGuard(socket);

	await assert.rejects(guard.bootstrap(), /subscription failed/);
	assert.equal(guard.connected, false);
	assert.equal(guard.panes.size, 0);
	assert.equal(socket.clearCount, 2);
});

test("repeated shell interrupts are never deduped and notifications coalesce", async () => {
	let clock = 2_000;
	const socket = new FakeSocket();
	const { guard, entries } = makeGuard(socket, { now: () => clock });
	await guard.bootstrap();
	const event = {
		event: "pane.output_matched",
		data: {
			pane_id: "p1",
			matched_line: "$ danger now",
			read: { text: "$ danger now" },
		},
	};
	socket.outputCallback(event);
	await settle();
	clock += 10;
	socket.outputCallback(event);
	await settle();
	const sends = socket.calls.filter((call) => call.method === "pane.send_keys");
	assert.equal(sends.length, 2);
	assert.deepEqual(sends[0].params, { pane_id: "p1", keys: ["ctrl+c"] });
	assert.equal(
		socket.calls.filter((call) => call.method === "notification.show").length,
		1,
	);
	const matches = entries.filter((entry) => entry.rule_id === "danger");
	assert.equal(matches.length, 2);
	assert.ok(
		matches.every(
			(entry) =>
				entry.decision === "request-interrupt" &&
				entry.interrupt_request === "accepted" &&
				entry.prevention === "unknown",
		),
	);
});

test("interrupt text in a non-shell pane audits without sending keys", async () => {
	const socket = new FakeSocket({ baseline: "", paneName: "node" });
	const { guard, entries } = makeGuard(socket, { paneName: "node" });
	await guard.bootstrap();
	const matches = scanText("danger in build output", [interruptRule], {
		paneType: "output",
	});
	assert.equal(matches.length, 1);
	await guard.handleMatch(guard.panes.get("p1"), matches[0], "test");
	assert.equal(
		socket.calls.some((call) => call.method === "pane.send_keys"),
		false,
	);
	assert.equal(entries.at(-1).decision, "log-only-non-shell");
	assert.equal(entries.at(-1).interrupt_request, "not-requested");
	assert.equal(entries.at(-1).prevention, "unknown");
});

test("accepted interrupt requests remain recorded after pane reclassification", async () => {
	const socket = new FakeSocket({ baseline: "", paneName: "zsh" });
	const { guard, entries } = makeGuard(socket);
	await guard.bootstrap();
	socket.paneName = "node";
	await guard.handleMatch(
		guard.panes.get("p1"),
		{ rule: interruptRule, line: "$ danger" },
		"test",
	);
	const entry = entries.at(-1);
	assert.equal(entry.pane_type_at_decision, "shell");
	assert.equal(entry.pane_type, "output");
	assert.equal(entry.decision, "request-interrupt");
	assert.equal(entry.interrupt_request, "accepted");
	assert.equal(entry.prevention, "unknown");
});

test("failed interrupt requests are recorded without claiming an interruption", async () => {
	const socket = new FakeSocket({ baseline: "" });
	const request = socket.request.bind(socket);
	socket.request = async (method, params) => {
		if (method === "pane.send_keys") throw new Error("request rejected");
		return request(method, params);
	};
	const { guard, entries } = makeGuard(socket);
	await guard.bootstrap();
	await guard.handleMatch(
		guard.panes.get("p1"),
		{ rule: interruptRule, line: "$ danger" },
		"test",
	);
	assert.equal(entries.at(-1).decision, "request-interrupt");
	assert.equal(entries.at(-1).interrupt_request, "failed");
	assert.equal(entries.at(-1).prevention, "unknown");
});

test("valid config changes reset the socket and fully bootstrap subscriptions", async () => {
	const socket = new FakeSocket({ baseline: "" });
	let changed = true;
	const { guard } = makeGuard(socket);
	guard.configStore.reloadIfChanged = () =>
		changed
			? ((changed = false),
				{
					changed: true,
					config: {
						enforcement: "active",
						paused_until: null,
						rules: [interruptRule],
					},
				})
			: { changed: false };
	await guard.bootstrap();
	const snapshotsBefore = socket.snapshotCount;
	await guard.configTick();
	assert.equal(socket.resetCount, 1);
	assert.equal(socket.snapshotCount, snapshotsBefore + 1);
	assert.equal(guard.connected, true);
});

test("failed config bootstrap audits failure then eventual retry application", async () => {
	const socket = new FakeSocket({ baseline: "" });
	let changed = true;
	const { guard, entries } = makeGuard(socket, { bootstrapRetryMs: 5 });
	guard.configStore.reloadIfChanged = () =>
		changed
			? ((changed = false),
				{
					changed: true,
					config: {
						enforcement: "active",
						paused_until: null,
						rules: [interruptRule],
					},
					warnings: ["rule rejected"],
				})
			: { changed: false };
	await guard.bootstrap();
	const subscribe = socket.subscribe.bind(socket);
	let rejectLifecycle = true;
	socket.subscribe = async (subscriptions, callback) => {
		if (rejectLifecycle && subscriptions[0]?.type === "pane.created") {
			rejectLifecycle = false;
			throw new Error("lifecycle subscribe rejected");
		}
		return subscribe(subscriptions, callback);
	};

	await guard.configTick();
	assert.equal(guard.connected, false);
	assert.ok(guard.bootstrapRetryTimer);
	await new Promise((resolve) => setTimeout(resolve, 25));
	assert.equal(guard.connected, true);
	assert.equal(guard.pendingConfigChange, null);
	assert.deepEqual(
		entries
			.filter((entry) => entry.action_taken?.startsWith("config-change-"))
			.map((entry) => entry.action_taken),
		[
			"config-change-detected",
			"config-change-failed",
			"config-change-applied",
		],
	);
	assert.equal(guard.renderState().loadWarnings, 1);
	const notificationBodies = socket.calls
		.filter((call) => call.method === "notification.show")
		.map((call) => call.params.body);
	assert.ok(notificationBodies.some((body) => body.includes("detected")));
	assert.ok(notificationBodies.some((body) => body.includes("failed")));
	assert.ok(notificationBodies.some((body) => body.includes("applied")));
	guard.stop();
});

test("config polling reports each bad generation once and applies recovery", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-config-poll-"));
	const defaultsPath = path.join(dir, "defaults.json");
	const configFile = path.join(dir, "rules.json");
	fs.writeFileSync(
		defaultsPath,
		JSON.stringify({ version: 1, rules: [interruptRuleInput] }),
	);
	const configStore = new ConfigStore({ configDir: dir, defaultsPath });
	const initialConfig = configStore.load().config;
	const socket = new FakeSocket({ baseline: "" });
	const { guard, entries } = makeGuard(socket, { configStore });
	guard.config = initialConfig;

	const writeGeneration = (contents, seconds) => {
		fs.writeFileSync(configFile, contents);
		fs.utimesSync(configFile, seconds, seconds);
		assert.equal(fs.statSync(configFile).mtimeMs, seconds * 1000);
	};
	const configActions = () =>
		entries
			.filter((entry) => entry.action_taken?.startsWith("config-change-"))
			.map((entry) => entry.action_taken);
	const notificationBodies = () =>
		socket.calls
			.filter((call) => call.method === "notification.show")
			.map((call) => call.params.body);

	writeGeneration("{", 1_700_000_011);
	await guard.configTick();
	await guard.configTick();
	assert.deepEqual(configActions(), [
		"config-change-detected",
		"config-change-failed",
	]);
	assert.equal(notificationBodies().length, 2);
	assert.equal(guard.config, initialConfig);
	assert.equal(guard.config.rules.length, 1);

	writeGeneration("{\"rules\":", 1_700_000_012);
	await guard.configTick();
	await guard.configTick();
	assert.deepEqual(configActions(), [
		"config-change-detected",
		"config-change-failed",
		"config-change-detected",
		"config-change-failed",
	]);
	assert.equal(notificationBodies().length, 4);
	assert.equal(guard.config, initialConfig);

	writeGeneration(
		JSON.stringify({
			version: 1,
			enforcement: "paused",
			rules: [interruptRuleInput],
		}),
		1_700_000_013,
	);
	await guard.configTick();
	await guard.configTick();
	assert.deepEqual(configActions(), [
		"config-change-detected",
		"config-change-failed",
		"config-change-detected",
		"config-change-failed",
		"config-change-detected",
		"config-change-applied",
	]);
	assert.equal(notificationBodies().length, 6);
	assert.equal(guard.config.enforcement, "paused");
	assert.equal(guard.config.rules.length, 1);
	assert.equal(socket.resetCount, 1);
});

test("dashboard reports load warnings and matches for this run only", () => {
	const socket = new FakeSocket({ baseline: "" });
	const { guard } = makeGuard(socket);
	guard.loadWarningCount = 2;
	guard.bumpMatches();
	guard.bumpMatches();
	const state = guard.renderState();
	assert.equal(state.loadWarnings, 2);
	assert.equal(state.matchesThisRun, 2);
	const dashboard = renderDashboard(state);
	assert.match(dashboard, /\(\+2 load warnings\)/);
	assert.match(dashboard, /matches this run:/);
	assert.doesNotMatch(dashboard, /matches today:/);

	const restarted = makeGuard(new FakeSocket({ baseline: "" })).guard;
	assert.equal(restarted.renderState().matchesThisRun, 0);
});

test("lower-severity flood traffic never suppresses an interrupt", async () => {
	const socket = new FakeSocket({ baseline: "" });
	const { guard } = makeGuard(socket, { now: () => 100_000 });
	await guard.bootstrap();
	for (let index = 0; index < 10; index++) {
		assert.equal(guard.rateLimiter.allow("p1", 99_000 + index), true);
	}
	await guard.handleMatch(
		guard.panes.get("p1"),
		{ rule: interruptRule, line: "$ danger after flood" },
		"test",
	);
	assert.equal(
		socket.calls.filter((call) => call.method === "pane.send_keys").length,
		1,
	);
});

test("failed bootstrap retries while the socket remains connected", async () => {
	const socket = new FakeSocket();
	socket.connected = true;
	const { guard } = makeGuard(socket, { bootstrapRetryMs: 5 });
	let attempts = 0;
	guard.bootstrap = async () => {
		attempts += 1;
		guard.connected = true;
	};
	guard.scheduleBootstrapRetry(new Error("temporary bootstrap failure"));
	await new Promise((resolve) => setTimeout(resolve, 20));
	assert.equal(attempts, 1);
	assert.equal(guard.connected, true);
	guard.stop();
});

test("initial connection failure recovers and performs the first bootstrap", async () => {
	const socket = new FakeSocket({ baseline: "" });
	socket.connected = false;
	socket.connect = async () => {
		const error = new Error("server unavailable");
		socket.emit("disconnected", error);
		setTimeout(() => {
			socket.connected = true;
			socket.emit("reconnected");
		}, 10);
		throw error;
	};
	const { guard } = makeGuard(socket);
	await guard.start();
	assert.equal(guard.connected, false);
	await new Promise((resolve) => setTimeout(resolve, 30));
	assert.equal(socket.snapshotCount, 1);
	assert.equal(guard.connected, true);
	guard.stop();
});

test("socket disconnect is audibly fail-visible and audited", async () => {
	const socket = new FakeSocket();
	let notices = 0;
	const { guard, entries } = makeGuard(socket, {
		onDisconnect: () => {
			notices += 1;
		},
	});
	await guard.start();
	socket.emit("disconnected");
	assert.equal(guard.connected, false);
	assert.equal(notices, 1);
	assert.ok(entries.some((entry) => entry.action_taken === "disconnected"));
	guard.stop();
});

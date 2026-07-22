// herdr-socket.mjs — NDJSON client for the herdr socket API.
// One multiplexed connection: requests resolve by id; subscriptions ack then
// route pushed lines with the same id to their handler. Reconnect exposes a
// 'reconnected' event so the watcher can re-bootstrap from scratch (the
// server does not resume subscriptions).

import net from "node:net";
import { EventEmitter } from "node:events";

export class HerdrSocket extends EventEmitter {
	constructor(
		socketPath,
		{ minDelayMs = 500, maxDelayMs = 30_000, connectTimeoutMs = 10_000 } = {},
	) {
		super();
		this.socketPath = socketPath;
		this.minDelayMs = minDelayMs;
		this.maxDelayMs = maxDelayMs;
		this.connectTimeoutMs = connectTimeoutMs;
		this.conn = null;
		this.buffer = "";
		this.nextId = 1;
		this.pending = new Map(); // id -> {resolve, reject, timer}
		this.subscriptions = new Map(); // id -> onEvent
		this.subscriptionCallbacks = new Set(); // Herdr 0.7.5 id-less events
		this.closedByUs = false;
		this.retryMs = minDelayMs;
		this.retryTimer = null;
		this.connected = false;
	}

	connect() {
		return new Promise((resolve, reject) => {
			const conn = net.createConnection(this.socketPath);
			let settled = false;
			const timer = setTimeout(() => {
				if (settled) return;
				settled = true;
				conn.destroy();
				reject(new Error("connect timeout"));
			}, this.connectTimeoutMs);

			conn.on("connect", () => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				this.conn = conn;
				this.connected = true;
				this.retryMs = this.minDelayMs;
				this.#wire(conn);
				resolve();
			});
			conn.on("error", (err) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				reject(err);
			});
		});
	}

	#wire(conn) {
		conn.setEncoding("utf8");
		conn.on("data", (chunk) => {
			this.buffer += chunk;
			let idx;
			while ((idx = this.buffer.indexOf("\n")) !== -1) {
				const line = this.buffer.slice(0, idx);
				this.buffer = this.buffer.slice(idx + 1);
				if (line.trim()) this.#handleLine(line);
			}
		});
		conn.on("error", () => {
			/* close follows; handled there */
		});
		conn.on("close", () => {
			const wasConnected = this.connected;
			this.connected = false;
			this.conn = null;
			this.#failAll(new Error("socket closed"));
			this.subscriptions.clear();
			this.subscriptionCallbacks.clear();
			if (!this.closedByUs) {
				if (wasConnected) this.emit("disconnected");
				this.#scheduleReconnect();
			}
		});
	}

	#handleLine(line) {
		let msg;
		try {
			msg = JSON.parse(line);
		} catch {
			this.emit("protocol-error", line);
			return;
		}
		const id = msg?.id;
		if (id !== undefined && this.subscriptions.has(id)) {
			this.subscriptions.get(id)(msg);
			return;
		}
		if (typeof msg?.event === "string" && msg.data !== undefined) {
			for (const callback of this.subscriptionCallbacks) callback(msg);
			return;
		}
		if (id !== undefined && this.pending.has(id)) {
			const { resolve, reject, timer, onEvent } = this.pending.get(id);
			this.pending.delete(id);
			clearTimeout(timer);
			if (msg.error) {
				const err = new Error(msg.error.message ?? "request failed");
				err.code = msg.error.code;
				reject(err);
			} else if (onEvent) {
				// Subscribe ack: move to subscription routing
				this.subscriptions.set(id, onEvent);
				this.subscriptionCallbacks.add(onEvent);
				resolve({ subscriptionId: id, ack: msg.result });
			} else {
				resolve(msg.result);
			}
			return;
		}
		this.emit("unsolicited", msg);
	}

	request(method, params = {}, { timeoutMs = 15_000, onEvent = null } = {}) {
		return new Promise((resolve, reject) => {
			if (!this.conn || !this.connected) {
				reject(new Error("not connected"));
				return;
			}
			const id = `g${this.nextId++}`;
			const timer = setTimeout(() => {
				this.pending.delete(id);
				const callback = this.subscriptions.get(id);
				this.subscriptions.delete(id);
				if (callback) this.subscriptionCallbacks.delete(callback);
				reject(new Error(`timeout: ${method}`));
			}, timeoutMs);
			this.pending.set(id, { resolve, reject, timer, onEvent });
			this.conn.write(`${JSON.stringify({ id, method, params })}\n`);
		});
	}

	/** events.subscribe; resolves with {subscriptionId, ack} after the ack. */
	subscribe(subscriptions, onEvent, opts = {}) {
		return this.request(
			"events.subscribe",
			{ subscriptions },
			{ ...opts, onEvent },
		);
	}

	#failAll(err) {
		for (const { reject, timer } of this.pending.values()) {
			clearTimeout(timer);
			reject(err);
		}
		this.pending.clear();
	}

	#scheduleReconnect() {
		if (this.closedByUs) return;
		this.emit("reconnecting", this.retryMs);
		this.retryTimer = setTimeout(async () => {
			try {
				await this.connect();
				this.emit("reconnected");
			} catch {
				this.#scheduleReconnect();
			}
		}, this.retryMs);
		this.retryMs = Math.min(this.retryMs * 2, this.maxDelayMs);
	}

	close() {
		this.closedByUs = true;
		if (this.retryTimer) clearTimeout(this.retryTimer);
		if (this.conn) this.conn.destroy();
		this.#failAll(new Error("closed"));
		this.connected = false;
	}
}

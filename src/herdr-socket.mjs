// herdr-socket.mjs — NDJSON client for the Herdr socket API.
// Herdr accepts one request per connection. RPC connections close after their
// response, while each events.subscribe call owns a dedicated streaming socket.

import net from "node:net";
import { EventEmitter } from "node:events";

function responseError(message) {
	const error = new Error(message?.error?.message ?? "request failed");
	error.code = message?.error?.code;
	return error;
}

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
		this.nextId = 1;
		this.requests = new Set();
		this.subscriptions = new Set();
		this.generation = 0;
		this.closedByUs = false;
		this.outage = false;
		this.retryMs = minDelayMs;
		this.retryTimer = null;
		this.connected = false;
	}

	async connect() {
		if (this.closedByUs) throw new Error("closed");
		const generation = this.generation;
		await this.#probe();
		if (this.closedByUs || generation !== this.generation)
			throw new Error("connection superseded");
		this.connected = true;
		this.outage = false;
		this.retryMs = this.minDelayMs;
	}

	#probe() {
		return new Promise((resolve, reject) => {
			const connection = net.createConnection(this.socketPath);
			let settled = false;
			const finish = (error = null) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				connection.destroy();
				if (error) reject(error);
				else resolve();
			};
			const timer = setTimeout(
				() => finish(new Error("connect timeout")),
				this.connectTimeoutMs,
			);
			connection.once("connect", () => finish());
			connection.once("error", finish);
			connection.once("close", () => finish(new Error("socket closed")));
		});
	}

	request(method, params = {}, { timeoutMs = 15_000 } = {}) {
		return new Promise((resolve, reject) => {
			if (this.closedByUs) {
				reject(new Error("closed"));
				return;
			}
			if (!this.connected) {
				reject(new Error("not connected"));
				return;
			}

			const id = `g${this.nextId++}`;
			const connection = net.createConnection(this.socketPath);
			const record = { connection, reject: null, settled: false };
			let buffer = "";
			let lastError = null;

			const finish = (error = null, result = undefined) => {
				if (record.settled) return;
				record.settled = true;
				clearTimeout(timer);
				this.requests.delete(record);
				connection.destroy();
				if (error) reject(error);
				else resolve(result);
			};
			record.reject = (error) => finish(error);
			this.requests.add(record);

			const timer = setTimeout(
				() => finish(new Error(`timeout: ${method}`)),
				timeoutMs,
			);
			connection.setEncoding("utf8");
			connection.once("connect", () => {
				connection.write(`${JSON.stringify({ id, method, params })}\n`);
			});
			connection.on("data", (chunk) => {
				buffer += chunk;
				let index;
				while ((index = buffer.indexOf("\n")) !== -1) {
					const line = buffer.slice(0, index);
					buffer = buffer.slice(index + 1);
					if (!line.trim()) continue;
					let message;
					try {
						message = JSON.parse(line);
					} catch {
						this.emit("protocol-error", line);
						finish(new Error("invalid JSON from Herdr socket"));
						return;
					}
					if (message?.id !== id) {
						this.emit("unsolicited", message);
						continue;
					}
					if (message.error) finish(responseError(message));
					else finish(null, message.result);
					return;
				}
			});
			connection.on("error", (error) => {
				lastError = error;
			});
			connection.on("close", () => {
				if (!record.settled) finish(lastError ?? new Error("socket closed"));
			});
		});
	}

	/** Start one streaming events.subscribe connection. */
	subscribe(subscriptions, onEvent, { timeoutMs = 15_000 } = {}) {
		return new Promise((resolve, reject) => {
			if (this.closedByUs) {
				reject(new Error("closed"));
				return;
			}
			if (!this.connected) {
				reject(new Error("not connected"));
				return;
			}

			const id = `g${this.nextId++}`;
			const connection = net.createConnection(this.socketPath);
			const record = {
				id,
				connection,
				reject,
				settled: false,
				acknowledged: false,
				intentional: false,
			};
			let buffer = "";
			let lastError = null;
			this.subscriptions.add(record);

			const failBeforeAck = (error) => {
				if (record.settled) return;
				record.settled = true;
				clearTimeout(timer);
				reject(error);
			};
			const timer = setTimeout(() => {
				lastError = new Error("timeout: events.subscribe");
				failBeforeAck(lastError);
				connection.destroy();
			}, timeoutMs);
			record.timer = timer;

			connection.setEncoding("utf8");
			connection.once("connect", () => {
				connection.write(
					`${JSON.stringify({ id, method: "events.subscribe", params: { subscriptions } })}\n`,
				);
			});
			connection.on("data", (chunk) => {
				buffer += chunk;
				let index;
				while ((index = buffer.indexOf("\n")) !== -1) {
					const line = buffer.slice(0, index);
					buffer = buffer.slice(index + 1);
					if (!line.trim()) continue;
					let message;
					try {
						message = JSON.parse(line);
					} catch {
						this.emit("protocol-error", line);
						lastError = new Error("invalid JSON from Herdr socket");
						if (!record.acknowledged) failBeforeAck(lastError);
						connection.destroy();
						return;
					}

					if (!record.acknowledged && message?.id === id) {
						if (message.error) {
							record.intentional = true;
							lastError = responseError(message);
							failBeforeAck(lastError);
							connection.destroy();
							return;
						}
						record.acknowledged = true;
						record.settled = true;
						clearTimeout(timer);
						resolve({ subscriptionId: id, ack: message.result });
						continue;
					}

					if (typeof message?.event === "string" && message.data !== undefined) {
						try {
							onEvent(message);
						} catch (error) {
							this.emit("callback-error", error);
						}
						continue;
					}
					this.emit("unsolicited", message);
				}
			});
			connection.on("error", (error) => {
				lastError = error;
			});
			connection.on("close", () => {
				this.subscriptions.delete(record);
				if (!record.acknowledged) {
					failBeforeAck(lastError ?? new Error("socket closed"));
					return;
				}
				if (!record.intentional && !this.closedByUs) {
					this.#handleOutage(lastError ?? new Error("socket closed"));
				}
			});
		});
	}

	#closeRequests(error) {
		for (const record of [...this.requests]) record.reject(error);
	}

	unsubscribe(subscriptionId, error = new Error("subscription closed")) {
		const record = [...this.subscriptions].find(
			(candidate) => candidate.id === subscriptionId,
		);
		if (!record) return;
		clearTimeout(record.timer);
		record.intentional = true;
		if (!record.acknowledged && !record.settled) {
			record.settled = true;
			record.reject(error);
		}
		record.connection.destroy();
		this.subscriptions.delete(record);
	}

	clearSubscriptions(error = new Error("subscriptions reset")) {
		for (const record of [...this.subscriptions])
			this.unsubscribe(record.id, error);
	}

	#handleOutage(error) {
		if (this.closedByUs || this.outage) return;
		this.outage = true;
		this.connected = false;
		this.clearSubscriptions(error);
		this.emit("disconnected", error);
		this.#scheduleReconnect();
	}

	#scheduleReconnect() {
		if (this.closedByUs || this.retryTimer) return;
		const delay = this.retryMs;
		this.retryMs = Math.min(this.retryMs * 2, this.maxDelayMs);
		this.emit("reconnecting", delay);
		const generation = this.generation;
		this.retryTimer = setTimeout(async () => {
			this.retryTimer = null;
			try {
				await this.#probe();
				if (this.closedByUs || generation !== this.generation) return;
				this.connected = true;
				this.outage = false;
				this.retryMs = this.minDelayMs;
				this.emit("reconnected");
			} catch {
				if (!this.closedByUs && generation === this.generation)
					this.#scheduleReconnect();
			}
		}, delay);
		this.retryTimer.unref?.();
	}

	/** Drop active work and confirm that a fresh Herdr connection is available. */
	async resetConnection() {
		if (this.closedByUs) throw new Error("closed");
		const generation = ++this.generation;
		if (this.retryTimer) clearTimeout(this.retryTimer);
		this.retryTimer = null;
		this.connected = false;
		this.outage = false;
		this.#closeRequests(new Error("connection reset"));
		this.clearSubscriptions(new Error("connection reset"));
		try {
			await this.#probe();
			if (this.closedByUs || generation !== this.generation)
				throw new Error("connection superseded");
			this.connected = true;
			this.retryMs = this.minDelayMs;
		} catch (error) {
			if (this.closedByUs || generation !== this.generation) throw error;
			this.outage = true;
			this.#scheduleReconnect();
			throw error;
		}
	}

	close() {
		if (this.closedByUs) return;
		this.closedByUs = true;
		this.generation += 1;
		if (this.retryTimer) clearTimeout(this.retryTimer);
		this.retryTimer = null;
		this.#closeRequests(new Error("closed"));
		this.clearSubscriptions(new Error("closed"));
		this.connected = false;
		this.outage = false;
	}
}

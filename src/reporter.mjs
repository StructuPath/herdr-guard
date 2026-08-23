// reporter.mjs — harness reporter ingest for herdr-guard.
//
// Pane-watching sees rendered text and can only *request* an interrupt after
// the fact. Harness reporters invert that: an agent harness (Claude Code
// PreToolUse hook, Pi extension) reports each tool call BEFORE execution and
// can honor a deny verdict — the one place in the system where prevention is
// actually possible. The guard stays the single policy brain; the transport
// is one NDJSON request/response line over a local unix socket.
//
// The socket lives at a well-known per-user path (not the per-session herdr
// state dir) because reporters run inside agent processes that do not have
// herdr's plugin environment. Directory 0700, socket 0600. Everything is
// fail-open by design on the reporter side; on the guard side an unreachable
// reporter socket is logged and visible, never fatal to the pane watcher.

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

export const MAX_LINE_BYTES = 256 * 1024;
export const CONNECTION_IDLE_TIMEOUT_MS = 10_000;

/** Well-known rendezvous path shared with reporters running outside herdr. */
export function defaultReporterSocketPath(env = process.env) {
	const stateHome =
		env.XDG_STATE_HOME && env.XDG_STATE_HOME.length > 0
			? env.XDG_STATE_HOME
			: path.join(os.homedir(), ".local", "state");
	return path.join(stateHome, "herdr-guard", "reporter.sock");
}

/**
 * Probe an existing socket file: "free" (no file), "stale" (file, nobody
 * listening — safe to unlink), or "live" (another guard is serving it).
 */
export function probeSocket(socketPath) {
	return new Promise((resolve) => {
		if (!fs.existsSync(socketPath)) return resolve("free");
		const probe = net.connect(socketPath);
		const done = (state) => {
			probe.destroy();
			resolve(state);
		};
		probe.once("connect", () => done("live"));
		probe.once("error", () => done("stale"));
		probe.setTimeout(1_000, () => done("live"));
	});
}

export class ReporterServer {
	constructor({ socketPath, handleReport }) {
		this.socketPath = socketPath;
		this.handleReport = handleReport;
		this.server = null;
	}

	async start() {
		const state = await probeSocket(this.socketPath);
		if (state === "live") {
			throw new Error(
				`another guard is already serving ${this.socketPath}`,
			);
		}
		fs.mkdirSync(path.dirname(this.socketPath), {
			recursive: true,
			mode: 0o700,
		});
		fs.chmodSync(path.dirname(this.socketPath), 0o700);
		if (state === "stale") fs.rmSync(this.socketPath, { force: true });

		this.server = net.createServer((connection) =>
			this.onConnection(connection),
		);
		await new Promise((resolve, reject) => {
			this.server.once("error", reject);
			this.server.listen(this.socketPath, () => {
				this.server.removeListener("error", reject);
				resolve();
			});
		});
		try {
			fs.chmodSync(this.socketPath, 0o600);
		} catch {
			/* some platforms ignore socket modes; the 0700 dir is the gate */
		}
		this.server.unref?.();
	}

	onConnection(connection) {
		let buffer = "";
		connection.setTimeout(CONNECTION_IDLE_TIMEOUT_MS, () =>
			connection.destroy(),
		);
		connection.on("error", () => {});
		connection.on("data", (chunk) => {
			buffer += chunk.toString("utf8");
			if (Buffer.byteLength(buffer) > MAX_LINE_BYTES) {
				connection.write(
					`${JSON.stringify({ ok: false, error: "request too large" })}\n`,
				);
				connection.destroy();
				return;
			}
			let newline = buffer.indexOf("\n");
			while (newline !== -1) {
				const line = buffer.slice(0, newline);
				buffer = buffer.slice(newline + 1);
				this.respond(connection, line);
				newline = buffer.indexOf("\n");
			}
		});
	}

	async respond(connection, line) {
		let response;
		try {
			const request = JSON.parse(line);
			response = await Promise.resolve(this.handleReport(request));
		} catch (error) {
			response = { ok: false, error: `bad request: ${error.message}` };
		}
		if (!connection.destroyed)
			connection.write(`${JSON.stringify(response)}\n`);
	}

	close() {
		this.server?.close();
		this.server = null;
		fs.rmSync(this.socketPath, { force: true });
	}
}

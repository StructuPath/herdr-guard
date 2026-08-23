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
//
// Ownership rules (two guards must never fight over the rendezvous point):
// a pid lock file is claimed atomically (O_EXCL) before binding, so
// concurrent starters cannot both unlink-and-listen; close() only removes
// the socket and lock this instance actually owns, so a loser's shutdown
// can never delete the surviving guard's live socket.

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

/**
 * Create the socket's parent directory 0700 only when it does not already
 * exist. The path is user-overridable, so never chmod a pre-existing
 * directory — pointing the socket into $HOME or /tmp must not change their
 * permissions (or fail on EPERM).
 */
function ensureSocketDir(socketPath) {
	const dir = path.dirname(socketPath);
	const created = fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	if (created) {
		try {
			fs.chmodSync(dir, 0o700);
		} catch {
			/* best effort — the mkdir mode already applied on most platforms */
		}
	}
}

function processAlive(pid) {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return error.code === "EPERM";
	}
}

export class ReporterServer {
	constructor({ socketPath, handleReport }) {
		this.socketPath = socketPath;
		this.lockPath = `${socketPath}.lock`;
		this.handleReport = handleReport;
		this.server = null;
		this.owned = false;
		this.lockHeld = false;
	}

	async start() {
		if ((await probeSocket(this.socketPath)) === "live") {
			throw new Error(`another guard is already serving ${this.socketPath}`);
		}
		ensureSocketDir(this.socketPath);
		this.claimLock();
		try {
			// Only the lock holder may reclaim a stale socket file and bind.
			fs.rmSync(this.socketPath, { force: true });
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
			this.owned = true;
			this.server.unref?.();
		} catch (error) {
			this.server?.close();
			this.server = null;
			this.releaseLock();
			throw error;
		}
	}

	/** Atomic (O_EXCL) pid-lock claim; a dead holder's lock is reclaimed. */
	claimLock() {
		for (let attempt = 0; attempt < 2; attempt++) {
			try {
				const descriptor = fs.openSync(this.lockPath, "wx", 0o600);
				fs.writeSync(descriptor, String(process.pid));
				fs.closeSync(descriptor);
				this.lockHeld = true;
				return;
			} catch (error) {
				if (error.code !== "EEXIST") throw error;
				let holder = NaN;
				try {
					holder = Number.parseInt(
						fs.readFileSync(this.lockPath, "utf8"),
						10,
					);
				} catch {
					/* unreadable lock — treat as stale below */
				}
				if (Number.isInteger(holder) && holder > 0 && processAlive(holder)) {
					throw new Error(
						`another guard (pid ${holder}) holds ${this.lockPath}`,
					);
				}
				fs.rmSync(this.lockPath, { force: true });
			}
		}
		throw new Error(`could not claim ${this.lockPath}`);
	}

	releaseLock() {
		if (!this.lockHeld) return;
		this.lockHeld = false;
		fs.rmSync(this.lockPath, { force: true });
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

	/** Removes only what this instance owns — never a surviving guard's socket. */
	close() {
		this.server?.close();
		this.server = null;
		if (this.owned) {
			this.owned = false;
			fs.rmSync(this.socketPath, { force: true });
		}
		this.releaseLock();
	}
}

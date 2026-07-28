import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export function guardSessionStateDir(stateDir, socketPath) {
	if (typeof socketPath !== "string" || socketPath.length === 0)
		throw new Error("HERDR_SOCKET_PATH is not set");
	const sessionKey = createHash("sha256").update(socketPath).digest("hex");
	return path.join(stateDir, "sessions", sessionKey);
}

export function ensureGuardSessionStateDir(stateDir, socketPath) {
	fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
	fs.chmodSync(stateDir, 0o700);
	const sessionStateDir = guardSessionStateDir(stateDir, socketPath);
	fs.mkdirSync(sessionStateDir, { recursive: true, mode: 0o700 });
	fs.chmodSync(sessionStateDir, 0o700);
	return sessionStateDir;
}

export function recordGuardPaneId(stateDir, socketPath, paneId) {
	const sessionStateDir = ensureGuardSessionStateDir(stateDir, socketPath);
	const paneIdPath = path.join(sessionStateDir, "guard-pane.id");
	const tempPath = `${paneIdPath}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
	let descriptor = null;
	try {
		descriptor = fs.openSync(tempPath, "wx", 0o600);
		fs.writeFileSync(descriptor, paneId);
		fs.fsyncSync(descriptor);
		fs.closeSync(descriptor);
		descriptor = null;
		fs.renameSync(tempPath, paneIdPath);
		const directory = fs.openSync(sessionStateDir, "r");
		try {
			fs.fsyncSync(directory);
		} finally {
			fs.closeSync(directory);
		}
	} finally {
		if (descriptor !== null) fs.closeSync(descriptor);
		fs.rmSync(tempPath, { force: true });
	}
	return paneIdPath;
}

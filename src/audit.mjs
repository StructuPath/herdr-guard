// audit.mjs — partitioned JSONL audit log.
// Severity-partitioned so a match flood cannot evict interrupt history;
// every event-derived string is sanitized + redacted + truncated before write.

import fs from "node:fs";
import path from "node:path";
import { cleanField } from "./policy.mjs";

const MAX_BYTES = 10 * 1024 * 1024; // 10MB
const GENERATIONS = 3;

const SCALAR_FIELDS = new Set([
	"rule_id",
	"severity",
	"matched_text",
	"process_argv",
	"cwd",
	"pane_id",
	"workspace_id",
	"pane_type",
	"action_taken",
	"source",
	"note",
]);

export class AuditLog {
	constructor(stateDir, { maxBytes = MAX_BYTES, generations = GENERATIONS } = {}) {
		this.stateDir = stateDir;
		this.maxBytes = maxBytes;
		this.generations = generations;
		fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
		fs.chmodSync(stateDir, 0o700);
		this.files = {
			interrupt: path.join(stateDir, "audit.interrupt.jsonl"),
			general: path.join(stateDir, "audit.jsonl"),
		};
		for (const file of Object.values(this.files)) this.#ensureFile(file);
	}

	#ensureFile(file) {
		if (!fs.existsSync(file)) {
			fs.writeFileSync(file, "", { mode: 0o600 });
		}
		fs.chmodSync(file, 0o600);
	}

	/** Rotate file -> .1 -> .2 -> .3 (oldest dropped). Permissions preserved. */
	#rotate(file) {
		for (let i = this.generations - 1; i >= 1; i--) {
			const from = `${file}.${i}`;
			const to = `${file}.${i + 1}`;
			if (fs.existsSync(from)) fs.renameSync(from, to);
		}
		if (fs.existsSync(file)) fs.renameSync(file, `${file}.1`);
		this.#ensureFile(file);
	}

	/**
	 * Append one entry. Scalar event-derived fields are cleaned; structured
	 * fields (ts, counts) pass through. severity === "interrupt" partitions
	 * into audit.interrupt.jsonl.
	 */
	write(entry) {
		const clean = { ...entry };
		for (const [key, value] of Object.entries(clean)) {
			if (SCALAR_FIELDS.has(key) && typeof value === "string") {
				clean[key] = cleanField(value);
			}
		}
		const file =
			entry?.severity === "interrupt"
				? this.files.interrupt
				: this.files.general;
		try {
			if (fs.statSync(file).size >= this.maxBytes) this.#rotate(file);
		} catch {
			/* stat failed — write anyway, rotation is best-effort */
		}
		fs.appendFileSync(file, `${JSON.stringify(clean)}\n`);
	}

	/** Last n entries across both partitions, newest last. Best-effort. */
	tail(n = 10) {
		const entries = [];
		for (const file of Object.values(this.files)) {
			const candidates = [file];
			for (let i = 1; i <= this.generations; i++) candidates.push(`${file}.${i}`);
			for (const candidate of candidates) {
				try {
					const lines = fs
						.readFileSync(candidate, "utf8")
						.split("\n")
						.filter(Boolean);
					for (const line of lines) {
						try {
							entries.push(JSON.parse(line));
						} catch {
							/* skip corrupt line */
						}
					}
				} catch {
					/* missing file */
				}
			}
		}
		entries.sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0));
		return entries.slice(-n);
	}
}

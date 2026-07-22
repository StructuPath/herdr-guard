import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { HerdrSocket } from "../src/herdr-socket.mjs";

test("socket requests and subscription events route by id", async () => {
	const socketPath = path.join(
		os.tmpdir(),
		`guard-${process.pid}-${Date.now()}.sock`,
	);
	const server = net.createServer((conn) => {
		let buf = "";
		conn.setEncoding("utf8");
		conn.on("data", (chunk) => {
			buf += chunk;
			let i;
			while ((i = buf.indexOf("\n")) >= 0) {
				const msg = JSON.parse(buf.slice(0, i));
				buf = buf.slice(i + 1);
				if (msg.method === "ping")
					conn.write(
						JSON.stringify({ id: msg.id, result: { type: "pong" } }) + "\n",
					);
				else if (msg.method === "events.subscribe") {
					conn.write(
						JSON.stringify({
							id: msg.id,
							result: { type: "subscription_ack" },
						}) + "\n",
					);
					setTimeout(
						() =>
							conn.write(
								JSON.stringify({
									id: msg.id,
									event: { type: "pane.output_matched", text: "$ guarded" },
								}) + "\n",
							),
						5,
					);
				}
			}
		});
	});
	await new Promise((resolve) => server.listen(socketPath, resolve));
	const client = new HerdrSocket(socketPath, { connectTimeoutMs: 1000 });
	await client.connect();
	assert.deepEqual(await client.request("ping"), { type: "pong" });
	const seen = new Promise((resolve) =>
		client.subscribe([{ type: "pane.created" }], (msg) => resolve(msg.event)),
	);
	assert.equal((await seen).type, "pane.output_matched");
	client.close();
	await new Promise((resolve) => server.close(resolve));
	try {
		fs.unlinkSync(socketPath);
	} catch {}
});

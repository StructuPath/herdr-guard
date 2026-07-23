import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { once } from "node:events";
import { HerdrSocket } from "../src/herdr-socket.mjs";

function socketPath() {
	return path.join(
		os.tmpdir(),
		`guard-${process.pid}-${Date.now()}-${Math.random()}.sock`,
	);
}

function startProtocolServer(target, onConnection = null) {
	const server = net.createServer((conn) => {
		onConnection?.(conn);
		let buffer = "";
		conn.setEncoding("utf8");
		conn.on("data", (chunk) => {
			buffer += chunk;
			let index;
			while ((index = buffer.indexOf("\n")) >= 0) {
				const message = JSON.parse(buffer.slice(0, index));
				buffer = buffer.slice(index + 1);
				if (message.method === "ping") {
					conn.write(
						`${JSON.stringify({ id: message.id, result: { type: "pong" } })}\n`,
					);
				} else if (message.method === "events.subscribe") {
					conn.write(
						`${JSON.stringify({ id: message.id, result: { type: "subscription_ack" } })}\n`,
					);
					setTimeout(() => {
						conn.write(
							`${JSON.stringify({ event: "pane.output_matched", data: { pane_id: "p1", matched_line: "$ guarded", read: { text: "$ guarded" } } })}\n`,
						);
					}, 5);
				}
			}
		});
	});
	return new Promise((resolve) => server.listen(target, () => resolve(server)));
}

async function closeServer(server, target) {
	await new Promise((resolve) => server.close(resolve));
	try {
		fs.unlinkSync(target);
	} catch {}
}

test("routes real Herdr 0.7.5 id-less subscription envelopes", async () => {
	const target = socketPath();
	const server = await startProtocolServer(target);
	const client = new HerdrSocket(target, { connectTimeoutMs: 1000 });
	await client.connect();
	assert.deepEqual(await client.request("ping"), { type: "pong" });
	const seen = new Promise((resolve) =>
		client.subscribe([{ type: "pane.created" }], resolve),
	);
	const event = await seen;
	assert.equal(event.event, "pane.output_matched");
	assert.equal(event.data.pane_id, "p1");
	client.close();
	await closeServer(server, target);
});

test("reconnect retries after an initial failed attempt", async () => {
	const target = socketPath();
	let activeConnection;
	let server = await startProtocolServer(target, (conn) => {
		activeConnection = conn;
	});
	const client = new HerdrSocket(target, {
		minDelayMs: 15,
		maxDelayMs: 30,
		connectTimeoutMs: 50,
	});
	await client.connect();
	const reconnected = once(client, "reconnected");
	activeConnection.destroy();
	await closeServer(server, target);
	// Let the first reconnect attempt fail, then restore the server.
	await new Promise((resolve) => setTimeout(resolve, 35));
	server = await startProtocolServer(target);
	await Promise.race([
		reconnected,
		new Promise((_, reject) =>
			setTimeout(() => reject(new Error("reconnect timeout")), 1000),
		),
	]);
	assert.equal(client.connected, true);
	client.close();
	await closeServer(server, target);
});

test("resetConnection schedules recovery when its immediate reconnect fails", async () => {
	const target = socketPath();
	let activeConnection;
	let server = await startProtocolServer(target, (connection) => {
		activeConnection = connection;
	});
	const client = new HerdrSocket(target, {
		minDelayMs: 15,
		maxDelayMs: 30,
		connectTimeoutMs: 50,
	});
	await client.connect();
	activeConnection.destroy();
	await closeServer(server, target);
	await assert.rejects(client.resetConnection());
	const reconnected = once(client, "reconnected");
	await new Promise((resolve) => setTimeout(resolve, 35));
	server = await startProtocolServer(target);
	await Promise.race([
		reconnected,
		new Promise((_, reject) =>
			setTimeout(() => reject(new Error("reset reconnect timeout")), 1000),
		),
	]);
	assert.equal(client.connected, true);
	client.close();
	await closeServer(server, target);
});

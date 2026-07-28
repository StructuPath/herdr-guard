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

function startProtocolServer(target) {
	const connections = new Set();
	const requests = [];
	const server = net.createServer((connection) => {
		const record = { connection, messages: [], subscription: false };
		connections.add(record);
		connection.on("close", () => connections.delete(record));
		connection.setEncoding("utf8");
		let buffer = "";
		connection.on("data", (chunk) => {
			buffer += chunk;
			let index;
			while ((index = buffer.indexOf("\n")) >= 0) {
				const message = JSON.parse(buffer.slice(0, index));
				buffer = buffer.slice(index + 1);
				record.messages.push(message);
				requests.push({ connection: record, message });

				// Herdr accepts exactly one request on each API connection.
				if (record.messages.length > 1) {
					connection.destroy();
					continue;
				}
				if (message.method === "events.subscribe") {
					record.subscription = true;
					if (message.params.subscriptions[0]?.pane_id === "missing") {
						connection.destroy();
						continue;
					}
					const ack = `${JSON.stringify({ id: message.id, result: { type: "subscription_started" } })}\n`;
					if (message.params.subscriptions[0]?.type === "pane.exited")
						connection.end(ack);
					else connection.write(ack);
				} else if (message.method === "hang") {
					// Exercise client timeout cleanup.
				} else {
					connection.end(
						`${JSON.stringify({ id: message.id, result: { type: "pong", method: message.method } })}\n`,
					);
				}
			}
		});
	});
	server.connections = connections;
	server.requests = requests;
	server.send = (record, message) => {
		record.connection.write(`${JSON.stringify(message)}\n`);
	};
	return new Promise((resolve) => server.listen(target, () => resolve(server)));
}

async function closeServer(server, target) {
	for (const { connection } of server.connections) connection.destroy();
	await new Promise((resolve) => server.close(resolve));
	try {
		fs.unlinkSync(target);
	} catch {}
}

function subscriptionRecord(server, type) {
	return server.requests.find(
		({ message }) =>
			message.method === "events.subscribe" &&
			message.params.subscriptions[0]?.type === type,
	)?.connection;
}

test("uses one-shot RPC sockets and a dedicated subscription socket", async () => {
	const target = socketPath();
	const server = await startProtocolServer(target);
	const client = new HerdrSocket(target, { connectTimeoutMs: 1000 });
	let disconnects = 0;
	client.on("disconnected", () => {
		disconnects += 1;
	});

	await client.connect();
	assert.deepEqual(await client.request("ping"), {
		type: "pong",
		method: "ping",
	});
	await client.subscribe([{ type: "pane.created" }], () => {});
	assert.deepEqual(await client.request("pane.read"), {
		type: "pong",
		method: "pane.read",
	});

	const requestConnections = server.requests.map(({ connection }) => connection);
	assert.equal(new Set(requestConnections).size, server.requests.length);
	assert.ok(requestConnections.every((record) => record.messages.length === 1));
	assert.equal(subscriptionRecord(server, "pane.created").connection.destroyed, false);
	assert.equal(disconnects, 0);

	client.close();
	await closeServer(server, target);
});

test("routes id-less events only to their dedicated subscription", async () => {
	const target = socketPath();
	const server = await startProtocolServer(target);
	const client = new HerdrSocket(target, { connectTimeoutMs: 1000 });
	await client.connect();

	const created = [];
	const closed = [];
	await client.subscribe([{ type: "pane.created" }], (event) =>
		created.push(event),
	);
	await client.subscribe([{ type: "pane.closed" }], (event) =>
		closed.push(event),
	);
	server.send(subscriptionRecord(server, "pane.created"), {
		event: "pane_created",
		data: { pane: { pane_id: "p1" } },
	});
	server.send(subscriptionRecord(server, "pane.closed"), {
		event: "pane_closed",
		data: { pane_id: "p2" },
	});
	await new Promise((resolve) => setTimeout(resolve, 10));

	assert.deepEqual(created.map((event) => event.event), ["pane_created"]);
	assert.deepEqual(closed.map((event) => event.event), ["pane_closed"]);

	client.close();
	await closeServer(server, target);
});

test("a rejected subscription does not tear down healthy streams", async () => {
	const target = socketPath();
	const server = await startProtocolServer(target);
	const client = new HerdrSocket(target, { connectTimeoutMs: 1000 });
	await client.connect();
	await client.subscribe([{ type: "pane.created" }], () => {});
	let disconnects = 0;
	client.on("disconnected", () => {
		disconnects += 1;
	});

	await assert.rejects(
		client.subscribe(
			[{ type: "pane.output_matched", pane_id: "missing" }],
			() => {},
		),
		/socket closed/,
	);
	await new Promise((resolve) => setTimeout(resolve, 10));

	assert.equal(client.connected, true);
	assert.equal(disconnects, 0);
	assert.equal(subscriptionRecord(server, "pane.created").connection.destroyed, false);

	client.close();
	await closeServer(server, target);
});

test("a dropped subscription emits one outage and reconnects once", async () => {
	const target = socketPath();
	const server = await startProtocolServer(target);
	const client = new HerdrSocket(target, {
		minDelayMs: 15,
		maxDelayMs: 30,
		connectTimeoutMs: 100,
	});
	await client.connect();
	await client.subscribe([{ type: "pane.created" }], () => {});

	let disconnects = 0;
	let reconnects = 0;
	client.on("disconnected", () => {
		disconnects += 1;
	});
	client.on("reconnected", () => {
		reconnects += 1;
	});
	const disconnected = once(client, "disconnected");
	const reconnected = once(client, "reconnected");
	subscriptionRecord(server, "pane.created").connection.destroy();
	await disconnected;
	await Promise.race([
		reconnected,
		new Promise((_, reject) =>
			setTimeout(() => reject(new Error("reconnect timeout")), 1000),
		),
	]);
	await new Promise((resolve) => setTimeout(resolve, 40));

	assert.equal(client.connected, true);
	assert.equal(disconnects, 1);
	assert.equal(reconnects, 1);

	client.close();
	await closeServer(server, target);
});

test("an acknowledged stream that closes immediately triggers recovery", async () => {
	const target = socketPath();
	const server = await startProtocolServer(target);
	const client = new HerdrSocket(target, {
		minDelayMs: 15,
		maxDelayMs: 30,
		connectTimeoutMs: 100,
	});
	await client.connect();
	const disconnected = once(client, "disconnected");
	const reconnected = once(client, "reconnected");

	await client.subscribe([{ type: "pane.exited" }], () => {});
	await disconnected;
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

test("overlapping resets cannot let an older generation corrupt readiness", async () => {
	const target = socketPath();
	const server = await startProtocolServer(target);
	const client = new HerdrSocket(target, { connectTimeoutMs: 1000 });
	await client.connect();
	let reconnects = 0;
	client.on("reconnected", () => {
		reconnects += 1;
	});

	const [older, newer] = await Promise.allSettled([
		client.resetConnection(),
		client.resetConnection(),
	]);
	assert.equal(older.status, "rejected");
	assert.match(older.reason.message, /connection superseded/);
	assert.equal(newer.status, "fulfilled");
	assert.equal(client.connected, true);
	assert.equal(client.outage, false);
	assert.equal(reconnects, 0);

	client.close();
	await closeServer(server, target);
});

test("reset intentionally replaces subscriptions without reporting an outage", async () => {
	const target = socketPath();
	const server = await startProtocolServer(target);
	const client = new HerdrSocket(target, { connectTimeoutMs: 1000 });
	await client.connect();
	await client.subscribe([{ type: "pane.created" }], () => {});
	const original = subscriptionRecord(server, "pane.created");
	let disconnects = 0;
	client.on("disconnected", () => {
		disconnects += 1;
	});

	await client.resetConnection();
	await new Promise((resolve) => setTimeout(resolve, 10));
	assert.equal(original.connection.destroyed, true);
	assert.equal(client.connected, true);
	assert.equal(disconnects, 0);

	await client.subscribe([{ type: "pane.closed" }], () => {});
	assert.equal(subscriptionRecord(server, "pane.closed").connection.destroyed, false);

	client.close();
	await closeServer(server, target);
});

test("times out and destroys an unresponsive one-shot request", async () => {
	const target = socketPath();
	const server = await startProtocolServer(target);
	const client = new HerdrSocket(target, { connectTimeoutMs: 1000 });
	await client.connect();

	await assert.rejects(
		client.request("hang", {}, { timeoutMs: 20 }),
		/timeout: hang/,
	);
	await new Promise((resolve) => setTimeout(resolve, 10));
	const hanging = server.requests.find(
		({ message }) => message.method === "hang",
	).connection;
	assert.equal(hanging.connection.destroyed, true);

	client.close();
	await closeServer(server, target);
});

import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { decodeDagCbor, encodeDagCbor } from "../src/repo/dag-cbor";
import { encodeBlock } from "../src/repo/cid";
import { decodeCar, encodeCar } from "../src/repo/car";

function nextFrame(socket: WebSocket): Promise<Uint8Array> {
	return new Promise((resolve, reject) => {
		socket.addEventListener("message", (event) => resolve(new Uint8Array(event.data as ArrayBuffer)), { once: true });
		socket.addEventListener("error", () => reject(new Error("WebSocket error")), { once: true });
	});
}

function nextFrames(socket: WebSocket, count: number): Promise<Uint8Array[]> {
	return new Promise((resolve, reject) => {
		const frames: Uint8Array[] = [];
		socket.addEventListener("message", (event) => {
			frames.push(new Uint8Array(event.data as ArrayBuffer));
			if (frames.length === count) resolve(frames);
		});
		socket.addEventListener("error", () => reject(new Error("WebSocket error")), { once: true });
	});
}

function decodeFrame(frame: Uint8Array) {
	const headerLength = encodeDagCbor({ op: 1, t: "#commit" }).length;
	return {
		header: decodeDagCbor<Record<string, unknown>>(frame.slice(0, headerLength)),
		payload: decodeDagCbor<Record<string, unknown>>(frame.slice(headerLength)),
	};
}

describe("subscribeRepos", () => {
	it("sequences identity and account events", async () => {
		const firehose = env.FIREHOSE.getByName("global");
		const subscription = await SELF.fetch("https://example.com/xrpc/com.atproto.sync.subscribeRepos", { headers: { upgrade: "websocket" } });
		const socket = subscription.webSocket!;
		socket.accept();
		const identityFrame = nextFrame(socket);
		const identitySeq = await firehose.publishIdentity("identity:test", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "alice.example.com");
		const identityHeader = encodeDagCbor({ op: 1, t: "#identity" }).length;
		expect(decodeDagCbor<Record<string, unknown>>((await identityFrame).slice(identityHeader))).toMatchObject({ seq: identitySeq, did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", handle: "alice.example.com" });
		const accountFrame = nextFrame(socket);
		const accountSeq = await firehose.publishAccount("account:test", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", true);
		const accountHeader = encodeDagCbor({ op: 1, t: "#account" }).length;
		expect(decodeDagCbor<Record<string, unknown>>((await accountFrame).slice(accountHeader))).toMatchObject({ seq: accountSeq, active: true });
		expect(accountSeq).toBe(identitySeq + 1);
		socket.close(1000, "done");
	});

	it("broadcasts commits and resumes from a cursor", async () => {
		const did = "did:plc:firehosetest";
		const repo = env.ACCOUNT_REPO.getByName(did);
		await repo.initialize(did);

		const subscription = await SELF.fetch("https://example.com/xrpc/com.atproto.sync.subscribeRepos", { headers: { upgrade: "websocket" } });
		expect(subscription.status).toBe(101);
		const socket = subscription.webSocket!;
		socket.accept();
		const incoming = nextFrame(socket);
		const commit = await repo.applyWrites([{ action: "create", path: "app.bsky.feed.post/firehose", record: { $type: "app.bsky.feed.post", text: "event" } }]);
		const live = decodeFrame(await incoming);
		expect(live.header).toEqual({ op: 1, t: "#commit" });
		expect(live.payload).toMatchObject({ seq: commit.seq, repo: did, rev: commit.rev, tooBig: false, rebase: false });
		expect((live.payload.blocks as Uint8Array).length).toBeGreaterThan(100);
		socket.close(1000, "done");
		await repo.applyWrites([{ action: "create", path: "app.bsky.feed.post/firehose-next", record: { $type: "app.bsky.feed.post", text: "next event" } }]);

		const resumed = await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.subscribeRepos?cursor=${commit.seq}`, { headers: { upgrade: "websocket" } });
		const resumedSocket = resumed.webSocket!;
		resumedSocket.accept();
		const replay = decodeFrame(await nextFrame(resumedSocket));
		expect(replay.payload.seq).toBe(commit.seq);
		resumedSocket.close(1000, "done");
	});

	it("uses a sync event when a commit exceeds the operation limit", async () => {
		const firehose = env.FIREHOSE.getByName("global");
		const subscription = await SELF.fetch("https://example.com/xrpc/com.atproto.sync.subscribeRepos", { headers: { upgrade: "websocket" } });
		const socket = subscription.webSocket!;
		socket.accept();
		const incoming = nextFrame(socket);
		const commit = await encodeBlock({ did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", rev: "3m2zfcijpj22a", data: null, sig: new Uint8Array() });
		await firehose.publishCommit({ id: "large-commit", repo: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", rev: "3m2zfcijpj22a", since: null, commit: commit.cid.toString(), blocks: encodeCar(commit.cid, [commit]), ops: Array.from({ length: 201 }, (_, index) => ({ action: "delete" as const, path: `example.test.record/${index}`, cid: null })), time: "2026-08-16T00:00:00.000Z" });
		const frame = await incoming;
		const headerLength = encodeDagCbor({ op: 1, t: "#sync" }).length;
		expect(decodeDagCbor(frame.slice(0, headerLength))).toEqual({ op: 1, t: "#sync" });
		const payload = decodeDagCbor<Record<string, unknown>>(frame.slice(headerLength));
		expect(payload).toMatchObject({ did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", rev: "3m2zfcijpj22a" });
		expect((await decodeCar(payload.blocks as Uint8Array)).blocks).toHaveLength(1);
		socket.close(1000, "done");
	});

	it("does not duplicate an event racing with cursor backfill", async () => {
		const firehose = env.FIREHOSE.getByName("global");
		const did = "did:plc:cursorbackfillrace";
		const cursor = await firehose.publishIdentity("race:cursor", did);
		const [subscription, next] = await Promise.all([
			SELF.fetch(`https://example.com/xrpc/com.atproto.sync.subscribeRepos?cursor=${cursor}`, { headers: { upgrade: "websocket" } }),
			firehose.publishIdentity("race:next", did),
		]);
		const socket = subscription.webSocket!;
		socket.accept();
		const headerLength = encodeDagCbor({ op: 1, t: "#identity" }).length;
		const sequences = (await nextFrames(socket, 2)).map((frame) => decodeDagCbor<{ seq: number }>(frame.slice(headerLength)).seq);
		expect(sequences).toEqual([cursor, next]);
		socket.close(1000, "done");
	});
});

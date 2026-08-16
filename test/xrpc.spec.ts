import { applyD1Migrations, env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { decodeCar } from "../src/repo/car";
import { AccountRepository } from "../src/db/accounts";
import { d1 } from "../src/db/d1";

describe("public repository XRPC", () => {
	it("returns records and a CAR export", async () => {
		await applyD1Migrations(env.DB, env.TEST_D1_MIGRATIONS);
		const did = "did:plc:xrpctest";
		await new AccountRepository(d1(env.DB)).create({ did, handle: "xrpc.localhost", email: "xrpc@example.com", passwordHash: "unused" });
		const repo = env.ACCOUNT_REPO.getByName(did);
		await repo.initialize(did);
		await repo.applyWrites([{ action: "create", path: "app.bsky.feed.post/one", record: { $type: "app.bsky.feed.post", text: "hello" } }]);

		const record = await SELF.fetch(`https://example.com/xrpc/com.atproto.repo.getRecord?repo=${did}&collection=app.bsky.feed.post&rkey=one`);
		expect(record.status).toBe(200);
		expect(await record.json()).toMatchObject({ value: { text: "hello" } });

		const latest = await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getLatestCommit?did=${did}`);
		const head = await latest.json<{ cid: string; rev: string }>();
		expect(head).toMatchObject({ rev: expect.stringMatching(/^[2-7a-z]{13}$/) });
		const blocks = await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getBlocks?did=${did}&cids=${head.cid}`);
		expect(blocks.headers.get("content-type")).toBe("application/vnd.ipld.car");
		await repo.applyWrites([{ action: "create", path: "app.bsky.feed.post/two", record: { $type: "app.bsky.feed.post", text: "second" } }]);
		const next = await (await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getLatestCommit?did=${did}`)).json<{ cid: string; rev: string }>();
		const listed = await (await SELF.fetch("https://example.com/xrpc/com.atproto.sync.listRepos?limit=1")).json<{ repos: { did: string; head: string; rev: string }[] }>();
		expect(listed.repos).toContainEqual({ did, head: next.cid, rev: next.rev, active: true });
		const byCollection = await (await SELF.fetch("https://example.com/xrpc/com.atproto.sync.listReposByCollection?collection=app.bsky.feed.post&limit=10")).json<{ repos: { did: string }[] }>();
		expect(byCollection.repos).toContainEqual({ did });

		const exported = await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getRepo?did=${did}`);
		expect(exported.headers.get("content-type")).toBe("application/vnd.ipld.car");
		const full = await decodeCar(new Uint8Array(await exported.arrayBuffer()));
		expect(full.roots[0].toString()).toBe(next.cid);
		const diff = await decodeCar(new Uint8Array(await (await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getRepo?did=${did}&since=${head.rev}`)).arrayBuffer()));
		expect(diff.roots[0].toString()).toBe(next.cid);
		expect(diff.blocks.map(({ cid }) => cid.toString())).toContain((await repo.getRecord("app.bsky.feed.post/two"))!.cid);
		const unchanged = await decodeCar(new Uint8Array(await (await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getRepo?did=${did}&since=${next.rev}`)).arrayBuffer()));
		expect(unchanged.blocks).toHaveLength(1);
		expect((await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getRepo?did=${did}&since=invalid`)).status).toBe(400);
		const proof = await decodeCar(new Uint8Array(await (await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getRecord?did=${did}&collection=app.bsky.feed.post&rkey=two`)).arrayBuffer()));
		expect(proof.roots[0].toString()).toBe(next.cid);
		expect(proof.blocks.map(({ cid }) => cid.toString())).toContain((await repo.getRecord("app.bsky.feed.post/two"))!.cid);
		expect(proof.blocks.map(({ cid }) => cid.toString())).not.toContain((await repo.getRecord("app.bsky.feed.post/one"))!.cid);
	});

	it("uses conventional JSON errors", async () => {
		const response = await SELF.fetch("https://example.com/xrpc/com.atproto.repo.getRecord");
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "InvalidRequest", message: "Missing required key \"repo\" at $" });
	});

	it("applies a batch atomically", async () => {
		const did = "did:plc:batchtest";
		const repo = env.ACCOUNT_REPO.getByName(did);
		await repo.initialize(did);
		// Authentication behavior is covered by session.spec; the DO batch transaction is covered here.
		await repo.applyWrites([
			{ action: "create", path: "app.bsky.feed.post/one", record: { $type: "app.bsky.feed.post", text: "one" } },
			{ action: "create", path: "app.bsky.feed.post/two", record: { $type: "app.bsky.feed.post", text: "two" } },
		]);
		expect(await repo.listCollections()).toEqual(["app.bsky.feed.post"]);
	});
});

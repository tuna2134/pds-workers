import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { cidForBytes } from "../src/repo/cid";
import { cleanupBlob } from "../src/blob/cleanup";
import { decodeCar } from "../src/repo/car";
import { decodeDagCbor } from "../src/repo/dag-cbor";
import type { CID } from "multiformats/cid";
import { formatDidKey } from "@atproto/crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { buildRepoCommit } from "../src/repo/update";
import { encodeBlock } from "../src/repo/cid";
import { formatTid } from "../src/repo/tid";
import { verifyRepoCar } from "@atproto/repo";

describe("AccountRepo", () => {
	it("isolates a DID and serializes record mutations", async () => {
		const repo = env.ACCOUNT_REPO.getByName("did:plc:testrepo");
		const initialized = await repo.initialize("did:plc:testrepo");
		expect(initialized.commit).toMatch(/^b/);

		const created = await repo.applyWrites([{ action: "create", path: "app.bsky.feed.post/one", record: { $type: "app.bsky.feed.post", text: "hello", createdAt: "2026-08-16T00:00:00.000Z" } }]);
		expect(created.rev > initialized.rev!).toBe(true);
		const exported = await decodeCar(await repo.exportRepo());
		expect(decodeDagCbor<{ prev: CID | null }>(exported.blocks[0].bytes).prev).toBeNull();
		const updated = await repo.applyWrites([{ action: "update", path: "app.bsky.feed.post/one", record: { $type: "app.bsky.feed.post", text: "updated", createdAt: "2026-08-16T00:00:00.000Z" } }]);
		const updatedCar = await decodeCar(await repo.exportRepo());
		expect(decodeDagCbor<{ prev: CID | null }>(updatedCar.blocks[0].bytes).prev).toBeNull();
		await Promise.all([
			repo.applyWrites([{ action: "create", path: "app.bsky.feed.post/two", record: { $type: "app.bsky.feed.post", text: "two" } }]),
			repo.applyWrites([{ action: "create", path: "app.bsky.feed.post/three", record: { $type: "app.bsky.feed.post", text: "three" } }]),
		]);
		expect((await repo.listRecords("app.bsky.feed.post")).length).toBe(3);
		expect((await repo.getRecord("app.bsky.feed.post/one"))?.value).toMatchObject({ text: "updated" });
		expect((await repo.exportRepo()).length).toBeGreaterThan(100);
		const deleted = await repo.applyWrites([{ action: "delete", path: "app.bsky.feed.post/one" }]);
		expect(deleted.rev > updated.rev).toBe(true);
	});

	it("commits repositories beyond the Durable Object SQL parameter limit", async () => {
		const repo = env.ACCOUNT_REPO.getByName("did:plc:largewrites");
		await repo.initialize("did:plc:largewrites");
		await repo.applyWrites(Array.from({ length: 40 }, (_, index) => ({
			action: "create" as const,
			path: `app.bsky.feed.post/${index}`,
			record: { $type: "app.bsky.feed.post", text: String(index), createdAt: "2026-08-20T00:00:00.000Z" },
		})));
		expect(await repo.listRecords("app.bsky.feed.post")).toHaveLength(40);
	});

	it("cleans only orphaned blob uploads", async () => {
		const did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
		const repo = env.ACCOUNT_REPO.getByName(did);
		await repo.initialize(did);
		const referencedBytes = new TextEncoder().encode("referenced");
		const referenced = await cidForBytes(referencedBytes, 0x55);
		await env.BLOBS.put(`blobs/${did}/${referenced}`, referencedBytes);
		await repo.applyWrites([{ action: "create", path: "example.test.record/blob", record: { $type: "example.test.record", blob: { $type: "blob", ref: { $link: referenced.toString() }, mimeType: "application/octet-stream", size: referencedBytes.length } } }]);
		await cleanupBlob(env, { did, cid: referenced.toString() });
		expect(await env.BLOBS.head(`blobs/${did}/${referenced}`)).not.toBeNull();

		const orphanBytes = new TextEncoder().encode("orphan");
		const orphan = await cidForBytes(orphanBytes, 0x55);
		await env.BLOBS.put(`blobs/${did}/${orphan}`, orphanBytes);
		await cleanupBlob(env, { did, cid: orphan.toString() });
		expect(await env.BLOBS.head(`blobs/${did}/${orphan}`)).toBeNull();
	});

	it("imports signed full and differential CARs with the official verifier", async () => {
		const did = "did:plc:importrepo";
		const sourceKey = new Uint8Array(32).fill(11);
		const targetKey = new Uint8Array(32).fill(12);
		const didKey = formatDidKey("ES256K", secp256k1.getPublicKey(sourceKey));
		const target = env.ACCOUNT_REPO.getByName(did);
		await target.initialize(did, targetKey);

		const first = await encodeBlock({ $type: "app.bsky.feed.post", text: "imported", createdAt: "2026-08-16T00:00:00.000Z" });
		const initial = await buildRepoCommit({ did, privateKey: sourceKey, rev: formatTid(10n), entries: [["app.bsky.feed.post/one", first]] });
		await target.importRepo(initial.diff, didKey);
		expect(await target.getRecord("app.bsky.feed.post/one")).toMatchObject({ value: { text: "imported" } });

		const second = await encodeBlock({ $type: "app.bsky.feed.post", text: "diff", createdAt: "2026-08-16T00:00:00.000Z" });
		const update = await buildRepoCommit({
			did, privateKey: sourceKey, rev: formatTid(20n), entries: [["app.bsky.feed.post/one", first], ["app.bsky.feed.post/two", second]],
			previousEntries: [["app.bsky.feed.post/one", first]], operations: [{ action: "create", path: "app.bsky.feed.post/two", cid: second.cid.toString() }],
		});
		await target.importRepo(update.diff, didKey);
		expect(await target.listRecords()).toHaveLength(2);
		const verified = await verifyRepoCar(await target.exportRepo(), did, formatDidKey("ES256K", secp256k1.getPublicKey(targetKey)));
		expect(verified.creates).toHaveLength(2);
	});
});

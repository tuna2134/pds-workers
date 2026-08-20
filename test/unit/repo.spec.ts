import * as dagCbor from "@ipld/dag-cbor";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { MemoryBlockstore, Repo, readCarWithRoot, verifyDiffCar, verifyRepoCar } from "@atproto/repo";
import { describe, expect, it } from "vitest";
import { decodeCar, encodeCar } from "../../src/repo/car";
import { encodeBlock } from "../../src/repo/cid";
import { createCommit, verifyCommit } from "../../src/repo/commit";
import { buildMst, deserializeMst, keyDepth, MstMap } from "../../src/repo/mst";
import { CID } from "multiformats/cid";
import { formatTid, parseTid, TidClock } from "../../src/repo/tid";
import { buildRepoCommit } from "../../src/repo/update";
import { formatDidKey } from "@atproto/crypto";

describe("repository core", () => {
	it("uses the specified MST depth function", async () => {
		expect(await keyDepth("2653ae71")).toBe(0);
		expect(await keyDepth("blue")).toBe(1);
		expect(await keyDepth("app.bsky.feed.post/454397e440ec")).toBe(4);
		expect(await keyDepth("app.bsky.feed.post/9adeb165882c")).toBe(8);
	});

	it("builds the same MST regardless of insertion order", async () => {
		const a = await encodeBlock({ text: "a" });
		const b = await encodeBlock({ text: "b" });
		const entries = [{ key: "app.bsky.feed.post/a", value: a.cid }, { key: "app.bsky.feed.post/b", value: b.cid }];
		expect((await buildMst(entries)).root.equals((await buildMst(entries.toReversed())).root)).toBe(true);
		await expect(buildMst([...entries, entries[0]])).rejects.toThrow("unique");
	});

	it("matches the official MST root fixtures", async () => {
		const value = CID.parse("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
		expect((await buildMst([])).root.toString()).toBe("bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm");
		expect((await buildMst([{ key: "com.example.record/3jqfcqzm3fo2j", value }])).root.toString()).toBe("bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu");
		const keys = ["3jqfcqzm3fp2j", "3jqfcqzm3fr2j", "3jqfcqzm3fs2j", "3jqfcqzm3ft2j", "3jqfcqzm4fc2j"];
		expect((await buildMst(keys.map((key) => ({ key: `com.example.record/${key}`, value })))).root.toString()).toBe("bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m");
	});

	it("supports lookup, replacement, deletion, iteration, and serialization round trips", async () => {
		const values = await Promise.all(["a", "b", "c"].map((text) => encodeBlock({ text })));
		let map = new MstMap();
		map = map.insert("app.example.record/a", values[0].cid).insert("app.example.record/b", values[1].cid);
		expect(map.lookup("app.example.record/a")?.equals(values[0].cid)).toBe(true);
		map = map.update("app.example.record/a", values[2].cid).delete("app.example.record/b");
		expect([...map].map(({ key }) => key)).toEqual(["app.example.record/a"]);
		expect(map.lookup("app.example.record/a")?.equals(values[2].cid)).toBe(true);
		const serialized = await map.serialize();
		const loaded = await MstMap.deserialize(serialized.root, serialized.blocks);
		expect((await loaded.serialize()).root.equals(serialized.root)).toBe(true);
		await expect(deserializeMst(serialized.root, [])).rejects.toThrow("Missing MST block");
		const malformed = await encodeBlock({ l: null, e: [{ p: 1, k: new TextEncoder().encode("app.example.record/a"), v: values[0].cid, t: null }] });
		await expect(deserializeMst(malformed.cid, [malformed])).rejects.toThrow("Malformed MST entry");
		const oversized = await encodeBlock({ l: null, e: Array.from({ length: 10_001 }, () => ({ p: 0, k: new Uint8Array([97]), v: values[0].cid, t: null })) });
		await expect(deserializeMst(oversized.cid, [oversized])).rejects.toThrow("Malformed MST node");
	});

	it("handles a deterministic 1000-record repository", async () => {
		const value = CID.parse("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
		const entries = Array.from({ length: 1000 }, (_, index) => ({ key: `app.example.record/${index.toString().padStart(4, "0")}`, value }));
		const tree = await buildMst(entries);
		expect(await deserializeMst(tree.root, tree.blocks)).toHaveLength(1000);
		expect((await buildMst(entries.toReversed())).root.equals(tree.root)).toBe(true);
	});

	it("encodes sortable, monotonic TIDs", () => {
		expect(formatTid(0n)).toBe("2222222222222");
		expect(parseTid("3jzfcijpj2z2a")).toBeGreaterThan(0n);
		const clock = new TidClock(1);
		const first = clock.next(1000);
		const second = clock.next(999);
		expect(second > first).toBe(true);
		expect(new TidClock(2).next(1, second) > second).toBe(true);
	});

	it("signs commits and creates CARv1 output", async () => {
		const record = await encodeBlock({ $type: "app.bsky.feed.post", text: "independently decoded" });
		const tree = await buildMst([{ key: "app.bsky.feed.post/interop", value: record.cid }]);
		const secretKey = new Uint8Array(32).fill(7);
		const did = "did:plc:example";
		const commit = await createCommit({ did, version: 3, data: tree.root, rev: formatTid(1n), prev: null }, secretKey);
		expect(await verifyCommit(commit.bytes, secp256k1.getPublicKey(secretKey))).toBe(true);
		const car = encodeCar(commit.cid, [commit, ...tree.blocks, record]);
		const headerLength = car[0];
		expect(dagCbor.decode<{ version: number }>(car.slice(1, 1 + headerLength)).version).toBe(1);
		const independentlyVerified = await verifyRepoCar(car, did, formatDidKey("ES256K", secp256k1.getPublicKey(secretKey)));
		expect(independentlyVerified.commit.cid.toString()).toBe(commit.cid.toString());
		expect(independentlyVerified.creates).toHaveLength(1);
		const decoded = await decodeCar(car);
		expect(decoded.roots[0].equals(commit.cid)).toBe(true);
		expect(decoded.blocks).toHaveLength(tree.blocks.length + 2);
		const corrupted = car.slice(); corrupted[corrupted.length - 1] ^= 1;
		await expect(decodeCar(corrupted)).rejects.toThrow("CID mismatch");
	});

	it("produces a diff accepted by the independent atproto verifier", async () => {
		const did = "did:plc:diffexample";
		const privateKey = new Uint8Array(32).fill(9);
		const initial = await buildRepoCommit({ did, privateKey, rev: formatTid(1n), entries: [] });
		const initialCar = encodeCar(initial.commit.cid, [initial.commit, ...initial.tree.blocks]);
		const parsed = await readCarWithRoot(initialCar);
		const previous = await Repo.load(new MemoryBlockstore(parsed.blocks), parsed.root);
		const record = await encodeBlock({ $type: "app.bsky.feed.post", text: "diff" });
		const update = await buildRepoCommit({
			did, privateKey, rev: formatTid(2n), entries: [["app.bsky.feed.post/diff", record]], previousEntries: [],
			operations: [{ action: "create", path: "app.bsky.feed.post/diff", cid: record.cid.toString() }],
		});
		expect(dagCbor.decode<{ prev: CID | null }>(update.commit.bytes).prev).toBeNull();
		const verified = await verifyDiffCar(previous, update.diff, did);
		expect(verified.writes).toHaveLength(1);
	});
});

import * as dagCbor from "@ipld/dag-cbor";
import * as lexCbor from "@atproto/lex-cbor";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { MemoryBlockstore, MST as OfficialMst, Repo, readCarWithRoot, verifyDiffCar, verifyRepoCar } from "@atproto/repo";
import { describe, expect, it } from "vitest";
import { decodeCar, encodeCar } from "../../src/repo/car";
import { encodeBlock } from "../../src/repo/cid";
import { createCommit, verifyCommit } from "../../src/repo/commit";
import { decodeDagCbor, encodeDagCbor, ipldToJson, jsonToIpld } from "../../src/repo/dag-cbor";
import { buildMst, deserializeMst, keyDepth, MstMap } from "../../src/repo/mst";
import { CID } from "multiformats/cid";
import { formatTid, parseTid, TidClock } from "../../src/repo/tid";
import { buildRepoCommit } from "../../src/repo/update";
import { formatDidKey } from "@atproto/crypto";

describe("repository core", () => {
	it("uses the official DRISL codec and rejects non-data-model CBOR", async () => {
		const link = CID.parse("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
		const value = { $type: "app.example.record", count: 42, bytes: new Uint8Array([0, 1, 255]), link };
		const block = await encodeBlock(value);
		expect(block.bytes).toEqual(lexCbor.encode(value));
		expect(block.cid.toString()).toBe((await lexCbor.cidForLex(value)).toString());
		expect(dagCbor.decode(block.bytes)).toEqual(value);
		expect(ipldToJson(jsonToIpld({ link: { $link: link.toString() }, bytes: { $bytes: "AAH/" } }))).toEqual({ link: { $link: link.toString() }, bytes: { $bytes: "AAH/" } });
		expect(() => encodeDagCbor({ value: 1.5 })).toThrow("Non-integer");
		expect(() => encodeDagCbor({ value: Number.MAX_SAFE_INTEGER + 1 })).toThrow("Non-integer");
		expect(() => decodeDagCbor(Uint8Array.of(0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02))).toThrow();
		expect(() => decodeDagCbor(Uint8Array.of(0x9f, 0x01, 0xff))).toThrow();
		expect(() => decodeDagCbor(Uint8Array.of(0xd8, 0x2a, 0x41, 0x01))).toThrow("leading 0x00");
	});

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

	it("matches the official implementation across deterministic insertion orders", async () => {
		const values = await Promise.all(Array.from({ length: 128 }, (_, index) => encodeBlock({ index })));
		const entries = values.map(({ cid }, index) => ({ key: `app.example.record/${(index * 73 % 128).toString().padStart(3, "0")}`, value: cid }));
		for (const ordered of [entries, entries.toReversed()]) {
			let official = await OfficialMst.create(new MemoryBlockstore());
			for (const { key, value } of ordered) official = await official.add(key, value);
			expect((await buildMst(ordered)).root.toString()).toBe((await official.getPointer()).toString());
		}
	});

	it("matches the official MST through deterministic mixed mutations", async () => {
		const values = await Promise.all(Array.from({ length: 64 }, (_, index) => encodeBlock({ index })));
		let state = 0x5eed1234;
		const random = () => state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
		let map = new MstMap();
		let official = await OfficialMst.create(new MemoryBlockstore());
		const active: string[] = [];
		let nextKey = 0;
		for (let operation = 0; operation < 256; operation++) {
			const choice = random() % 100;
			if (!active.length || choice < 45) {
				const key = `app.example.record/${(nextKey++).toString().padStart(4, "0")}`;
				const value = values[random() % values.length].cid;
				map = map.insert(key, value); official = await official.add(key, value); active.push(key);
			} else {
				const index = random() % active.length;
				const key = active[index];
				if (choice < 75) {
					const value = values[random() % values.length].cid;
					map = map.update(key, value); official = await official.update(key, value);
				} else {
					map = map.delete(key); official = await official.delete(key); active.splice(index, 1);
				}
			}
			if (operation % 16 === 15) {
				const serialized = await map.serialize();
				expect(serialized.root.toString()).toBe((await official.getPointer()).toString());
				expect([...map].map(({ key }) => key)).toEqual((await official.leaves()).map(({ key }) => key));
			}
		}
		const serialized = await map.serialize();
		expect([...(await MstMap.deserialize(serialized.root, serialized.blocks))]).toEqual([...map]);
	});

	it("rejects duplicate, missing, and boundary-invalid keys", async () => {
		const value = (await encodeBlock({ value: true })).cid;
		const longest = `a/${"b".repeat(1022)}`;
		expect((await buildMst([{ key: longest, value }])).root).toBeDefined();
		for (const key of ["a", "a/", "/b", `a/${"b".repeat(1023)}`, "a/💙"])
			await expect(buildMst([{ key, value }])).rejects.toThrow("valid and unique");
		const map = new MstMap([{ key: "a/b", value }]);
		expect(() => map.insert("a/b", value)).toThrow("already exists");
		expect(() => map.update("a/c", value)).toThrow("does not exist");
		expect(() => map.delete("a/c")).toThrow("does not exist");
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
		const duplicated = encodeCar(commit.cid, [record, commit, record, ...tree.blocks]);
		expect((await decodeCar(duplicated)).blocks.filter(({ cid }) => cid.equals(record.cid))).toHaveLength(2);
		expect((await readCarWithRoot(duplicated)).root.toString()).toBe(commit.cid.toString());
		const overlongHeaderLength = Uint8Array.from([car[0] | 0x80, 0, ...car.slice(1)]);
		await expect(decodeCar(overlongHeaderLength)).rejects.toThrow("Non-canonical CAR varint");
		await expect(decodeCar(car.slice(0, -1))).rejects.toThrow("Malformed CAR block length");
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

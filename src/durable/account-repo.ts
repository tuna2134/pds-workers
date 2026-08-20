import { DurableObject } from "cloudflare:workers";
import { count, countDistinct, eq, inArray } from "drizzle-orm";
import { drizzle, type DrizzleSqliteDODatabase } from "drizzle-orm/durable-sqlite";
import { migrate } from "drizzle-orm/durable-sqlite/migrator";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { CID } from "multiformats/cid";
import { unwrapKey, wrapKey } from "../crypto/key-wrap";
import migrations from "../db/repo-migrations";
import * as schema from "../db/schema/repo";
import { encodeBlock } from "../repo/cid";
import { buildMst, deserializeMst } from "../repo/mst";
import { encodeCar } from "../repo/car";
import { decodeDagCbor, ipldToJson, jsonToIpld } from "../repo/dag-cbor";
import { encodeDagCbor } from "../repo/dag-cbor";
import type { CommitEventInput } from "./firehose";
import { buildRepoCommit, buildRepoDiff, type RepoEntry, type RepoOperation } from "../repo/update";
import { TidClock } from "../repo/tid";
import { isValidNsid, isValidRecordKey } from "@atproto/syntax";
import { jsonToLex } from "@atproto/lex";
import { BlockMap, MemoryBlockstore, Repo, readCarWithRoot, verifyDiff } from "@atproto/repo";
import { formatDidKey } from "@atproto/crypto";
import { notifyCrawlers } from "../sync/crawler";

export type RepoWrite =
	| { action: "create" | "update"; path: string; record: Record<string, unknown>; swapRecord?: string }
	| { action: "delete"; path: string; swapRecord?: string };

function validPath(path: string) {
	const [collection, rkey, extra] = path.split("/");
	return !extra && isValidNsid(collection) && isValidRecordKey(rkey);
}

function base64url(value: Uint8Array) {
	let binary = "";
	for (const byte of value) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}

function chunks<T>(values: T[], size: number): T[][] {
	return Array.from({ length: Math.ceil(values.length / size) }, (_, index) => values.slice(index * size, (index + 1) * size));
}

export class AccountRepo extends DurableObject<Env> {
	readonly #db: DrizzleSqliteDODatabase<typeof schema>;
	readonly #clock = new TidClock();
	#writeTail: Promise<void> = Promise.resolve();

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.#db = drizzle(ctx.storage, { schema });
		ctx.blockConcurrencyWhile(() => migrate(this.#db, migrations));
	}

	async initialize(did: string, suppliedPrivateKey?: Uint8Array) {
		return this.#serialize(async () => {
			const existing = await this.#db.select().from(schema.repoState).get();
			if (existing) {
				if (existing.did !== did) throw new Error("Durable Object DID mismatch");
				return { did, rev: existing.rev, commit: existing.commitCid };
			}
			const reserved = await this.ctx.storage.get<string>("reservedSigningKey");
			const privateKey = reserved ? await unwrapKey(reserved, this.env.SIGNING_KEY_WRAPPING_SECRET) : suppliedPrivateKey ?? secp256k1.utils.randomSecretKey();
			const wrappedSigningKey = await wrapKey(privateKey, this.env.SIGNING_KEY_WRAPPING_SECRET);
			const result = await this.#commit(did, wrappedSigningKey, privateKey, []);
			if (reserved) await this.ctx.storage.delete("reservedSigningKey");
			return { ...result, publicKey: secp256k1.getPublicKey(privateKey) };
		});
	}

	async reserveSigningKey(did: string, suppliedPrivateKey?: Uint8Array) {
		return this.#serialize(async () => {
			const state = await this.#db.select().from(schema.repoState).get();
			if (state) {
				if (state.did !== did) throw new Error("Durable Object DID mismatch");
				return this.signingKeyDid();
			}
			let wrapped = await this.ctx.storage.get<string>("reservedSigningKey");
			if (!wrapped) {
				wrapped = await wrapKey(suppliedPrivateKey ?? secp256k1.utils.randomSecretKey(), this.env.SIGNING_KEY_WRAPPING_SECRET);
				await this.ctx.storage.put("reservedSigningKey", wrapped);
			}
			return formatDidKey("ES256K", secp256k1.getPublicKey(await unwrapKey(wrapped, this.env.SIGNING_KEY_WRAPPING_SECRET)));
		});
	}

	async applyWrites(writes: RepoWrite[], swapCommit?: string) {
		if (!writes.length) throw new TypeError("At least one write is required");
		if (writes.length > 200) throw new RangeError("A commit may contain at most 200 operations");
		return this.#serialize(async () => {
			const state = await this.#db.select().from(schema.repoState).get();
			if (!state) throw new Error("Repository is not initialized");
			if (swapCommit && state.commitCid !== swapCommit) throw new Error("InvalidSwap");
			const current = await this.#db.select().from(schema.records).all();
			const records = new Map<string, { cid: CID; bytes: Uint8Array<ArrayBufferLike> }>(current.map((record) => [record.path, { cid: CID.parse(record.cid), bytes: new Uint8Array(record.bytes) }]));
			const previousEntries = [...records] as [string, { cid: CID; bytes: Uint8Array<ArrayBufferLike> }][];
			const operations: { action: "create" | "update" | "delete"; path: string; cid: string | null; prev?: string }[] = [];
			for (const write of writes) {
				if (!validPath(write.path)) throw new TypeError("Invalid repository path");
				const found = records.get(write.path);
				if (write.swapRecord && found?.cid.toString() !== write.swapRecord) throw new Error("InvalidSwap");
				if (write.action === "create" && found) throw new Error("RecordAlreadyExists");
				if (write.action === "update" && !found) throw new Error("RecordNotFound");
				if (write.action === "delete") {
					if (!found) throw new Error("RecordNotFound");
					records.delete(write.path);
					operations.push({ action: "delete", path: write.path, cid: null, prev: found.cid.toString() });
				} else {
					if (write.record.$type !== write.path.slice(0, write.path.indexOf("/"))) throw new TypeError("record.$type must match collection");
					jsonToLex(write.record as never, { strict: true });
					const encoded = await encodeBlock(jsonToIpld(write.record));
					if (encoded.bytes.length > 1_000_000) throw new RangeError("Record block exceeds 1 MB");
					records.set(write.path, encoded);
					operations.push({ action: write.action, path: write.path, cid: encoded.cid.toString(), ...(found ? { prev: found.cid.toString() } : {}) });
				}
			}
			const privateKey = await unwrapKey(state.wrappedSigningKey, this.env.SIGNING_KEY_WRAPPING_SECRET);
			return this.#commit(state.did, state.wrappedSigningKey, privateKey, records, { operations, previousEntries, since: state.rev, prevData: state.rootCid ?? undefined });
		});
	}

	async importRepo(car: Uint8Array, signingKey: string) {
		return this.#serialize(async () => {
			const state = await this.#db.select().from(schema.repoState).get();
			if (!state?.commitCid || !state.rev) throw new Error("Repository is not initialized");
			const currentRows = await this.#db.select().from(schema.records).all();
			const current = new Map<string, RepoEntry>(currentRows.map((record) => [record.path, { cid: CID.parse(record.cid), bytes: new Uint8Array(record.bytes) }]));
			const stored = new BlockMap((await this.#db.select().from(schema.blocks).all()).map((block) => [CID.parse(block.cid), new Uint8Array(block.bytes)] as const));
			const local = await Repo.load(new MemoryBlockstore(stored), CID.parse(state.commitCid));
			const incoming = await readCarWithRoot(car);
			const verified = await verifyDiff(local, incoming.blocks, incoming.root, state.did, signingKey);
			const operations: RepoOperation[] = [];
			for (const write of verified.writes) {
				const path = `${write.collection}/${write.rkey}`;
				if (!validPath(path)) throw new TypeError("Invalid repository path");
				const previous = current.get(path);
				if (write.action === "delete") {
					current.delete(path);
					operations.push({ action: "delete", path, cid: null, ...(previous ? { prev: previous.cid.toString() } : {}) });
					continue;
				}
				const bytes = incoming.blocks.get(write.cid);
				if (!bytes) throw new TypeError(`Missing record block: ${write.cid}`);
				if (bytes.length > 1_000_000) throw new RangeError("Record block exceeds 1 MB");
				const record = ipldToJson(decodeDagCbor(bytes)) as Record<string, unknown>;
				if (record.$type !== write.collection) throw new TypeError("record.$type must match collection");
				jsonToLex(record as never, { strict: true });
				current.set(path, { cid: CID.parse(write.cid.toString()), bytes });
				operations.push({ action: previous ? "update" : "create", path, cid: write.cid.toString(), ...(previous ? { prev: previous.cid.toString() } : {}) });
			}
			if (!operations.length) return this.describe();
			const privateKey = await unwrapKey(state.wrappedSigningKey, this.env.SIGNING_KEY_WRAPPING_SECRET);
			return this.#commit(state.did, state.wrappedSigningKey, privateKey, current, {
				operations, previousEntries: [...new Map(currentRows.map((record) => [record.path, { cid: CID.parse(record.cid), bytes: new Uint8Array(record.bytes) }]))],
				since: state.rev, prevData: state.rootCid ?? undefined, revisionFloor: verified.commit.rev, allowMissingBlobs: true,
			});
		});
	}

	async getRecord(path: string) {
		const record = await this.#db.select().from(schema.records).where(eq(schema.records.path, path)).get();
		return record ? { uri: `at://${(await this.describe()).did}/${path}`, cid: record.cid, value: ipldToJson(decodeDagCbor(record.bytes)) } : null;
	}

	async listRecords(collection?: string) {
		const state = await this.describe();
		const rows = (await this.#db.select().from(schema.records).all()).filter((record) => !collection || record.path.startsWith(`${collection}/`)).sort((a, b) => a.path.localeCompare(b.path));
		return rows.map((record) => ({ uri: `at://${state.did}/${record.path}`, cid: record.cid, value: ipldToJson(decodeDagCbor(record.bytes)) }));
	}

	async listCollections() {
		return [...new Set((await this.#db.select({ path: schema.records.path }).from(schema.records).all()).map(({ path }) => path.slice(0, path.indexOf("/"))))].sort();
	}

	async describe() {
		const state = await this.#db.select().from(schema.repoState).get();
		if (!state?.rev || !state.commitCid || !state.rootCid) throw new Error("Repository is not initialized");
		return { did: state.did, rev: state.rev, commit: state.commitCid, root: state.rootCid };
	}

	pitrBookmark(at?: number) {
		return at === undefined ? this.ctx.storage.getCurrentBookmark() : this.ctx.storage.getBookmarkForTime(at);
	}

	schedulePitrRestore(bookmark: string) {
		return this.ctx.storage.onNextSessionRestoreBookmark(bookmark);
	}

	async signServiceAuth(aud: string, lxm?: string, expiresAt = Math.floor(Date.now() / 1000) + 60) {
		const state = await this.#db.select().from(schema.repoState).get();
		if (!state) throw new Error("Repository is not initialized");
		const now = Math.floor(Date.now() / 1000);
		if (!Number.isInteger(expiresAt) || expiresAt <= now || expiresAt > now + 300) throw new RangeError("BadExpiration");
		const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256K", typ: "JWT", kid: "#atproto" })));
		const payload = base64url(new TextEncoder().encode(JSON.stringify({ iss: state.did, aud, exp: expiresAt, iat: now, jti: crypto.randomUUID(), ...(lxm ? { lxm } : {}) })));
		const message = new TextEncoder().encode(`${header}.${payload}`);
		const privateKey = await unwrapKey(state.wrappedSigningKey, this.env.SIGNING_KEY_WRAPPING_SECRET);
		const signature = secp256k1.sign(message, privateKey, { prehash: true, format: "compact", lowS: true });
		return `${header}.${payload}.${base64url(signature)}`;
	}

	async signingKeyDid() {
		const state = await this.#db.select().from(schema.repoState).get();
		if (!state) throw new Error("Repository is not initialized");
		const privateKey = await unwrapKey(state.wrappedSigningKey, this.env.SIGNING_KEY_WRAPPING_SECRET);
		return formatDidKey("ES256K", secp256k1.getPublicKey(privateKey));
	}

	async resign() {
		return this.#serialize(async () => {
			const state = await this.#db.select().from(schema.repoState).get();
			if (!state?.rev) throw new Error("Repository is not initialized");
			const rows = await this.#db.select().from(schema.records).all();
			const entries = rows.map((record) => [record.path, { cid: CID.parse(record.cid), bytes: new Uint8Array(record.bytes) }] as [string, RepoEntry]);
			const privateKey = await unwrapKey(state.wrappedSigningKey, this.env.SIGNING_KEY_WRAPPING_SECRET);
			return this.#commit(state.did, state.wrappedSigningKey, privateKey, entries, { operations: [], previousEntries: entries, since: state.rev, prevData: state.rootCid ?? undefined, allowMissingBlobs: true });
		});
	}

	async status() {
		const state = await this.describe();
		const [repoBlocks, indexedRecords, expectedBlobs] = await Promise.all([
			this.#db.select({ value: count() }).from(schema.blocks).get(),
			this.#db.select({ value: count() }).from(schema.records).get(),
			this.#db.select({ value: countDistinct(schema.blobRefs.cid) }).from(schema.blobRefs).get(),
		]);
		return { ...state, repoBlocks: repoBlocks!.value, indexedRecords: indexedRecords!.value, expectedBlobs: expectedBlobs!.value };
	}

	async exportRepo(since?: string): Promise<Uint8Array> {
		const state = await this.describe();
		const rows = await this.#db.select().from(schema.records).all();
		const recordBlocks = rows.map((record) => ({ cid: CID.parse(record.cid), bytes: new Uint8Array(record.bytes) }));
		const tree = await buildMst(rows.map((record) => ({ key: record.path, value: CID.parse(record.cid) })));
		if (tree.root.toString() !== state.root) throw new Error("Repository root does not match record index");
		const commit = await this.#db.select().from(schema.commits).where(eq(schema.commits.cid, state.commit)).get();
		if (!commit) throw new Error("Commit block is missing");
		if (since) {
			const previousCommit = await this.#db.select().from(schema.commits).where(eq(schema.commits.rev, since)).get();
			if (previousCommit) {
				const storedBlocks = (await this.#db.select().from(schema.blocks).all()).map((block) => ({ cid: CID.parse(block.cid), bytes: new Uint8Array(block.bytes) }));
				const previous = await deserializeMst(CID.parse(previousCommit.rootCid), storedBlocks);
				const old = new Map(previous.map((entry) => [entry.key, entry.value.toString()]));
				const current = new Map(rows.map((record) => [record.path, record.cid]));
				const operations = [
					...rows.filter((record) => old.get(record.path) !== record.cid).map((record) => ({ action: old.has(record.path) ? "update" as const : "create" as const, path: record.path, cid: record.cid })),
					...previous.filter((entry) => !current.has(entry.key)).map((entry) => ({ action: "delete" as const, path: entry.key, cid: null, prev: entry.value.toString() })),
				];
				return (await buildRepoDiff({ commit: { cid: CID.parse(commit.cid), bytes: new Uint8Array(commit.bytes) }, entries: rows.map((record) => [record.path, { cid: CID.parse(record.cid), bytes: new Uint8Array(record.bytes) }]), previousEntries: previous.map((entry) => [entry.key, { cid: entry.value, bytes: new Uint8Array() }]), operations })).diff;
			}
		}
		return encodeCar(CID.parse(state.commit), [{ cid: CID.parse(state.commit), bytes: new Uint8Array(commit.bytes) }, ...tree.blocks.toReversed(), ...recordBlocks]);
	}

	async getBlocks(cids: string[]): Promise<Uint8Array> {
		if (!cids.length || cids.length > 1000) throw new TypeError("Between 1 and 1000 CIDs are required");
		const requested = cids.map((cid) => {
			try { return CID.parse(cid); }
			catch { throw new TypeError("Invalid CID"); }
		});
		const rows = (await Promise.all(chunks(cids, 100).map((batch) => this.#db.select().from(schema.blocks).where(inArray(schema.blocks.cid, batch)).all()))).flat();
		if (rows.length !== new Set(cids).size) throw new Error("BlockNotFound");
		const byCid = new Map(rows.map((row) => [row.cid, row]));
		return encodeCar(requested, requested.map((cid) => ({ cid, bytes: new Uint8Array(byCid.get(cid.toString())!.bytes) })));
	}

	async getRecordProof(path: string): Promise<Uint8Array> {
		const state = await this.describe();
		const rows = await this.#db.select().from(schema.records).all();
		const record = rows.find((row) => row.path === path);
		if (!record) throw new Error("RecordNotFound");
		const tree = await buildMst(rows.map((row) => ({ key: row.path, value: CID.parse(row.cid) })));
		if (tree.root.toString() !== state.root) throw new Error("Repository root does not match record index");
		const commit = await this.#db.select().from(schema.commits).where(eq(schema.commits.cid, state.commit)).get();
		if (!commit) throw new Error("Commit block is missing");
		return encodeCar(CID.parse(state.commit), [
			{ cid: CID.parse(state.commit), bytes: new Uint8Array(commit.bytes) },
			...tree.blocks,
			{ cid: CID.parse(record.cid), bytes: new Uint8Array(record.bytes) },
		]);
	}

	async alarm() { await this.#serialize(() => this.#flushOutbox()); }

	async deleteAccount() { await this.ctx.storage.deleteAll(); }

	async listBlobs(since?: string): Promise<string[]> {
		return (await this.#db.select({ cid: schema.blobRefs.cid, addedRev: schema.blobRefs.addedRev }).from(schema.blobRefs).all()).filter((reference) => !since || reference.addedRev > since).map(({ cid }) => cid).filter((cid, index, all) => all.indexOf(cid) === index).sort();
	}

	async isBlobReferenced(cid: string): Promise<boolean> {
		return Boolean(await this.#db.select().from(schema.blobRefs).where(eq(schema.blobRefs.cid, cid)).get());
	}

	async listMissingBlobs(cursor?: string, limit = 500) {
		const did = (await this.describe()).did;
		const references = (await this.#db.select().from(schema.blobRefs).all())
			.map((reference) => ({ ...reference, key: `${reference.recordPath}\0${reference.cid}` }))
			.filter((reference) => !cursor || reference.key > cursor)
			.sort((a, b) => a.key.localeCompare(b.key));
		const scanned = references.slice(0, limit);
		const blobs = (await Promise.all(scanned.map(async (reference) => await this.env.BLOBS.head(`blobs/${did}/${reference.cid}`) ? null : { cid: reference.cid, recordUri: `at://${did}/${reference.recordPath}` }))).filter((value) => value !== null);
		return { blobs, ...(references.length > scanned.length && scanned.length ? { cursor: scanned.at(-1)!.key } : {}) };
	}

	#serialize<T>(operation: () => Promise<T>): Promise<T> {
		const result = this.#writeTail.then(operation);
		this.#writeTail = result.then(() => undefined, () => undefined);
		return result;
	}

	async #commit(did: string, wrappedSigningKey: string, privateKey: Uint8Array, source: Iterable<[string, { cid: CID; bytes: Uint8Array<ArrayBufferLike> }]>, previous?: {
		operations: RepoOperation[];
		previousEntries: [string, RepoEntry][];
		since: string | null;
		prevData?: string;
		revisionFloor?: string;
		allowMissingBlobs?: boolean;
	}) {
		const entries = [...source];
		const rawReferences = entries.flatMap(([path, record]) => this.#blobReferences(path, decodeDagCbor(record.bytes)));
		const previousRows = await this.#db.select().from(schema.blobRefs).all();
		const rev = this.#clock.next(Date.now(), [previous?.since, previous?.revisionFloor].filter((value): value is string => Boolean(value)).sort().at(-1));
		const references = rawReferences.map(({ recordPath, cid }) => ({ recordPath, cid, addedRev: previousRows.find((old) => old.cid === cid)?.addedRev ?? rev }));
		if (!previous?.allowMissingBlobs) {
			const blobs = new Map<string, R2Object | null>();
			for (const { cid, size } of rawReferences) {
				if (!blobs.has(cid)) blobs.set(cid, await this.env.BLOBS.head(`blobs/${did}/${cid}`));
				const blob = blobs.get(cid);
				if (!blob) throw new Error(`BlobNotFound:${cid}`);
				if (blob.size !== size) throw new TypeError(`Blob size does not match uploaded bytes: ${cid}`);
			}
		}
		const previousReferences = previousRows.map(({ cid }) => cid);
		const { tree, commit, diff } = await buildRepoCommit({ did, rev, privateKey, entries, previousEntries: previous?.previousEntries, operations: previous?.operations });
		const now = new Date();
		const event: CommitEventInput = {
			id: commit.cid.toString(), repo: did, rev, since: previous?.since ?? null, commit: commit.cid.toString(), blocks: diff,
			...(previous?.prevData ? { prevData: previous.prevData } : {}), ops: previous?.operations ?? [], time: now.toISOString(),
		};
		await this.#db.transaction(async (tx) => {
			await tx.delete(schema.records);
			await tx.delete(schema.blobRefs);
			for (const batch of chunks(entries.map(([path, record]) => ({ path, cid: record.cid.toString(), bytes: Buffer.from(record.bytes) })), 25)) await tx.insert(schema.records).values(batch);
			for (const batch of chunks(references, 25)) await tx.insert(schema.blobRefs).values(batch);
			for (const batch of chunks([commit, ...tree.blocks, ...entries.map(([, record]) => record)].map((block) => ({ cid: block.cid.toString(), bytes: Buffer.from(block.bytes), createdAt: now })), 25)) await tx.insert(schema.blocks).values(batch).onConflictDoNothing();
			await tx.insert(schema.commits).values({ rev, cid: commit.cid.toString(), rootCid: tree.root.toString(), bytes: Buffer.from(commit.bytes), createdAt: now });
			await tx.insert(schema.repoState).values({ id: 1, did, rev, rootCid: tree.root.toString(), commitCid: commit.cid.toString(), wrappedSigningKey }).onConflictDoUpdate({ target: schema.repoState.id, set: { rev, rootCid: tree.root.toString(), commitCid: commit.cid.toString() } });
			await tx.insert(schema.firehoseOutbox).values({ id: event.id, payload: Buffer.from(encodeDagCbor(event)), createdAt: now });
		});
		await Promise.all(previousReferences.filter((cid) => !references.some((reference) => reference.cid === cid)).map((cid) => this.env.BLOBS.delete(`blobs/${did}/${cid}`)));
		const seq = await this.#flushOutbox(event.id);
		this.ctx.waitUntil(notifyCrawlers(this.env.CRAWLERS, this.env.PDS_URL).catch((error) => console.error(JSON.stringify({ did, commit: commit.cid.toString(), error: error instanceof Error ? error.message : "Crawler notification failed" }))));
		return { did, rev, commit: commit.cid.toString(), root: tree.root.toString(), seq };
	}

	async #flushOutbox(wantedId?: string): Promise<number | null> {
		let wantedSeq: number | null = null;
		for (const pending of await this.#db.select().from(schema.firehoseOutbox).all()) {
			try {
				const seq = await this.env.FIREHOSE.getByName("global").publishCommit(decodeDagCbor<CommitEventInput>(pending.payload));
				await this.#db.delete(schema.firehoseOutbox).where(eq(schema.firehoseOutbox.id, pending.id));
				if (pending.id === wantedId) wantedSeq = seq;
			} catch {
				await this.ctx.storage.setAlarm(Date.now() + 5_000);
				break;
			}
		}
		return wantedSeq;
	}

	#blobReferences(recordPath: string, value: unknown): { recordPath: string; cid: string; size: number }[] {
		const found = new Map<string, number>();
		const visit = (child: unknown) => {
			if (!child || typeof child !== "object") return;
			if (Array.isArray(child)) { child.forEach(visit); return; }
			const object = child as Record<string, unknown>;
			if (object.$type === "blob") {
				const cid = CID.asCID(object.ref);
				if (!cid || cid.version !== 1 || cid.code !== 0x55 || cid.multihash.code !== 0x12 || cid.multihash.digest.length !== 32) throw new TypeError("Invalid blob CID");
				if (!Number.isSafeInteger(object.size) || Number(object.size) < 0) throw new TypeError("Invalid blob size");
				const key = cid.toString();
				if (found.has(key) && found.get(key) !== object.size) throw new TypeError("Conflicting blob sizes");
				found.set(key, Number(object.size));
			}
			Object.values(object).forEach(visit);
		};
		visit(value);
		return [...found].map(([cid, size]) => ({ recordPath, cid, size }));
	}
}

import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import { encodeBlock } from "../cid";
import * as dagCbor from "@ipld/dag-cbor";

export interface MstEntry { key: string; value: CID }
export interface Block { cid: CID; bytes: Uint8Array }
export interface Mst { root: CID; blocks: Block[] }

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export function validMstKey(key: string): boolean {
	return encoder.encode(key).length <= 1024 && /^[A-Za-z0-9._~:-]+\/[A-Za-z0-9._~:-]+$/.test(key);
}

export async function keyDepth(key: string): Promise<number> {
	const digest = (await sha256.digest(encoder.encode(key))).digest;
	let zeros = 0;
	for (const byte of digest) {
		if (byte === 0) { zeros += 8; continue; }
		zeros += Math.clz32(byte) - 24;
		break;
	}
	return Math.floor(zeros / 2);
}

export async function buildMst(input: Iterable<MstEntry>): Promise<Mst> {
	const sorted = [...input].sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
	for (let i = 0; i < sorted.length; i++) {
		if (!validMstKey(sorted[i].key) || (i && sorted[i - 1].key === sorted[i].key)) throw new TypeError("MST keys must be valid and unique");
	}
	const entries = await Promise.all(sorted.map(async (entry) => ({ ...entry, depth: await keyDepth(entry.key), bytes: encoder.encode(entry.key) })));
	const blocks: Block[] = [];

	async function node(items: typeof entries, layer: number): Promise<CID> {
		const pivots = items.filter((item) => item.depth === layer);
		let offset = 0;
		const groups = pivots.map((pivot) => {
			const index = items.indexOf(pivot);
			const group = items.slice(offset, index);
			offset = index + 1;
			return group;
		});
		groups.push(items.slice(offset));
		const children = layer > 0 ? await Promise.all(groups.map((group) => group.length ? node(group, layer - 1) : null)) : groups.map(() => null);
		let previous: Uint8Array<ArrayBufferLike> = new Uint8Array();
		const encodedEntries = pivots.map((entry, index) => {
			let prefix = 0;
			while (prefix < previous.length && prefix < entry.bytes.length && previous[prefix] === entry.bytes[prefix]) prefix++;
			const result = { p: prefix, k: entry.bytes.slice(prefix), v: entry.value, t: children[index + 1] };
			previous = entry.bytes;
			return result;
		});
		const block = await encodeBlock({ l: children[0], e: encodedEntries });
		blocks.push(block);
		return block.cid;
	}

	const root = await node(entries, entries.length ? Math.max(...entries.map((entry) => entry.depth)) : 0);
	return { root, blocks };
}

type EncodedEntry = { p: number; k: Uint8Array; v: CID; t: CID | null };
type EncodedNode = { l: CID | null; e: EncodedEntry[] };

function bytesEqual(a: Uint8Array, b: Uint8Array) { return a.length === b.length && a.every((value, index) => value === b[index]); }

export async function deserializeMst(root: CID, source: Iterable<Block>): Promise<MstEntry[]> {
	const blocks = new Map([...source].map((block) => [block.cid.toString(), block]));
	const entries: MstEntry[] = [];
	const visited = new Set<string>();
	let lastKey: string | undefined;

	async function visit(cid: CID): Promise<void> {
		const id = cid.toString();
		if (visited.has(id)) throw new TypeError("MST contains a cycle or shared node");
		visited.add(id);
		const block = blocks.get(id);
		if (!block) throw new TypeError(`Missing MST block: ${id}`);
		let value: unknown;
		try { value = dagCbor.decode(block.bytes); } catch { throw new TypeError("Malformed MST block"); }
		const canonical = await encodeBlock(value);
		if (!canonical.cid.equals(cid) || !bytesEqual(canonical.bytes, block.bytes)) throw new TypeError("Non-canonical or CID-mismatched MST block");
		if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("Malformed MST node");
		const node = value as Partial<EncodedNode> & Record<string, unknown>;
		if (Object.keys(node).sort().join(",") !== "e,l" || !Array.isArray(node.e) || (node.l !== null && !CID.asCID(node.l))) throw new TypeError("Malformed MST node");
		if (node.l) await visit(CID.asCID(node.l)!);
		let previous = new Uint8Array();
		for (const item of node.e) {
			if (!item || typeof item !== "object" || Array.isArray(item)) throw new TypeError("Malformed MST entry");
			const entry = item as Partial<EncodedEntry> & Record<string, unknown>;
			if (Object.keys(entry).sort().join(",") !== "k,p,t,v" || !Number.isInteger(entry.p) || entry.p! < 0 || entry.p! > previous.length || !(entry.k instanceof Uint8Array) || !entry.k.length || !CID.asCID(entry.v) || (entry.t !== null && !CID.asCID(entry.t))) throw new TypeError("Malformed MST entry");
			const keyBytes = new Uint8Array(entry.p! + entry.k.length);
			keyBytes.set(previous.slice(0, entry.p!)); keyBytes.set(entry.k, entry.p!);
			let key: string;
			try { key = decoder.decode(keyBytes); } catch { throw new TypeError("Malformed MST key"); }
			if (!validMstKey(key) || lastKey !== undefined && key <= lastKey) throw new TypeError("MST keys are not strictly ordered");
			entries.push({ key, value: CID.asCID(entry.v)! }); lastKey = key; previous = keyBytes;
			if (entry.t) await visit(CID.asCID(entry.t)!);
		}
	}

	await visit(root);
	if (!(await buildMst(entries)).root.equals(root)) throw new TypeError("MST is not in canonical form");
	return entries;
}

export class MstMap implements Iterable<MstEntry> {
	readonly #entries: Map<string, CID>;
	constructor(entries: Iterable<MstEntry> = []) { this.#entries = new Map([...entries].map(({ key, value }) => [key, value])); }
	lookup(key: string) { return this.#entries.get(key) ?? null; }
	insert(key: string, value: CID) { if (this.#entries.has(key)) throw new TypeError("MST key already exists"); return this.#with(key, value); }
	update(key: string, value: CID) { if (!this.#entries.has(key)) throw new TypeError("MST key does not exist"); return this.#with(key, value); }
	delete(key: string) { if (!this.#entries.has(key)) throw new TypeError("MST key does not exist"); const next = new Map(this.#entries); next.delete(key); return new MstMap([...next].map(([entryKey, value]) => ({ key: entryKey, value }))); }
	serialize() { return buildMst(this); }
	static async deserialize(root: CID, blocks: Iterable<Block>) { return new MstMap(await deserializeMst(root, blocks)); }
	*[Symbol.iterator]() { for (const [key, value] of [...this.#entries].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) yield { key, value }; }
	#with(key: string, value: CID) { if (!validMstKey(key)) throw new TypeError("Invalid MST key"); return new MstMap([...this.#entries, [key, value]].map(([entryKey, entryValue]) => ({ key: entryKey as string, value: entryValue as CID }))); }
}

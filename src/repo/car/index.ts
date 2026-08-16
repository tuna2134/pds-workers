import * as dagCbor from "@ipld/dag-cbor";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";

export interface CarBlock { cid: CID; bytes: Uint8Array }

function varint(value: number): Uint8Array {
	const bytes: number[] = [];
	do { bytes.push((value & 0x7f) | (value > 0x7f ? 0x80 : 0)); value >>>= 7; } while (value);
	return Uint8Array.from(bytes);
}

function concat(parts: Uint8Array[]): Uint8Array {
	const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
	let offset = 0;
	for (const part of parts) { result.set(part, offset); offset += part.length; }
	return result;
}

export function encodeCar(root: CID | CID[], blocks: Iterable<CarBlock>): Uint8Array {
	const header = dagCbor.encode({ roots: Array.isArray(root) ? root : [root], version: 1 });
	const sections = [varint(header.length), header];
	for (const block of blocks) {
		const body = concat([block.cid.bytes, block.bytes]);
		sections.push(varint(body.length), body);
	}
	return concat(sections);
}

function readVarint(source: Uint8Array, offset: number) {
	let value = 0;
	let factor = 1;
	for (let index = offset; index < source.length && index < offset + 9; index++) {
		const byte = source[index];
		value += (byte & 0x7f) * factor;
		if (!Number.isSafeInteger(value)) throw new TypeError("CAR varint exceeds safe integer range");
		if (!(byte & 0x80)) {
			const length = index - offset + 1;
			if (varint(value).length !== length) throw new TypeError("Non-canonical CAR varint");
			return { value, length };
		}
		factor *= 128;
	}
	throw new TypeError("Malformed CAR varint");
}

export async function decodeCar(source: Uint8Array): Promise<{ roots: CID[]; blocks: CarBlock[] }> {
	let offset = 0;
	const headerLength = readVarint(source, offset); offset += headerLength.length;
	if (!headerLength.value || headerLength.value > source.length - offset) throw new TypeError("Malformed CAR header length");
	let header: unknown;
	try { header = dagCbor.decode(source.slice(offset, offset + headerLength.value)); } catch { throw new TypeError("Malformed CAR header"); }
	offset += headerLength.value;
	if (!header || typeof header !== "object" || Array.isArray(header)) throw new TypeError("Malformed CAR header");
	const value = header as { version?: unknown; roots?: unknown };
	if (value.version !== 1 || !Array.isArray(value.roots) || !value.roots.length || value.roots.some((root) => !CID.asCID(root))) throw new TypeError("Unsupported CAR header");
	const blocks: CarBlock[] = [];
	while (offset < source.length) {
		const sectionLength = readVarint(source, offset); offset += sectionLength.length;
		if (!sectionLength.value || sectionLength.value > source.length - offset) throw new TypeError("Malformed CAR block length");
		const section = source.slice(offset, offset + sectionLength.value); offset += sectionLength.value;
		let cid: CID; let bytes: Uint8Array;
		try { [cid, bytes] = CID.decodeFirst(section); } catch { throw new TypeError("Malformed CAR block CID"); }
		if (cid.version !== 1 || cid.multihash.code !== sha256.code || !cid.equals(CID.createV1(cid.code, await sha256.digest(bytes)))) throw new TypeError("CAR block CID mismatch");
		blocks.push({ cid, bytes });
	}
	return { roots: value.roots.map((root) => CID.asCID(root)!), blocks };
}

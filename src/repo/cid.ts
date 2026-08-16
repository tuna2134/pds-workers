import * as dagCbor from "@ipld/dag-cbor";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";

export async function cidForBytes(bytes: Uint8Array, codec: number = dagCbor.code): Promise<CID> {
	return CID.createV1(codec, await sha256.digest(bytes));
}

export async function encodeBlock(value: unknown): Promise<{ cid: CID; bytes: Uint8Array }> {
	const bytes = dagCbor.encode(value);
	return { cid: await cidForBytes(bytes), bytes };
}

import * as cbor from "@atproto/lex-cbor";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";

const DAG_CBOR_CODEC = 0x71;

export async function cidForBytes(bytes: Uint8Array, codec: number = DAG_CBOR_CODEC): Promise<CID> {
	return CID.createV1(codec, await sha256.digest(bytes));
}

export async function encodeBlock(value: unknown): Promise<{ cid: CID; bytes: Uint8Array }> {
	const bytes = cbor.encode(value as Parameters<typeof cbor.encode>[0]);
	return { cid: await cidForBytes(bytes), bytes };
}

import * as cbor from "@atproto/lex-cbor";
import { formatDidKey, Secp256k1Keypair, verifySignature } from "@atproto/crypto";
import { CID } from "multiformats/cid";
import { encodeBlock } from "./cid";

export interface UnsignedCommit { did: string; version: 3; data: CID; rev: string; prev: CID | null }

export async function createCommit(unsigned: UnsignedCommit, privateKey: Uint8Array) {
	const sig = await (await Secp256k1Keypair.import(privateKey)).sign(cbor.encode(unsigned as unknown as Parameters<typeof cbor.encode>[0]));
	return encodeBlock({ ...unsigned, sig });
}

export async function verifyCommit(bytes: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
	const { sig, ...unsigned } = cbor.decode(bytes) as Record<string, unknown> & { sig: Uint8Array };
	return verifySignature(formatDidKey("ES256K", publicKey), cbor.encode(unsigned as Parameters<typeof cbor.encode>[0]), sig);
}

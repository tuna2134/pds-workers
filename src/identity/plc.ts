import * as dagCbor from "@ipld/dag-cbor";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { base32 } from "multiformats/bases/base32";
import { base58btc } from "multiformats/bases/base58";
import { sha256 } from "multiformats/hashes/sha2";
import { parseDidKey, verifySignature } from "@atproto/crypto";
import { encodeBlock } from "../repo/cid";

export type PlcOperation = {
	type: "plc_operation";
	rotationKeys: string[];
	verificationMethods: Record<string, string> & { atproto: string };
	alsoKnownAs: string[];
	services: Record<string, { type: string; endpoint: string }> & { atproto_pds: { type: "AtprotoPersonalDataServer"; endpoint: string } };
	prev: string | null;
	sig: string;
};

export type PlcDocumentData = Omit<PlcOperation, "type" | "prev" | "sig"> & { did: string };

export function k256DidKey(publicKey: Uint8Array): string {
	if (publicKey.length !== 33) throw new TypeError("Compressed secp256k1 public key required");
	return `did:key:${base58btc.encode(Uint8Array.of(0xe7, 0x01, ...publicKey))}`;
}

function base64url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}

export async function createPlcOperation(input: { handle: string; service: string; rotationKey: Uint8Array; signingPublicKey: Uint8Array | string }) {
	const signingKey = typeof input.signingPublicKey === "string" ? input.signingPublicKey : k256DidKey(input.signingPublicKey);
	const unsigned = {
		type: "plc_operation" as const,
		rotationKeys: [k256DidKey(secp256k1.getPublicKey(input.rotationKey))],
		verificationMethods: { atproto: signingKey },
		alsoKnownAs: [`at://${input.handle}`],
		services: { atproto_pds: { type: "AtprotoPersonalDataServer" as const, endpoint: input.service } },
		prev: null,
	};
	const digest = (await sha256.digest(dagCbor.encode(unsigned))).digest;
	const operation: PlcOperation = { ...unsigned, sig: base64url(secp256k1.sign(digest, input.rotationKey, { prehash: false, format: "compact", lowS: true })) };
	const operationDigest = (await sha256.digest(dagCbor.encode(operation))).digest;
	return { did: `did:plc:${base32.encode(operationDigest).slice(1, 25)}`, operation };
}

export async function createPlcUpdate(directory: string, did: string, handle: string, rotationKey: Uint8Array) {
	return createSignedPlcUpdate(directory, did, { alsoKnownAs: [`at://${handle}`] }, rotationKey);
}

export async function createSignedPlcUpdate(directory: string, did: string, changes: Partial<Pick<PlcDocumentData, "rotationKeys" | "verificationMethods" | "alsoKnownAs" | "services">>, rotationKey: Uint8Array) {
	const base = directory.replace(/\/$/, "");
	const [current, last] = await Promise.all([plcJson(`${base}/${did}/data`), plcJson(`${base}/${did}/log/last`)]);
	if (!current || typeof current !== "object") throw new TypeError("Invalid PLC document data");
	const data = current as PlcDocumentData;
	if (!Array.isArray(data.rotationKeys) || !data.rotationKeys.includes(k256DidKey(secp256k1.getPublicKey(rotationKey))) || !data.verificationMethods?.atproto || !data.services?.atproto_pds) throw new TypeError("PDS rotation key is not authorized by the PLC document");
	const next = { rotationKeys: changes.rotationKeys ?? data.rotationKeys, verificationMethods: changes.verificationMethods ?? data.verificationMethods, alsoKnownAs: changes.alsoKnownAs ?? data.alsoKnownAs, services: changes.services ?? data.services };
	validatePlcData(next);
	const unsigned = {
		type: "plc_operation" as const, ...next, prev: (await encodeBlock(last)).cid.toString(),
	};
	if (dagCbor.encode(unsigned).length > 100_000) throw new RangeError("PLC operation exceeds 100 KB");
	const operation: PlcOperation = { ...unsigned, sig: base64url(secp256k1.sign(dagCbor.encode(unsigned), rotationKey, { prehash: true, format: "compact", lowS: true })) };
	return { operation, data: { did, rotationKeys: operation.rotationKeys, verificationMethods: operation.verificationMethods, alsoKnownAs: operation.alsoKnownAs, services: operation.services } };
}

function validatePlcData(data: Pick<PlcDocumentData, "rotationKeys" | "verificationMethods" | "alsoKnownAs" | "services">) {
	if (!Array.isArray(data.rotationKeys) || data.rotationKeys.length < 1 || data.rotationKeys.length > 5 || new Set(data.rotationKeys).size !== data.rotationKeys.length) throw new TypeError("PLC rotationKeys must contain 1 to 5 unique keys");
	for (const key of data.rotationKeys) if (!(["ES256", "ES256K"] as string[]).includes(parseDidKey(key).jwtAlg)) throw new TypeError("Unsupported PLC rotation key");
	if (!data.verificationMethods || typeof data.verificationMethods !== "object" || Array.isArray(data.verificationMethods) || Object.keys(data.verificationMethods).length < 1 || Object.keys(data.verificationMethods).length > 10) throw new TypeError("Invalid PLC verificationMethods");
	for (const [name, key] of Object.entries(data.verificationMethods)) { if (!name || name.includes("#") || name.length > 100 || typeof key !== "string") throw new TypeError("Invalid PLC verification method"); parseDidKey(key); }
	if (!Array.isArray(data.alsoKnownAs) || data.alsoKnownAs.length > 10 || data.alsoKnownAs.some((value) => typeof value !== "string" || value.length > 2_048)) throw new TypeError("Invalid PLC alsoKnownAs");
	if (!data.services || typeof data.services !== "object" || Array.isArray(data.services) || Object.keys(data.services).length > 10) throw new TypeError("Invalid PLC services");
	for (const [name, service] of Object.entries(data.services)) {
		if (!name || name.includes("#") || name.length > 100 || !service || typeof service.type !== "string" || !service.type || typeof service.endpoint !== "string") throw new TypeError("Invalid PLC service");
		let endpoint: URL; try { endpoint = new URL(service.endpoint); } catch { throw new TypeError("Invalid PLC service endpoint"); }
		if (!/https?:/.test(endpoint.protocol)) throw new TypeError("Invalid PLC service endpoint");
	}
}

export async function submitPlcOperation(directory: string, did: string, operation: PlcOperation): Promise<void> {
	const response = await fetch(`${directory.replace(/\/$/, "")}/${did}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(operation) });
	if (!response.ok) throw new Error(`PLC directory rejected operation (${response.status})`);
}

export async function publishPlcOperation(directory: string, did: string, operation: PlcOperation): Promise<void> {
	try { await submitPlcOperation(directory, did, operation); }
	catch (submitError) {
		try {
			const current = await plcJson(`${directory.replace(/\/$/, "")}/${did}/data`) as PlcDocumentData;
			const expected = { rotationKeys: operation.rotationKeys, verificationMethods: operation.verificationMethods, alsoKnownAs: operation.alsoKnownAs, services: operation.services };
			const actual = { rotationKeys: current.rotationKeys, verificationMethods: current.verificationMethods, alsoKnownAs: current.alsoKnownAs, services: current.services };
			const [actualBytes, expectedBytes] = [dagCbor.encode(actual), dagCbor.encode(expected)];
			if (current.did === did && actualBytes.length === expectedBytes.length && actualBytes.every((byte, index) => byte === expectedBytes[index])) return;
		} catch { /* preserve the publication failure */ }
		throw submitError;
	}
}

function decodeBase64url(value: string) {
	if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("Invalid PLC signature encoding");
	const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
	return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

async function plcJson(url: string) {
	const response = await fetch(url, { headers: { accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(10_000) });
	if (!response.ok) throw new Error(`PLC directory rejected lookup (${response.status})`);
	const bytes = new Uint8Array(await response.arrayBuffer());
	if (bytes.length > 100_000) throw new RangeError("PLC response exceeds 100 KB");
	return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
}

export async function validatePlcUpdate(directory: string, did: string, value: unknown): Promise<{ operation: PlcOperation; data: PlcDocumentData }> {
	if (!value || typeof value !== "object") throw new TypeError("Invalid PLC operation");
	const operation = value as PlcOperation;
	if (operation.type !== "plc_operation" || !Array.isArray(operation.rotationKeys) || !operation.rotationKeys.length || operation.rotationKeys.length > 5 || typeof operation.prev !== "string" || typeof operation.sig !== "string") throw new TypeError("Invalid PLC operation");
	if (!operation.verificationMethods || typeof operation.verificationMethods.atproto !== "string" || !Array.isArray(operation.alsoKnownAs) || !operation.services?.atproto_pds || typeof operation.services.atproto_pds.endpoint !== "string") throw new TypeError("Invalid PLC operation");
	for (const key of [...operation.rotationKeys, ...Object.values(operation.verificationMethods)]) parseDidKey(key);
	const base = directory.replace(/\/$/, "");
	const [current, last] = await Promise.all([plcJson(`${base}/${did}/data`), plcJson(`${base}/${did}/log/last`)]);
	if (!current || typeof current !== "object" || !Array.isArray((current as PlcDocumentData).rotationKeys)) throw new TypeError("Invalid PLC document data");
	if (operation.prev !== (await encodeBlock(last)).cid.toString()) throw new TypeError("PLC operation does not extend the current log");
	const { sig, ...unsigned } = operation;
	const signature = decodeBase64url(sig);
	let valid = false;
	for (const key of (current as PlcDocumentData).rotationKeys) if (await verifySignature(key, dagCbor.encode(unsigned), signature)) { valid = true; break; }
	if (!valid) throw new TypeError("Invalid PLC operation signature");
	return { operation, data: { did, rotationKeys: operation.rotationKeys, verificationMethods: operation.verificationMethods, alsoKnownAs: operation.alsoKnownAs, services: operation.services } };
}

export function plcDocument(data: PlcDocumentData) {
	return {
		"@context": ["https://www.w3.org/ns/did/v1"], id: data.did, alsoKnownAs: data.alsoKnownAs,
		verificationMethod: Object.entries(data.verificationMethods).map(([name, key]) => ({ id: `${data.did}#${name}`, type: "Multikey", controller: data.did, publicKeyMultibase: key.slice("did:key:".length) })),
		service: Object.entries(data.services).map(([name, service]) => ({ id: `${data.did}#${name}`, type: service.type, serviceEndpoint: service.endpoint })),
	};
}

import * as dagCbor from "@ipld/dag-cbor";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { base58btc } from "multiformats/bases/base58";
import { sha256 } from "multiformats/hashes/sha2";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifySignature } from "@atproto/crypto";
import { createPlcOperation, createPlcUpdate, createSignedPlcUpdate, k256DidKey, publishPlcOperation } from "../../src/identity/plc";

describe("DID PLC", () => {
	afterEach(() => vi.unstubAllGlobals());
	it("creates a self-certifying, low-S signed genesis operation", async () => {
		const rotationKey = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
		const signingKey = Uint8Array.from({ length: 32 }, (_, index) => 32 - index);
		const { did, operation } = await createPlcOperation({ handle: "alice.example.com", service: "https://pds.example.com", rotationKey, signingPublicKey: secp256k1.getPublicKey(signingKey) });
		expect(did).toMatch(/^did:plc:[a-z2-7]{24}$/);
		expect(k256DidKey(secp256k1.getPublicKey(rotationKey))).toMatch(/^did:key:z/);
		const { sig, ...unsigned } = operation;
		const signature = Uint8Array.from(atob(sig.replaceAll("-", "+").replaceAll("_", "/") + "=="), (value) => value.charCodeAt(0));
		const digest = (await sha256.digest(dagCbor.encode(unsigned))).digest;
		const encodedRotationKey = operation.rotationKeys[0].slice("did:key:".length);
		const publicKey = base58btc.decode(encodedRotationKey).slice(2);
		expect(secp256k1.verify(signature, digest, publicKey, { prehash: false, lowS: true })).toBe(true);
	});

	it("accepts an ambiguous PLC submission only when the published operation matches", async () => {
		const created = await createPlcOperation({ handle: "retry.example.com", service: "https://pds.example.com", rotationKey: new Uint8Array(32).fill(3), signingPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(4)) });
		const data = { did: created.did, services: created.operation.services, alsoKnownAs: created.operation.alsoKnownAs, verificationMethods: created.operation.verificationMethods, rotationKeys: created.operation.rotationKeys };
		vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response("", { status: 503 })).mockResolvedValueOnce(Response.json(data)));
		await expect(publishPlcOperation("https://plc.directory", created.did, created.operation)).resolves.toBeUndefined();
	});

	it("signs handle updates with the authorized PLC rotation key", async () => {
		const rotationKey = new Uint8Array(32).fill(7);
		const rotationDid = k256DidKey(secp256k1.getPublicKey(rotationKey));
		const data = { did: "did:plc:updatetest", rotationKeys: [rotationDid], verificationMethods: { atproto: rotationDid }, alsoKnownAs: ["at://old.example.com"], services: { atproto_pds: { type: "AtprotoPersonalDataServer" as const, endpoint: "https://pds.example.com" } } };
		vi.stubGlobal("fetch", async (url: string) => Response.json(url.endsWith("/data") ? data : { type: "plc_operation", prev: null, sig: "old" }));
		const { operation } = await createPlcUpdate("https://plc.directory", data.did, "new.example.com", rotationKey);
		const { sig, ...unsigned } = operation;
		const signature = Uint8Array.from(atob(sig.replaceAll("-", "+").replaceAll("_", "/") + "=="), (value) => value.charCodeAt(0));
		expect(operation.alsoKnownAs).toEqual(["at://new.example.com"]);
		expect(await verifySignature(rotationDid, dagCbor.encode(unsigned), signature)).toBe(true);
	});

	it("signs validated migration credentials while the current rotation key is authorized", async () => {
		const rotationKey = new Uint8Array(32).fill(9);
		const rotationDid = k256DidKey(secp256k1.getPublicKey(rotationKey));
		const replacement = k256DidKey(secp256k1.getPublicKey(new Uint8Array(32).fill(10)));
		const data = { did: "did:plc:migrationtest", rotationKeys: [rotationDid], verificationMethods: { atproto: rotationDid }, alsoKnownAs: ["at://old.example.com"], services: { atproto_pds: { type: "AtprotoPersonalDataServer" as const, endpoint: "https://old-pds.example.com" } } };
		vi.stubGlobal("fetch", async (url: string) => Response.json(url.endsWith("/data") ? data : { type: "plc_operation", prev: null, sig: "old" }));
		const { operation } = await createSignedPlcUpdate("https://plc.directory", data.did, { rotationKeys: [replacement], services: { atproto_pds: { type: "AtprotoPersonalDataServer", endpoint: "https://new-pds.example.com" } } }, rotationKey);
		const { sig, ...unsigned } = operation;
		const signature = Uint8Array.from(atob(sig.replaceAll("-", "+").replaceAll("_", "/") + "=="), (value) => value.charCodeAt(0));
		expect(operation.rotationKeys).toEqual([replacement]);
		expect(operation.services.atproto_pds.endpoint).toBe("https://new-pds.example.com");
		expect(await verifySignature(rotationDid, dagCbor.encode(unsigned), signature)).toBe(true);
	});
});

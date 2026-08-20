import { afterEach, describe, expect, it, vi } from "vitest";
import { issueDpopNonce, jwkThumbprint, validDpopNonce, verifyDpop } from "../../src/auth/oauth/dpop";
import { authenticateClient, clientMetadata, redirectUriAllowed, type ClientMetadata } from "../../src/auth/oauth/client-auth";
import type { OAuthStore } from "../../src/auth/oauth/store";
import { expandPermissionScopes } from "../../src/auth/oauth/permissions";
import { assertPublicHost } from "../../src/utils/public-fetch";

afterEach(() => vi.unstubAllGlobals());

function encode(value: object | Uint8Array): string {
	const bytes = value instanceof Uint8Array ? value : new TextEncoder().encode(JSON.stringify(value));
	return Buffer.from(bytes).toString("base64url");
}

describe("OAuth DPoP", () => {
	it("verifies request-bound ES256 proofs and signed server nonces", async () => {
		const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey) as JsonWebKey & { kty: "EC"; crv: "P-256"; x: string; y: string };
		const nonce = await issueDpopNonce("test secret", 10);
		expect(await validDpopNonce(nonce, "test secret", 10)).toBe(true);
		expect(await validDpopNonce(nonce, "test secret", 310)).toBe(true);
		expect(await validDpopNonce(nonce, "test secret", 311)).toBe(false);
		expect(await validDpopNonce(nonce, "test secret", 9)).toBe(false);
		const header = encode({ typ: "dpop+jwt", alg: "ES256", jwk });
		const payload = encode({ jti: "unique-proof", htm: "POST", htu: "https://pds.example.com/oauth/token", iat: 1000, nonce });
		const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(`${header}.${payload}`)));
		const verified = await verifyDpop(`${header}.${payload}.${encode(signature)}`, { method: "POST", url: "https://pds.example.com/oauth/token?ignored=yes", nonce, now: 1000 });
		expect(verified.jkt).toBe(await jwkThumbprint(jwk));
		await expect(verifyDpop(`${header}.${payload}.${encode(signature)}`, { method: "GET", url: "https://pds.example.com/oauth/token", nonce, now: 1000 })).rejects.toThrow("binding mismatch");
		const privateHeader = encode({ typ: "dpop+jwt", alg: "ES256", jwk: { ...jwk, d: "must-not-be-sent" } });
		const privateSignature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(`${privateHeader}.${payload}`)));
		await expect(verifyDpop(`${privateHeader}.${payload}.${encode(privateSignature)}`, { method: "POST", url: "https://pds.example.com/oauth/token", nonce, now: 1000 })).rejects.toThrow("Unsupported DPoP header");
		const badPayload = encode({ jti: 1, htm: "POST", htu: "https://pds.example.com/oauth/token", iat: 1000, nonce });
		const badSignature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(`${header}.${badPayload}`)));
		await expect(verifyDpop(`${header}.${badPayload}.${encode(badSignature)}`, { method: "POST", url: "https://pds.example.com/oauth/token", nonce, now: 1000 })).rejects.toThrow("Invalid DPoP claims");
	});

	it("authenticates confidential clients with bound, non-replayable ES256 assertions", async () => {
		const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const jwk = { ...await crypto.subtle.exportKey("jwk", pair.publicKey), kid: "client-key", alg: "ES256" } as JsonWebKey & { kty: "EC"; crv: "P-256"; x: string; y: string; kid: string; alg: string };
		const clientId = "https://client.example/oauth.json";
		const metadata: ClientMetadata = { client_id: clientId, redirect_uris: ["https://client.example/callback"], scope: "atproto", response_types: ["code"], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "private_key_jwt", token_endpoint_auth_signing_alg: "ES256", dpop_bound_access_tokens: true, jwks: { keys: [jwk] } };
		const now = Math.floor(Date.now() / 1000);
		const header = encode({ alg: "ES256", kid: jwk.kid, typ: "JWT" });
		const payload = encode({ iss: clientId, sub: clientId, aud: "https://pds.example.com", iat: now, exp: now + 60, jti: "assertion-1" });
		const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(`${header}.${payload}`)));
		const seen = new Set<string>();
		const store = { recordProof: async (jkt: string, jti: string) => { const id = `${jkt}:${jti}`; if (seen.has(id)) throw new TypeError("replayed"); seen.add(id); } } as OAuthStore;
		const input = new URLSearchParams({ client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: `${header}.${payload}.${encode(signature)}` });
		await expect(authenticateClient(input, metadata, "https://pds.example.com", store)).resolves.toMatchObject({ kid: "client-key", alg: "ES256" });
		await expect(authenticateClient(input, metadata, "https://pds.example.com", store)).rejects.toThrow("replayed");
		const unsafePayload = encode({ iss: clientId, sub: clientId, aud: "https://pds.example.com", iat: Number.MAX_SAFE_INTEGER + 1, exp: Number.MAX_SAFE_INTEGER + 2, jti: "unsafe-time" });
		const unsafeSignature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(`${header}.${unsafePayload}`)));
		await expect(authenticateClient(new URLSearchParams({ client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: `${header}.${unsafePayload}.${encode(unsafeSignature)}` }), metadata, "https://pds.example.com", store)).rejects.toThrow("Invalid client assertion claims");
	});

	it("enforces redirect URI rules for web, native, and localhost clients", async () => {
		const clientId = "https://client.example:8443/oauth.json";
		const invalid = { client_id: clientId, redirect_uris: ["javascript:alert(1)"], scope: "atproto", response_types: ["code"], grant_types: ["authorization_code"], dpop_bound_access_tokens: true } as ClientMetadata;
		await expect(clientMetadata(clientId, { findClient: async () => invalid } as OAuthStore)).rejects.toThrow("Invalid client metadata");
		await expect(clientMetadata(clientId, { findClient: async () => ({ ...invalid, redirect_uris: ["https://client.example:443/callback"] }) } as OAuthStore)).rejects.toThrow("Invalid client metadata");
		const native = { ...invalid, application_type: "native" as const, redirect_uris: ["example.client:/callback"] };
		await expect(clientMetadata(clientId, { findClient: async () => native } as OAuthStore)).resolves.toBe(native);
		const localId = `http://localhost/?redirect_uri=${encodeURIComponent("http://127.0.0.1/callback")}`;
		const local = await clientMetadata(localId, {} as OAuthStore);
		expect(redirectUriAllowed(local, "http://127.0.0.1:49152/callback")).toBe(true);
		expect(redirectUriAllowed(local, "http://127.0.0.1:49152/other")).toBe(false);
		for (const invalidLocal of ["http://localhost:8080/", "http://user@localhost/", `http://localhost/?redirect_uri=${encodeURIComponent("http://user@127.0.0.1/callback")}`]) {
			await expect(clientMetadata(invalidLocal, { findClient: async () => undefined } as OAuthStore)).rejects.toThrow("Unsafe metadata URL");
		}
	});

	it("resolves and safely expands published Lexicon permission sets", async () => {
		const did = "did:plc:abcdefghijklmnopqrstuvwx";
		vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
			const url = new URL(String(input));
			if (url.hostname === "cloudflare-dns.com" && url.searchParams.get("type") === "A") return Response.json({ Answer: [{ type: 1, data: "93.184.216.34" }] });
			if (url.hostname === "cloudflare-dns.com" && url.searchParams.get("type") === "AAAA") return Response.json({ Answer: [] });
			if (url.hostname === "cloudflare-dns.com") return Response.json({ Answer: [{ data: `did=${did}` }] });
			if (url.hostname === "plc.directory") return Response.json({ id: did, service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: "https://pds.example.com" }] });
			if (url.hostname === "pds.example.com") return Response.json({ value: { $type: "com.atproto.lexicon.schema", lexicon: 1, id: "com.example.authBasic", defs: { main: { type: "permission-set", permissions: [{ type: "permission", resource: "repo", action: ["create", "update"], collection: ["com.example.post"] }, { type: "permission", resource: "rpc", lxm: ["com.example.getThing"], inheritAud: true }, { type: "permission", resource: "repo", action: ["create"], collection: ["net.other.post"] }] } } } });
			return new Response(null, { status: 404 });
		}));
		await expect(expandPermissionScopes(["atproto", "include:com.example.authBasic?aud=did:web:api.example.com%23appview"])).resolves.toBe("atproto repo:com.example.post?action=create&action=update rpc:com.example.getThing?aud=did:web:api.example.com%23appview");
	});

	it("rejects remote hosts resolving to private addresses", async () => {
		vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => Response.json(new URL(String(input)).searchParams.get("type") === "AAAA" ? { Answer: [{ type: 28, data: "::ffff:a00:1" }] } : { Answer: [{ type: 1, data: "10.0.0.1" }] })));
		await expect(assertPublicHost(new URL("https://client.example/oauth.json"))).rejects.toThrow("not public");
	});
});

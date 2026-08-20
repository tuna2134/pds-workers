export type EcJwk = JsonWebKey & { kty: "EC"; crv: "P-256"; x: string; y: string; kid?: string; alg?: string; d?: string };

export type DpopClaims = { jti: string; htm: string; htu: string; iat: number; nonce: string; ath?: string };

function decode(value: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("Invalid base64url");
	const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
	return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function encode(value: Uint8Array): string {
	let binary = "";
	for (const byte of value) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}

function json<T>(part: string): T {
	try { return JSON.parse(new TextDecoder().decode(decode(part))) as T; }
	catch { throw new TypeError("Invalid DPoP JWT"); }
}

export function dpopNonce(proof: string): string | undefined {
	const parts = proof.split(".");
	return parts.length === 3 ? json<{ nonce?: string }>(parts[1]).nonce : undefined;
}

async function digest(value: string): Promise<string> {
	return encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

export async function jwkThumbprint(jwk: EcJwk): Promise<string> {
	return digest(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
}

export async function verifyDpop(proof: string, expected: { method: string; url: string; nonce: string; accessToken?: string; now?: number }) {
	const parts = proof.split(".");
	if (parts.length !== 3) throw new TypeError("Invalid DPoP JWT");
	const header = json<{ typ?: string; alg?: string; jwk?: EcJwk }>(parts[0]);
	const claims = json<Partial<DpopClaims>>(parts[1]);
	if (header.typ?.toLowerCase() !== "dpop+jwt" || header.alg !== "ES256" || header.jwk?.kty !== "EC" || header.jwk.crv !== "P-256" || typeof header.jwk.x !== "string" || typeof header.jwk.y !== "string" || "d" in header.jwk) throw new TypeError("Unsupported DPoP header");
	if (typeof claims.jti !== "string" || !claims.jti || typeof claims.htm !== "string" || typeof claims.htu !== "string" || !Number.isInteger(claims.iat) || typeof claims.nonce !== "string" || !claims.nonce || claims.ath !== undefined && typeof claims.ath !== "string") throw new TypeError("Invalid DPoP claims");
	const url = new URL(expected.url); url.search = ""; url.hash = "";
	if (claims.htm !== expected.method.toUpperCase() || claims.htu !== url.href || claims.nonce !== expected.nonce) throw new TypeError("DPoP request binding mismatch");
	const now = expected.now ?? Math.floor(Date.now() / 1000);
	if (Math.abs(now - claims.iat!) > 300) throw new TypeError("DPoP proof is stale");
	if (expected.accessToken && claims.ath !== await digest(expected.accessToken)) throw new TypeError("DPoP access-token hash mismatch");
	const key = await crypto.subtle.importKey("jwk", header.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
	const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, decode(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
	if (!valid) throw new TypeError("Invalid DPoP signature");
	return { claims: claims as DpopClaims, jkt: await jwkThumbprint(header.jwk) };
}

export async function issueDpopNonce(secret: string, now = Math.floor(Date.now() / 1000)): Promise<string> {
	const payload = String(now);
	const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return `${payload}.${encode(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))))}`;
}

export async function validDpopNonce(nonce: string, secret: string, now = Math.floor(Date.now() / 1000)): Promise<boolean> {
	const [payload, signature, extra] = nonce.split(".");
	const issuedAt = Number(payload);
	if (!payload || !signature || extra || !Number.isSafeInteger(issuedAt) || payload !== String(issuedAt) || issuedAt > now || now - issuedAt > 300) return false;
	try {
		const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
		return crypto.subtle.verify("HMAC", key, decode(signature), new TextEncoder().encode(payload));
	} catch { return false; }
}

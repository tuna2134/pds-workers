type TokenType = "at+jwt" | "refresh+jwt";
const encoder = new TextEncoder();

function base64url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function decode(value: string): Uint8Array {
	const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
	return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

async function hmac(secret: string, usage: ("sign" | "verify")[]): Promise<CryptoKey> {
	const bytes = decode(secret);
	if (bytes.length < 32) throw new TypeError("JWT secret must contain at least 32 bytes");
	return crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, usage);
}

export interface JwtClaims { sub: string; aud: string; scope: string; iat: number; exp: number; jti: string }

export async function signJwt(claims: JwtClaims, type: TokenType, secret: string): Promise<string> {
	const header = base64url(encoder.encode(JSON.stringify({ alg: "HS256", typ: type })));
	const payload = base64url(encoder.encode(JSON.stringify(claims)));
	const message = `${header}.${payload}`;
	return `${message}.${base64url(new Uint8Array(await crypto.subtle.sign("HMAC", await hmac(secret, ["sign"]), encoder.encode(message))))}`;
}

export async function verifyJwt(token: string, type: TokenType, secret: string): Promise<JwtClaims | null> {
	try {
		const [header, payload, signature, extra] = token.split(".");
		if (!header || !payload || !signature || extra) return null;
		const parsedHeader = JSON.parse(new TextDecoder().decode(decode(header))) as { alg?: string; typ?: string };
		if (parsedHeader.alg !== "HS256" || parsedHeader.typ !== type) return null;
		if (!await crypto.subtle.verify("HMAC", await hmac(secret, ["verify"]), decode(signature), encoder.encode(`${header}.${payload}`))) return null;
		const claims = JSON.parse(new TextDecoder().decode(decode(payload))) as JwtClaims;
		const now = Math.floor(Date.now() / 1000);
		return typeof claims.sub === "string" && Boolean(claims.sub) && typeof claims.aud === "string" && Boolean(claims.aud) && typeof claims.scope === "string" && Boolean(claims.scope)
			&& typeof claims.jti === "string" && Boolean(claims.jti) && Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp)
			&& claims.iat <= now + 60 && claims.exp > now && claims.exp > claims.iat ? claims : null;
	} catch { return null; }
}

export async function tokenHash(token: string): Promise<string> {
	return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(token))));
}

import { extractAtprotoData } from "@atproto/did";
import { verifySignature } from "@atproto/crypto";
import { didProvider } from "../identity/did";

function decode(value: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("Invalid JWT encoding");
	const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
	return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

export async function verifyServiceJwt(token: string, issuer: string, audience: string, lxm: string): Promise<boolean> {
	try {
		const [encodedHeader, encodedPayload, encodedSignature, extra] = token.split(".");
		if (!encodedHeader || !encodedPayload || !encodedSignature || extra) return false;
		const header = JSON.parse(new TextDecoder().decode(decode(encodedHeader))) as { alg?: string; typ?: string; kid?: string };
		const claims = JSON.parse(new TextDecoder().decode(decode(encodedPayload))) as { iss?: string; aud?: string; lxm?: string; iat?: number; exp?: number; jti?: string };
		const now = Math.floor(Date.now() / 1000);
		if (!["ES256K", "ES256"].includes(header.alg ?? "") || header.typ !== "JWT" || header.kid !== "#atproto") return false;
		if (claims.iss !== issuer || claims.aud !== audience || claims.lxm !== lxm || typeof claims.jti !== "string") return false;
		if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.iat! > now + 60 || claims.iat! < now - 300 || claims.exp! <= now || claims.exp! > now + 300) return false;
		const key = extractAtprotoData(await didProvider(issuer).resolve(issuer)).key;
		return Boolean(key && await verifySignature(`did:key:${key.publicKeyMultibase}`, new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`), decode(encodedSignature)));
	} catch { return false; }
}

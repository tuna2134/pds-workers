import { jwkThumbprint, type EcJwk } from "./dpop";
import type { OAuthStore } from "./store";
import { publicFetch } from "../../utils/public-fetch";

export type ClientMetadata = {
	client_id: string;
	redirect_uris: string[];
	scope: string;
	response_types: string[];
	grant_types: string[];
	application_type?: "web" | "native";
	token_endpoint_auth_method?: "none" | "private_key_jwt";
	token_endpoint_auth_signing_alg?: "ES256";
	dpop_bound_access_tokens: boolean;
	jwks?: { keys: EcJwk[] };
	jwks_uri?: string;
};

const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

function decode(part: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]+$/.test(part)) throw new TypeError("Invalid JWT encoding");
	const value = part.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((part.length + 3) % 4);
	return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function json<T>(part: string): T {
	try { return JSON.parse(new TextDecoder().decode(decode(part))) as T; }
	catch { throw new TypeError("Invalid client assertion"); }
}

function safeHttpsUrl(value: string) {
	const url = new URL(value);
	if (url.protocol !== "https:" || url.username || url.password || url.hash || /^(localhost|\d+(\.\d+){3}|\[.*\])$/.test(url.hostname)) throw new TypeError("Unsafe metadata URL");
	return url;
}

function validRedirect(clientId: string, applicationType: "web" | "native", value: string): boolean {
	try {
		const url = new URL(value);
		if (url.username || url.password || url.hash) return false;
		if (/^https:\/\/(?:\[[^\]]+\]|[^/:?#]+):443(?:[/?#]|$)/i.test(value)) return false;
		if (applicationType === "web") return url.protocol === "https:";
		const client = new URL(clientId);
		if (url.protocol === "https:") return url.origin === client.origin;
		const scheme = client.hostname.split(".").reverse().join(".");
		return url.protocol === `${scheme}:` && value.startsWith(`${scheme}:/`) && !value.startsWith(`${scheme}://`) && url.pathname.length > 1;
	} catch { return false; }
}

export function redirectUriAllowed(metadata: ClientMetadata, requested: string): boolean {
	const local = virtualClient(metadata.client_id);
	if (!local) return metadata.redirect_uris.includes(requested);
	try {
		const actual = new URL(requested);
		return metadata.redirect_uris.some((declared) => {
			const expected = new URL(declared);
			return actual.protocol === "http:" && ["127.0.0.1", "[::1]"].includes(actual.hostname) && actual.protocol === expected.protocol && actual.hostname === expected.hostname && actual.pathname === expected.pathname && actual.search === expected.search && !actual.hash;
		});
	} catch { return false; }
}

async function fetchJson<T>(url: URL): Promise<T> {
	const response = await publicFetch(url, { headers: { accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(10_000) });
	if (response.status !== 200 || !response.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new TypeError("Invalid metadata response");
	const length = Number(response.headers.get("content-length"));
	if (Number.isFinite(length) && length > 100_000) throw new TypeError("Metadata response too large");
	const bytes = new Uint8Array(await response.arrayBuffer());
	if (bytes.length > 100_000) throw new TypeError("Metadata response too large");
	return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

function virtualClient(clientId: string): ClientMetadata | undefined {
	const url = new URL(clientId);
	if (url.protocol !== "http:" || url.hostname !== "localhost" || url.port || url.username || url.password || url.hash || url.pathname !== "/" || url.searchParams.getAll("scope").length > 1) return;
	const redirects = url.searchParams.getAll("redirect_uri");
	if (redirects.some((redirect) => { try { const parsed = new URL(redirect); return parsed.protocol !== "http:" || parsed.username || parsed.password || parsed.hash || (parsed.hostname !== "127.0.0.1" && parsed.hostname !== "[::1]"); } catch { return true; } })) return;
	return { client_id: clientId, redirect_uris: redirects.length ? redirects : ["http://127.0.0.1/", "http://[::1]/"], scope: url.searchParams.get("scope") ?? "atproto", response_types: ["code"], grant_types: ["authorization_code", "refresh_token"], application_type: "native", token_endpoint_auth_method: "none", dpop_bound_access_tokens: true };
}

export async function clientMetadata(clientId: string, store: OAuthStore): Promise<ClientMetadata> {
	const local = virtualClient(clientId);
	if (local) return local;
	const cached = await store.findClient(clientId);
	const metadata = cached ?? await fetchJson<ClientMetadata>(safeHttpsUrl(clientId));
	const applicationType = metadata.application_type ?? "web";
	if (metadata.client_id !== clientId || !["web", "native"].includes(applicationType) || !Array.isArray(metadata.redirect_uris) || !metadata.redirect_uris.length || metadata.redirect_uris.some((redirect) => typeof redirect !== "string" || !validRedirect(clientId, applicationType, redirect)) || !metadata.response_types?.includes("code") || !metadata.grant_types?.includes("authorization_code") || typeof metadata.scope !== "string" || !metadata.scope.split(" ").includes("atproto") || metadata.dpop_bound_access_tokens !== true) throw new TypeError("Invalid client metadata");
	const method = metadata.token_endpoint_auth_method ?? "none";
	if (method !== "none" && method !== "private_key_jwt") throw new TypeError("Unsupported client authentication method");
	if (method === "private_key_jwt" && (metadata.token_endpoint_auth_signing_alg !== "ES256" || Boolean(metadata.jwks) === Boolean(metadata.jwks_uri))) throw new TypeError("Invalid confidential client metadata");
	if (!cached) await store.saveClient(metadata);
	return metadata;
}

async function clientKeys(metadata: ClientMetadata): Promise<EcJwk[]> {
	if (metadata.jwks) return metadata.jwks.keys;
	const uri = safeHttpsUrl(metadata.jwks_uri!);
	const result = await fetchJson<{ keys?: EcJwk[] }>(uri);
	if (!Array.isArray(result.keys)) throw new TypeError("Invalid client JWKS");
	return result.keys;
}

export async function authenticateClient(input: URLSearchParams, metadata: ClientMetadata, issuer: string, store: OAuthStore) {
	const method = metadata.token_endpoint_auth_method ?? "none";
	const assertion = input.get("client_assertion");
	const assertionType = input.get("client_assertion_type");
	if (method === "none") {
		if (assertion || assertionType) throw new TypeError("Public client must not authenticate");
		return;
	}
	if (!assertion || assertionType !== ASSERTION_TYPE) throw new TypeError("Client assertion required");
	const parts = assertion.split(".");
	if (parts.length !== 3) throw new TypeError("Invalid client assertion");
	const header = json<{ alg?: string; kid?: string }>(parts[0]);
	const claims = json<{ iss?: string; sub?: string; aud?: string | string[]; jti?: string; iat?: number; exp?: number }>(parts[1]);
	const now = Math.floor(Date.now() / 1000);
	const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
	if (header.alg !== "ES256" || !header.kid || claims.iss !== metadata.client_id || claims.sub !== metadata.client_id || !audience.includes(issuer) || !claims.jti || !Number.isInteger(claims.iat) || !Number.isInteger(claims.exp) || claims.iat! < now - 300 || claims.iat! > now + 60 || claims.exp! <= now || claims.exp! > claims.iat! + 300) throw new TypeError("Invalid client assertion claims");
	const key = (await clientKeys(metadata)).find((candidate) => candidate.kid === header.kid && candidate.kty === "EC" && candidate.crv === "P-256" && (!candidate.alg || candidate.alg === "ES256") && !candidate.d);
	if (!key?.x || !key.y) throw new TypeError("Unknown client authentication key");
	const imported = await crypto.subtle.importKey("jwk", key, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
	if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, imported, decode(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`))) throw new TypeError("Invalid client assertion signature");
	const result = { kid: header.kid, alg: header.alg, jkt: await jwkThumbprint(key) };
	await store.recordProof(result.jkt, claims.jti);
	return result;
}

import { verifyPasswordOrDummy } from "../password";
import { tokenHash } from "../../crypto/jwt";
import { AccountRepository } from "../../db/accounts";
import { d1 } from "../../db/d1";
import { dpopNonce, issueDpopNonce, validDpopNonce, verifyDpop } from "./dpop";
import { OAuthStore, randomToken } from "./store";
import { isAtprotoOauthScope } from "@atproto/oauth-scopes";
import { authenticateClient, clientMetadata, redirectUriAllowed } from "./client-auth";
import { AuditRepository } from "../../db/audit";
import { expandPermissionScopes } from "./permissions";
import { constantTimeEqual } from "../../crypto/constant-time";

function oauthError(error: string, status = 400, description?: string, nonce?: string) {
	return Response.json({ error, ...(description ? { error_description: description } : {}) }, { status, headers: { "cache-control": "no-store", ...(nonce ? { "dpop-nonce": nonce } : {}) } });
}

async function form(request: Request): Promise<URLSearchParams> {
	if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/x-www-form-urlencoded")) throw new TypeError("Form encoding required");
	const length = Number(request.headers.get("content-length"));
	if (Number.isFinite(length) && length > 100_000) throw new TypeError("Request too large");
	const body = new TextDecoder().decode(await request.arrayBuffer());
	if (body.length > 100_000) throw new TypeError("Request too large");
	return new URLSearchParams(body);
}

async function proof(request: Request, env: Env, endpoint: string, accessToken?: string) {
	const nextNonce = await issueDpopNonce(env.SESSION_JWT_SECRET);
	const value = request.headers.get("dpop");
	if (!value) return { error: oauthError("use_dpop_nonce", 400, undefined, nextNonce) };
	try {
		const nonce = dpopNonce(value);
		if (!nonce || !await validDpopNonce(nonce, env.SESSION_JWT_SECRET)) throw new TypeError("Invalid nonce");
		const verified = await verifyDpop(value, { method: request.method, url: `${env.PDS_URL}${endpoint}`, nonce, accessToken });
		const store = new OAuthStore(d1(env.DB));
		await store.recordProof(verified.jkt, verified.claims.jti);
		return { verified, nonce: nextNonce };
	} catch { return { error: oauthError("invalid_dpop_proof", 400, undefined, nextNonce) }; }
}

function html(value: string) { return value.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"); }

function authorizationRedirect(url: URL) {
	return new Response(null, { status: 303, headers: { location: url.href, "set-cookie": "oauth_csrf=; Path=/oauth/authorize; Max-Age=0; HttpOnly; Secure; SameSite=Lax", "cache-control": "no-store" } });
}

function sessionExpiry(confidential: boolean) {
	return new Date(Date.now() + (confidential ? 90 : 14) * 24 * 60 * 60_000);
}

function clientAuthMatches(session: { clientAuthKid: string | null; clientAuthAlg: string | null; clientAuthJkt: string | null }, authentication?: { kid: string; alg: string; jkt: string }) {
	return authentication ? session.clientAuthKid === authentication.kid && session.clientAuthAlg === authentication.alg && session.clientAuthJkt === authentication.jkt : session.clientAuthJkt === null;
}

async function audit(env: Env, request: Request, action: string, accountId?: string) {
	await new AuditRepository(d1(env.DB)).record({ action, accountId, requestId: request.headers.get("x-request-id") ?? crypto.randomUUID(), ipHash: await tokenHash(request.headers.get("cf-connecting-ip") ?? "unknown") });
}

export async function oauthRoute(request: Request, env: Env): Promise<Response | undefined> {
	const url = new URL(request.url);
	if (request.method === "POST" && ["/oauth/par", "/oauth/token", "/oauth/revoke"].includes(url.pathname)) {
		const limited = await env.OAUTH_TOKEN_RATE.limit({ key: `${url.pathname}:${await tokenHash(request.headers.get("cf-connecting-ip") ?? "unknown")}` });
		if (!limited.success) return oauthError("temporarily_unavailable", 429);
	}
	if (url.pathname === "/oauth/par" && request.method === "POST") {
		const checked = await proof(request, env, "/oauth/par");
		if (checked.error) return checked.error;
		try {
			const input = await form(request);
			const clientId = input.get("client_id") ?? "";
			const store = new OAuthStore(d1(env.DB));
			const metadata = await clientMetadata(clientId, store);
			const clientAuth = await authenticateClient(input, metadata, env.PDS_URL, store);
			const redirectUri = input.get("redirect_uri") ?? "";
			const scope = input.get("scope") ?? "";
			const scopes = scope.split(" ").filter(Boolean);
			const challenge = input.get("code_challenge") ?? "";
			const state = input.get("state") ?? "";
			if (input.get("response_type") !== "code" || input.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge) || !state || !scopes.includes("atproto") || scopes.some((item) => !isAtprotoOauthScope(item)) || !redirectUriAllowed(metadata, redirectUri) || !scopes.every((item) => metadata.scope.split(" ").includes(item))) throw new TypeError("Invalid authorization request or unsupported scope");
			const permissionsScope = await expandPermissionScopes(scopes);
			const result = await store.createPar({ clientId, state, pkceChallenge: challenge, dpopJkt: checked.verified!.jkt, redirectUri, scope, permissionsScope, loginHint: input.get("login_hint") ?? undefined, clientAuth });
			return Response.json({ request_uri: result.requestUri, expires_in: 300 }, { status: 201, headers: { "cache-control": "no-store", "dpop-nonce": checked.nonce! } });
		} catch (error) { return oauthError("invalid_request", 400, error instanceof Error ? error.message : undefined, checked.nonce); }
	}
	if (url.pathname === "/oauth/authorize" && request.method === "GET") {
		const requestUri = url.searchParams.get("request_uri") ?? "";
		const prepared = await new OAuthStore(d1(env.DB)).prepareAuthorization(requestUri);
		if (!prepared || prepared.session.clientId !== url.searchParams.get("client_id")) return oauthError("invalid_request_uri");
		const body = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize</title></head><body><main><h1>Authorize ${html(new URL(prepared.session.clientId).hostname)}</h1><p>Client: <code>${html(prepared.session.clientId)}</code></p><p>Requested access: <code>${html(prepared.session.scope ?? "")}</code></p><form method="post"><input type="hidden" name="request_uri" value="${html(requestUri)}"><input type="hidden" name="client_id" value="${html(prepared.session.clientId)}"><input type="hidden" name="csrf" value="${prepared.csrf}"><label>Account <input name="identifier" value="${html(prepared.session.loginHint ?? "")}" required autocomplete="username"></label><label>Password <input name="password" type="password" required autocomplete="current-password"></label><button name="action" value="approve">Authorize</button><button name="action" value="deny">Deny</button></form></main></body></html>`;
		return new Response(body, { headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'", "set-cookie": `oauth_csrf=${prepared.csrf}; Path=/oauth/authorize; Max-Age=300; HttpOnly; Secure; SameSite=Lax`, "cache-control": "no-store" } });
	}
	if (url.pathname === "/oauth/authorize" && request.method === "POST") {
		try {
			const input = await form(request);
			const requestUri = input.get("request_uri") ?? "";
			const pending = await new OAuthStore(d1(env.DB)).findRequest(requestUri);
			const csrf = input.get("csrf") ?? "";
			const cookieCsrf = request.headers.get("cookie")?.match(/(?:^|;\s*)oauth_csrf=([^;]+)/)?.[1] ?? "";
			if (!pending || pending.clientId !== input.get("client_id") || !csrf || !await constantTimeEqual(cookieCsrf, csrf)) return oauthError("invalid_request");
			const redirect = new URL(pending.redirectUri!);
			if (input.get("action") === "deny") {
				if (!await new OAuthStore(d1(env.DB)).cancel(requestUri)) return oauthError("invalid_request");
				redirect.searchParams.set("error", "access_denied"); redirect.searchParams.set("state", pending.state!); redirect.searchParams.set("iss", env.PDS_URL);
				return authorizationRedirect(redirect);
			}
			const identifier = input.get("identifier") ?? "";
			const [accountLimit, ipLimit] = await Promise.all([env.LOGIN_ACCOUNT_RATE.limit({ key: await tokenHash(identifier.toLowerCase()) }), env.LOGIN_IP_RATE.limit({ key: await tokenHash(request.headers.get("cf-connecting-ip") ?? "unknown") })]);
			if (!accountLimit.success || !ipLimit.success) return oauthError("temporarily_unavailable", 429);
			const account = await new AccountRepository(d1(env.DB)).find(identifier);
			const hintedAccount = !pending.loginHint || pending.loginHint === account?.did || pending.loginHint.toLowerCase() === account?.handle.toLowerCase();
			const passwordValid = await verifyPasswordOrDummy(input.get("password") ?? "", account?.passwordHash);
			if (!account || !hintedAccount || account.status !== "active" || !passwordValid) { await audit(env, request, "oauth.authorization.failed", account?.id); return oauthError("access_denied", 401, "Invalid account or password"); }
			const authorized = await new OAuthStore(d1(env.DB)).authorize(requestUri, csrf, account.id);
			if (!authorized) return oauthError("invalid_request");
			await audit(env, request, "oauth.authorization.approved", account.id);
			redirect.searchParams.set("code", authorized.code); redirect.searchParams.set("state", authorized.session.state!); redirect.searchParams.set("iss", env.PDS_URL);
			return authorizationRedirect(redirect);
		} catch { return oauthError("invalid_request"); }
	}
	if (url.pathname === "/oauth/token" && request.method === "POST") {
		const checked = await proof(request, env, "/oauth/token");
		if (checked.error) return checked.error;
		try {
			const input = await form(request);
			const store = new OAuthStore(d1(env.DB));
			const clientId = input.get("client_id") ?? "";
			const metadata = await clientMetadata(clientId, store);
			const clientAuth = await authenticateClient(input, metadata, env.PDS_URL, store);
			const accessToken = randomToken(); const refreshToken = randomToken();
			let session;
			if (input.get("grant_type") === "authorization_code") {
				const found = await store.findCode(input.get("code") ?? "", clientId, input.get("redirect_uri") ?? "");
				const verifier = input.get("code_verifier") ?? "";
				if (!found || found.dpopJkt !== checked.verified!.jkt || !clientAuthMatches(found, clientAuth) || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || await tokenHash(verifier) !== found.pkceChallenge) return oauthError("invalid_grant", 400, undefined, checked.nonce);
				session = await store.consumeCode(found.id, accessToken, refreshToken, sessionExpiry(Boolean(clientAuth)));
				if (!session) return oauthError("invalid_grant", 400, undefined, checked.nonce);
			} else if (input.get("grant_type") === "refresh_token") {
				const previous = input.get("refresh_token") ?? "";
				const found = await store.findRefresh(previous);
				if (!found || found.clientId !== clientId || found.dpopJkt !== checked.verified!.jkt || !clientAuthMatches(found, clientAuth) || !metadata.grant_types.includes("refresh_token")) return oauthError("invalid_grant", 400, undefined, checked.nonce);
				session = await store.rotateRefresh(found.id, previous, accessToken, refreshToken, sessionExpiry(Boolean(clientAuth)));
				if (!session) return oauthError("invalid_grant", 400, undefined, checked.nonce);
			} else return oauthError("unsupported_grant_type", 400, undefined, checked.nonce);
			const account = await new AccountRepository(d1(env.DB)).findById(session.accountId!);
			if (!account) return oauthError("invalid_grant", 400, undefined, checked.nonce);
			await audit(env, request, "oauth.token.issued", account.id);
			return Response.json({ access_token: accessToken, token_type: "DPoP", expires_in: 300, refresh_token: refreshToken, scope: session.scope, sub: account.did }, { headers: { "cache-control": "no-store", "dpop-nonce": checked.nonce! } });
		} catch { return oauthError("invalid_request", 400, undefined, checked.nonce); }
	}
	if (url.pathname === "/oauth/revoke" && request.method === "POST") {
		const checked = await proof(request, env, "/oauth/revoke");
		if (checked.error) return checked.error;
		try {
			const input = await form(request);
			const token = input.get("token") ?? "";
			const clientId = input.get("client_id") ?? "";
			if (!token || !clientId) throw new TypeError("token and client_id are required");
			const store = new OAuthStore(d1(env.DB));
			const authentication = await authenticateClient(input, await clientMetadata(clientId, store), env.PDS_URL, store);
			const session = await store.findToken(token);
			if (session && (session.clientId !== clientId || session.dpopJkt !== checked.verified!.jkt || !clientAuthMatches(session, authentication))) return oauthError("invalid_client", 401, undefined, checked.nonce);
			if (session) { await store.revoke(token); await audit(env, request, "oauth.session.revoked", session.accountId ?? undefined); }
			return new Response(null, { status: 200, headers: { "dpop-nonce": checked.nonce! } });
		}
		catch { return oauthError("invalid_request", 400, undefined, checked.nonce); }
	}
}

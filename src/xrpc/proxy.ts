import { authenticated } from "../api/register";
import { tokenHash } from "../crypto/jwt";
import type { AccountRepo } from "../durable/account-repo";
import { resolveService } from "../identity/did";
import { isValidNsid } from "@atproto/syntax";
import { issueDpopNonce } from "../auth/oauth/dpop";
import { XrpcError, xrpcErrorResponse } from "./errors";
import { publicFetch } from "../utils/public-fetch";

const REQUEST_HEADERS = ["accept", "accept-language", "content-type", "atproto-accept-labelers"];
const RESPONSE_HEADERS = ["content-type", "cache-control", "etag", "atproto-content-labelers", "retry-after", "www-authenticate"];

export async function proxyXrpc(request: Request, env: Env): Promise<Response> {
	const started = performance.now();
	const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
	const nsid = new URL(request.url).pathname.slice(6);
	let status = 500;
	try {
		const url = new URL(request.url);
		if (!isValidNsid(nsid) || (request.method !== "GET" && request.method !== "POST")) throw new XrpcError(404, "MethodNotFound");
		const audience = request.headers.get("atproto-proxy");
		if (!audience) throw new XrpcError(404, "MethodNotFound");
		const rate = await env.PROXY_RATE.limit({ key: await tokenHash(request.headers.get("cf-connecting-ip") ?? "unknown") });
		if (!rate.success) throw new XrpcError(429, "RateLimitExceeded");
		const auth = await authenticated({ request, env, params: url.searchParams, requestId });
		if (auth.permissions && !auth.permissions.allowsRpc({ aud: audience, lxm: nsid })) throw new XrpcError(403, "AuthScopeMismatch");
		const length = Number(request.headers.get("content-length"));
		if (Number.isFinite(length) && length > 10_000_000) throw new XrpcError(413, "PayloadTooLarge");
		const body = request.method === "POST" ? new Uint8Array(await request.arrayBuffer()) : undefined;
		if (body && body.length > 10_000_000) throw new XrpcError(413, "PayloadTooLarge");
		const endpoint = await resolveService(audience);
		const target = new URL(`${url.pathname}${url.search}`, endpoint);
		const headers = new Headers();
		for (const name of REQUEST_HEADERS) if (request.headers.has(name)) headers.set(name, request.headers.get(name)!);
		const repo = env.ACCOUNT_REPO.getByName(auth.account.did) as unknown as AccountRepo;
		headers.set("authorization", `Bearer ${await repo.signServiceAuth(audience, nsid)}`);
		const upstream = await publicFetch(target, { method: request.method, headers, body, redirect: "manual", signal: AbortSignal.timeout(30_000) });
		if (upstream.status >= 300 && upstream.status < 400) throw new XrpcError(502, "UpstreamFailure", "Service redirects are not allowed");
		const responseHeaders = new Headers({ "x-request-id": requestId, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" });
		for (const name of RESPONSE_HEADERS) if (upstream.headers.has(name)) responseHeaders.set(name, upstream.headers.get(name)!);
		for (const [name, value] of upstream.headers) if (name.startsWith("ratelimit-")) responseHeaders.set(name, value);
		if (request.headers.has("dpop") || request.headers.get("authorization")?.startsWith("DPoP ")) responseHeaders.set("dpop-nonce", await issueDpopNonce(env.SESSION_JWT_SECRET));
		status = upstream.status;
		return new Response(upstream.body, { status, statusText: upstream.statusText, headers: responseHeaders });
	} catch (error) {
		const response = xrpcErrorResponse(error instanceof XrpcError ? error : new XrpcError(502, "UpstreamFailure"), requestId);
		status = response.status;
		const headers = new Headers(response.headers);
		if (request.headers.has("dpop") || request.headers.get("authorization")?.startsWith("DPoP ")) headers.set("dpop-nonce", await issueDpopNonce(env.SESSION_JWT_SECRET));
		return new Response(response.body, { status, headers });
	} finally {
		console.log(JSON.stringify({ requestId, nsid, method: request.method, status, durationMs: Math.round(performance.now() - started), proxy: true }));
	}
}

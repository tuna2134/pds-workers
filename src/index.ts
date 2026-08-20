/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export { AccountRepo } from "./durable/account-repo";
export { Firehose } from "./durable/firehose";
import { Hono } from "hono";
import { createRouter } from "./api/register";
import { authorizationServerMetadata, protectedResourceMetadata } from "./auth/oauth/metadata";
import { oauthRoute } from "./auth/oauth/routes";
import { d1 } from "./db/d1";
import { AccountRepository } from "./db/accounts";
import { cleanupBlob, type BlobCleanupMessage } from "./blob/cleanup";
import { proxyXrpc } from "./xrpc/proxy";
import { requireAdmin } from "./auth/admin";
import { XrpcError, xrpcErrorResponse } from "./xrpc/errors";
import { validDid } from "./identity/did";
import { AuditRepository } from "./db/audit";
import { tokenHash } from "./crypto/jwt";
import { readBody } from "./utils/body";

const router = createRouter();
const app = new Hono<{ Bindings: Env }>();

function pitrTarget(url: URL, env: Env) {
	const kind = url.searchParams.get("kind");
	if (kind === "firehose") return env.FIREHOSE.getByName("global");
	const did = url.searchParams.get("did") ?? "";
	if (kind !== "account" || !validDid(did)) throw new XrpcError(400, "InvalidRequest", "kind=account requires a valid did; kind=firehose does not");
	return env.ACCOUNT_REPO.getByName(did);
}

async function adminPitr(request: Request, env: Env) {
	try {
		await requireAdmin(request, env);
		const url = new URL(request.url);
		const target = pitrTarget(url, env);
		if (request.method === "GET") {
			const input = url.searchParams.get("timestamp");
			const at = input === null ? undefined : Date.parse(input);
			if (at !== undefined && (!Number.isFinite(at) || at > Date.now() || at < Date.now() - 30 * 86_400_000)) throw new XrpcError(400, "InvalidRequest", "timestamp must be within the previous 30 days");
			return Response.json({ bookmark: await target.pitrBookmark(at) });
		}
		if (request.method !== "POST") throw new XrpcError(405, "MethodNotAllowed");
		if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new XrpcError(400, "InvalidRequest", "Content-Type must be application/json");
		let bookmark: string | undefined;
		try { ({ bookmark } = JSON.parse(new TextDecoder().decode(await readBody(request, 2_048))) as { bookmark?: string }); }
		catch (error) {
			if (error instanceof RangeError) throw new XrpcError(413, "PayloadTooLarge");
			throw new XrpcError(400, "InvalidRequest", "Invalid JSON body");
		}
		if (!bookmark || bookmark.length > 256 || !/^[A-Za-z0-9_-]+$/.test(bookmark) || request.headers.get("x-confirm-restore") !== bookmark) throw new XrpcError(400, "InvalidRequest", "x-confirm-restore must exactly match a valid bookmark");
		const undoBookmark = await target.schedulePitrRestore(bookmark);
		await new AuditRepository(d1(env.DB)).record({ action: "admin.pitr.scheduled", requestId: request.headers.get("x-request-id") ?? crypto.randomUUID(), ipHash: await tokenHash(request.headers.get("cf-connecting-ip") ?? "unknown"), detail: { kind: url.searchParams.get("kind"), did: url.searchParams.get("did"), bookmark, undoBookmark } });
		return Response.json({ undoBookmark, restartRequired: true }, { status: 202 });
	} catch (error) { return xrpcErrorResponse(error, request.headers.get("x-request-id") ?? crypto.randomUUID()); }
}

function oauthHeaders(response: Response) {
	const headers = new Headers(response.headers);
	headers.set("access-control-allow-origin", "*");
	headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
	headers.set("access-control-allow-headers", "content-type, dpop");
	headers.set("access-control-expose-headers", "dpop-nonce");
	headers.set("x-content-type-options", "nosniff");
	headers.set("referrer-policy", "no-referrer");
	return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function xrpcHeaders(response: Response, request: Request) {
	const headers = new Headers(response.headers);
	headers.set("access-control-allow-origin", "*");
	headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
	headers.set("access-control-allow-headers", request.headers.get("access-control-request-headers") ?? "authorization, content-type, dpop, atproto-proxy, atproto-accept-labelers, x-request-id");
	headers.set("access-control-expose-headers", "dpop-nonce, www-authenticate, atproto-content-labelers, ratelimit-limit, ratelimit-remaining, ratelimit-reset, retry-after, x-request-id");
	headers.set("access-control-max-age", "86400");
	return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

app.all("/admin/pitr", (c) => adminPitr(c.req.raw, c.env));
app.get("/.well-known/oauth-protected-resource", (c) => Response.json(protectedResourceMetadata(c.env), { headers: { "access-control-allow-origin": "*" } }));
app.get("/.well-known/oauth-authorization-server", (c) => Response.json(authorizationServerMetadata(c.env), { headers: { "access-control-allow-origin": "*" } }));
app.get("/.well-known/did.json", (c) => c.env.SERVICE_DID.startsWith("did:web:") ? Response.json({
	"@context": ["https://www.w3.org/ns/did/v1"],
	id: c.env.SERVICE_DID,
	service: [{ id: `${c.env.SERVICE_DID}#atproto_pds`, type: "AtprotoPersonalDataServer", serviceEndpoint: c.env.PDS_URL }],
}, { headers: { "cache-control": "public, max-age=300" } }) : c.notFound());
app.get("/.well-known/atproto-did", async (c) => {
	const account = await new AccountRepository(d1(c.env.DB)).find(new URL(c.req.url).hostname.toLowerCase());
	return account?.status === "active" ? new Response(account.did, { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=300" } }) : c.notFound();
});
app.options("/oauth/*", () => oauthHeaders(new Response(null, { status: 204 })));
app.all("/oauth/*", async (c) => oauthHeaders(await oauthRoute(c.req.raw, c.env) ?? new Response("Not Found", { status: 404 })));
app.all("/xrpc/com.atproto.sync.subscribeRepos", (c) => c.env.FIREHOSE.getByName("global").fetch(c.req.raw));
app.options("/xrpc/*", (c) => xrpcHeaders(new Response(null, { status: 204 }), c.req.raw));
app.all("/xrpc/:nsid", async (c) => {
	const { nsid } = c.req.param();
	const request = c.req.raw;
	const local = router.has(nsid, request.method);
	const localAppState = nsid === "app.bsky.actor.getPreferences" || nsid === "app.bsky.actor.putPreferences";
	return xrpcHeaders(await (!local || request.headers.has("atproto-proxy") && nsid.startsWith("app.bsky.") && !localAppState ? proxyXrpc(request, c.env) : router.handle(request, c.env)), request);
});

export default {
	fetch: (request, env, ctx) => app.fetch(request, env, ctx),
	async queue(batch: MessageBatch<BlobCleanupMessage>, env): Promise<void> {
		for (const message of batch.messages) {
			try { await cleanupBlob(env, message.body); message.ack(); }
			catch (error) { if (error instanceof TypeError) message.ack(); else message.retry(); }
		}
	},
} satisfies ExportedHandler<Env, BlobCleanupMessage>;

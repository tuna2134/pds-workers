import { XrpcError, xrpcErrorResponse } from "./errors";
import { issueDpopNonce } from "../auth/oauth/dpop";
import { validateXrpcBody, validateXrpcOutput, validateXrpcRequest } from "../lexicon/xrpc";

export interface XrpcContext { request: Request; env: Env; params: URLSearchParams; requestId: string }
type Handler = (context: XrpcContext) => unknown | Promise<unknown>;

export class XrpcRouter {
	readonly #queries = new Map<string, Handler>();
	readonly #procedures = new Map<string, Handler>();

	registerQuery(nsid: string, handler: Handler) { this.#register(this.#queries, nsid, handler); }
	registerProcedure(nsid: string, handler: Handler) { this.#register(this.#procedures, nsid, handler); }
	has(nsid: string, method: string) { return (method === "GET" ? this.#queries : method === "POST" ? this.#procedures : new Map()).has(nsid); }

	async handle(request: Request, env: Env): Promise<Response> {
		const started = performance.now();
		const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
		const url = new URL(request.url);
		const nsid = url.pathname.startsWith("/xrpc/") ? url.pathname.slice(6) : "";
		let status = 500;
		try {
			const registry = request.method === "GET" ? this.#queries : request.method === "POST" ? this.#procedures : null;
			if (!registry) throw new XrpcError(405, "MethodNotAllowed");
			const handler = registry.get(nsid);
			if (!handler) throw new XrpcError(404, "MethodNotFound");
			try { validateXrpcRequest(nsid, request, url.searchParams); }
			catch (error) { throw new XrpcError(400, "InvalidRequest", error instanceof Error ? error.message : "Invalid request"); }
			const value = await handler({ request, env, params: url.searchParams, requestId });
			const response = value instanceof Response ? value : Response.json(value);
			validateXrpcOutput(nsid, value, response);
			status = response.status;
			return await this.#headers(response, requestId, request, env);
		} catch (error) {
			const response = xrpcErrorResponse(error, requestId);
			status = response.status;
			return await this.#headers(response, requestId, request, env);
		} finally {
			console.log(JSON.stringify({ requestId, nsid, method: request.method, status, durationMs: Math.round(performance.now() - started) }));
		}
	}

	#register(registry: Map<string, Handler>, nsid: string, handler: Handler) {
		if (registry.has(nsid)) throw new Error(`Duplicate XRPC route: ${nsid}`);
		registry.set(nsid, handler);
	}

	async #headers(response: Response, requestId: string, request: Request, env: Env): Promise<Response> {
		const headers = new Headers(response.headers);
		headers.set("x-request-id", requestId);
		headers.set("x-content-type-options", "nosniff");
		headers.set("referrer-policy", "no-referrer");
		if (request.headers.has("dpop") || request.headers.get("authorization")?.startsWith("DPoP ")) headers.set("dpop-nonce", await issueDpopNonce(env.SESSION_JWT_SECRET));
		return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
	}
}

export function required(params: URLSearchParams, name: string): string {
	const value = params.get(name);
	if (!value) throw new XrpcError(400, "InvalidRequest", `Missing required parameter: ${name}`);
	return value;
}

export async function jsonBody<T>(request: Request, maximum = 1_000_000): Promise<T> {
	const length = Number(request.headers.get("content-length") ?? 0);
	if (length > maximum) throw new XrpcError(413, "PayloadTooLarge");
	if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new XrpcError(400, "InvalidRequest", "Content-Type must be application/json");
	const bytes = new Uint8Array(await request.arrayBuffer());
	if (bytes.length > maximum) throw new XrpcError(413, "PayloadTooLarge");
	try {
		const value = JSON.parse(new TextDecoder().decode(bytes)) as T;
		validateXrpcBody(new URL(request.url).pathname.slice(6), value);
		return value;
	}
	catch (error) {
		if (error instanceof XrpcError) throw error;
		throw new XrpcError(400, "InvalidRequest", error instanceof SyntaxError ? "Invalid JSON body" : error instanceof Error ? error.message : "Invalid request body");
	}
}

import { jsonToLex, type Payload, type Procedure, type Query } from "@atproto/lex";
import { com } from "./generated";

type Method = Query | Procedure;

function collect(value: unknown, methods = new Map<string, Method>()): Map<string, Method> {
	if (!value || typeof value !== "object") return methods;
	const main = (value as { main?: Method }).main;
	if (main?.nsid && (main.type === "query" || main.type === "procedure")) methods.set(main.nsid, main);
	else for (const child of Object.values(value)) collect(child, methods);
	return methods;
}

const methods = collect(com);

function validatePayload(payload: Payload, value: unknown): void {
	if (!payload.schema) return;
	const result = payload.schema.safeParse(jsonToLex(value as never, { strict: true }));
	if (!result.success) throw result.reason;
}

export function validateXrpcRequest(nsid: string, request: Request, params: URLSearchParams): void {
	const method = methods.get(nsid);
	if (!method) return;
	method.parameters.fromURLSearchParams(params);
	if (method.type !== "procedure" || !method.input.encoding) return;
	const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
	if (!method.input.matchesEncoding(contentType)) throw new TypeError(`Expected ${method.input.encoding} request body`);
}

export function validateXrpcBody(nsid: string, value: unknown): void {
	const method = methods.get(nsid);
	if (method?.type === "procedure") validatePayload(method.input, value);
}

export function validateXrpcOutput(nsid: string, value: unknown, response: Response): void {
	const method = methods.get(nsid);
	if (!method || response.status >= 400) return;
	const contentType = response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
	if (!method.output.matchesEncoding(contentType)) throw new TypeError(`XRPC ${nsid} returned ${contentType ?? "no content"}; expected ${method.output.encoding ?? "no content"}`);
	if (value instanceof Response) {
		if (method.output.schema) throw new TypeError(`XRPC ${nsid} returned an unvalidated JSON Response`);
	} else validatePayload(method.output, value);
}

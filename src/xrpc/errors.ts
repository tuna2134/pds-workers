export class XrpcError extends Error {
	constructor(readonly status: number, readonly error: string, message?: string) { super(message); }
}

export function xrpcErrorResponse(error: unknown, requestId: string): Response {
	const known = error instanceof XrpcError ? error : new XrpcError(500, "InternalServerError", "Internal server error");
	const message = known.status >= 500 ? "Internal server error" : known.message;
	return Response.json({ error: known.error, ...(message ? { message } : {}) }, {
		status: known.status,
		headers: { "x-request-id": requestId, ...(known.status === 401 ? { "www-authenticate": "Bearer" } : {}) },
	});
}

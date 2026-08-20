export async function readBody(request: Pick<Request, "headers" | "body">, maximum: number): Promise<Uint8Array> {
	const declared = request.headers.get("content-length");
	if (declared !== null) {
		const length = Number(declared);
		if (!Number.isSafeInteger(length) || length < 0) throw new TypeError("Invalid Content-Length");
		if (length > maximum) throw new RangeError("Request body exceeds limit");
	}
	if (!request.body) return new Uint8Array();
	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > maximum) throw new RangeError("Request body exceeds limit");
			chunks.push(value);
		}
	} finally { reader.releaseLock(); }
	if (declared !== null && total !== Number(declared)) throw new TypeError("Content-Length does not match body");
	const result = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
	return result;
}

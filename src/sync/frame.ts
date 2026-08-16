import { encodeDagCbor } from "../repo/dag-cbor";

export function streamFrame(type: string, payload: object): Uint8Array {
	const header = encodeDagCbor({ op: 1, t: type });
	const body = encodeDagCbor(payload);
	const frame = new Uint8Array(header.length + body.length);
	frame.set(header);
	frame.set(body, header.length);
	return frame;
}

export function streamError(error: string, message?: string): Uint8Array {
	const header = encodeDagCbor({ op: -1 });
	const body = encodeDagCbor({ error, ...(message ? { message } : {}) });
	const frame = new Uint8Array(header.length + body.length);
	frame.set(header);
	frame.set(body, header.length);
	return frame;
}

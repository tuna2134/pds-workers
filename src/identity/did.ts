import { isValidDid } from "@atproto/syntax";
import { didDocumentValidator, didWebToUrl, isDidPlc, isAtprotoDidWeb, type AtprotoDidDocument } from "@atproto/did";
import { publicFetch } from "../utils/public-fetch";

export type DidDocument = AtprotoDidDocument;

export function validDid(value: string): boolean {
	return isValidDid(value);
}

export interface DidProvider {
	resolve(did: string): Promise<DidDocument>;
}

async function document(url: string, did: string, remote = false): Promise<DidDocument> {
	const response = await (remote ? publicFetch : fetch)(new URL(url), { headers: { accept: "application/did+ld+json, application/json" }, redirect: "manual", signal: AbortSignal.timeout(10_000) });
	if (!response.ok) throw new Error("DidNotFound");
	const length = Number(response.headers.get("content-length"));
	if (Number.isFinite(length) && length > 100_000) throw new Error("InvalidDidDocument");
	const bytes = new Uint8Array(await response.arrayBuffer());
	if (bytes.length > 100_000) throw new Error("InvalidDidDocument");
	const value = didDocumentValidator.parse(JSON.parse(new TextDecoder().decode(bytes))) as DidDocument;
	if (value.id !== did) throw new Error("InvalidDidDocument");
	return value;
}

export class PlcDidProvider implements DidProvider {
	resolve(did: string) {
		if (!isDidPlc(did)) return Promise.reject(new Error("UnsupportedDid"));
		return document(`https://plc.directory/${did}`, did);
	}
}

export class WebDidProvider implements DidProvider {
	resolve(did: string) {
		if (!isAtprotoDidWeb(did)) return Promise.reject(new Error("UnsupportedDid"));
		return document(new URL("/.well-known/did.json", didWebToUrl(did)).href, did, true);
	}
}

export function didProvider(did: string): DidProvider {
	if (did.startsWith("did:plc:")) return new PlcDidProvider();
	if (did.startsWith("did:web:")) return new WebDidProvider();
	throw new Error("UnsupportedDid");
}

export async function resolveService(reference: string): Promise<URL> {
	const separator = reference.indexOf("#");
	if (separator < 1 || separator === reference.length - 1) throw new TypeError("Service DID reference requires a fragment");
	const did = reference.slice(0, separator);
	const fragment = reference.slice(separator);
	const resolved = await didProvider(did).resolve(did);
	const service = resolved.service?.find((item) => (item.id === fragment || item.id === reference) && typeof item.serviceEndpoint === "string");
	if (!service || typeof service.serviceEndpoint !== "string") throw new TypeError("Service endpoint not found");
	const endpoint = new URL(service.serviceEndpoint);
	if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.pathname !== "/" || endpoint.search || endpoint.hash || /^(localhost|\d+(\.\d+){3}|\[.*\])$/.test(endpoint.hostname)) throw new TypeError("Invalid service endpoint");
	return endpoint;
}

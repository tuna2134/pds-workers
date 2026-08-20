import * as cbor from "@atproto/lex-cbor";
import { CID } from "multiformats/cid";

export const encodeDagCbor = (value: unknown) => cbor.encode(value as Parameters<typeof cbor.encode>[0]);
export const decodeDagCbor = <T = unknown>(bytes: Uint8Array) => cbor.decode(bytes) as T;

export function jsonToIpld(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(jsonToIpld);
	if (!value || typeof value !== "object") return value;
	const object = value as Record<string, unknown>;
	if (typeof object.$link === "string" && Object.keys(object).length === 1) return CID.parse(object.$link);
	if (typeof object.$bytes === "string" && Object.keys(object).length === 1) return Uint8Array.from(atob(object.$bytes), (character) => character.charCodeAt(0));
	return Object.fromEntries(Object.entries(object).map(([key, child]) => [key, jsonToIpld(child)]));
}

export function ipldToJson(value: unknown): unknown {
	if (CID.asCID(value)) return { $link: CID.asCID(value)!.toString() };
	if (value instanceof Uint8Array) {
		let binary = "";
		for (const byte of value) binary += String.fromCharCode(byte);
		return { $bytes: btoa(binary) };
	}
	if (Array.isArray(value)) return value.map(ipldToJson);
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, ipldToJson(child)]));
}

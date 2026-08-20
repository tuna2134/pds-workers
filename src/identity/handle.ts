import { didProvider, validDid } from "./did";
import { isValidHandle, normalizeAndEnsureValidHandle } from "@atproto/syntax";
import { publicFetch } from "../utils/public-fetch";
import { readBody } from "../utils/body";

export function normalizeHandle(value: string): string {
	try { return normalizeAndEnsureValidHandle(value); }
	catch { throw new TypeError("Invalid handle"); }
}

function dnsDids(answer: unknown): string[] {
	if (!Array.isArray(answer)) return [];
	return [...new Set(answer.flatMap((item) => {
		if (!item || typeof item !== "object" || !("data" in item) || typeof item.data !== "string") return [];
		const text = item.data.replace(/^"|"$/g, "").replaceAll('" "', "");
		return text.startsWith("did=") && validDid(text.slice(4)) ? [text.slice(4)] : [];
	}))];
}

async function resolveDns(handle: string): Promise<string | undefined> {
	const url = new URL("https://cloudflare-dns.com/dns-query");
	url.searchParams.set("name", `_atproto.${handle}`);
	url.searchParams.set("type", "TXT");
	const response = await fetch(url, { headers: { accept: "application/dns-json" } });
	if (!response.ok) return;
	const dids = dnsDids((JSON.parse(new TextDecoder().decode(await readBody(response, 64_000))) as { Answer?: unknown }).Answer);
	return dids.length === 1 ? dids[0] : undefined;
}

async function resolveHttps(handle: string): Promise<string | undefined> {
	let url = new URL(`https://${handle}/.well-known/atproto-did`);
	for (let redirects = 0; redirects <= 5; redirects++) {
		const response = await publicFetch(url, { headers: { accept: "text/plain" }, redirect: "manual", signal: AbortSignal.timeout(10_000) });
		if (response.status >= 300 && response.status < 400) {
			const location = response.headers.get("location");
			if (!location) return;
			url = new URL(location, url);
			if (url.protocol !== "https:" || !isValidHandle(url.hostname)) return;
			continue;
		}
		if (!response.ok) return;
		const did = new TextDecoder().decode(await readBody(response, 8_192)).trim();
		return validDid(did) ? did : undefined;
	}
}

export async function resolveHandleMapping(handleInput: string): Promise<string> {
	const handle = normalizeHandle(handleInput);
	const [dns, https] = await Promise.allSettled([resolveDns(handle), resolveHttps(handle)]);
	const did = dns.status === "fulfilled" && dns.value || https.status === "fulfilled" && https.value;
	if (!did) throw new Error("HandleNotFound");
	return did;
}

export async function resolveHandle(handleInput: string): Promise<string> {
	const handle = normalizeHandle(handleInput);
	const did = await resolveHandleMapping(handle);
	const doc = await didProvider(did).resolve(did);
	if (!Array.isArray(doc.alsoKnownAs) || !doc.alsoKnownAs.includes(`at://${handle}`)) throw new Error("HandleNotFound");
	return did;
}

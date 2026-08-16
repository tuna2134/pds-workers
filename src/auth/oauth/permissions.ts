import { IncludeScope, type LexiconPermissionSet } from "@atproto/oauth-scopes";
import { NSID } from "@atproto/syntax";
import { didProvider, type DidDocument } from "../../identity/did";
import { extractPdsUrl } from "@atproto/did";
import { publicFetch } from "../../utils/public-fetch";

const MAX_LEXICON_BYTES = 100_000;

function txtDids(answer: unknown): string[] {
	if (!Array.isArray(answer)) return [];
	return [...new Set(answer.flatMap((item) => {
		if (!item || typeof item !== "object" || !("data" in item) || typeof item.data !== "string") return [];
		const text = item.data.replace(/^"|"$/g, "").replaceAll('" "', "");
		return text.startsWith("did=did:") ? [text.slice(4)] : [];
	}))];
}

function pdsEndpoint(document: DidDocument): URL {
	const url = extractPdsUrl(document);
	if (url.protocol !== "https:" || url.username || url.password || url.hash || /^(localhost|\d+(\.\d+){3}|\[.*\])$/.test(url.hostname)) throw new TypeError("Unsafe Lexicon PDS URL");
	return url;
}

async function json(url: URL, remote = true): Promise<unknown> {
	const response = await (remote ? publicFetch : fetch)(url, { headers: { accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(10_000) });
	const length = Number(response.headers.get("content-length"));
	if (!response.ok || !response.headers.get("content-type")?.toLowerCase().startsWith("application/json") || (Number.isFinite(length) && length > MAX_LEXICON_BYTES)) throw new TypeError("Unable to resolve permission set");
	const bytes = new Uint8Array(await response.arrayBuffer());
	if (bytes.length > MAX_LEXICON_BYTES) throw new TypeError("Permission set response too large");
	return JSON.parse(new TextDecoder().decode(bytes));
}

async function resolvePermissionSet(nsid: string): Promise<LexiconPermissionSet> {
	const authority = NSID.parse(nsid).authority;
	const dns = new URL("https://cloudflare-dns.com/dns-query");
	dns.searchParams.set("name", `_lexicon.${authority}`);
	dns.searchParams.set("type", "TXT");
	const dnsResult = await json(dns, false) as { Answer?: unknown };
	const dids = txtDids(dnsResult.Answer);
	if (dids.length !== 1) throw new TypeError("Lexicon authority DNS is invalid");
	const endpoint = pdsEndpoint(await didProvider(dids[0]).resolve(dids[0]));
	const record = new URL("/xrpc/com.atproto.repo.getRecord", endpoint);
	record.searchParams.set("repo", dids[0]);
	record.searchParams.set("collection", "com.atproto.lexicon.schema");
	record.searchParams.set("rkey", nsid);
	const result = await json(record) as { value?: unknown };
	const value = result.value;
	if (!value || typeof value !== "object" || !("$type" in value) || value.$type !== "com.atproto.lexicon.schema" || !("id" in value) || value.id !== nsid || !("lexicon" in value) || value.lexicon !== 1 || !("defs" in value) || !value.defs || typeof value.defs !== "object" || !("main" in value.defs)) throw new TypeError("Invalid permission-set Lexicon");
	const permissionSet = value.defs.main;
	if (!permissionSet || typeof permissionSet !== "object" || !("type" in permissionSet) || permissionSet.type !== "permission-set" || !("permissions" in permissionSet) || !Array.isArray(permissionSet.permissions)) throw new TypeError("Lexicon is not a permission set");
	return permissionSet as LexiconPermissionSet;
}

export async function expandPermissionScopes(scopes: string[]): Promise<string> {
	const expanded = await Promise.all(scopes.map(async (scope) => {
		const include = IncludeScope.fromString(scope);
		return include ? include.toScopes(await resolvePermissionSet(include.nsid)) : [scope];
	}));
	return [...new Set(expanded.flat())].join(" ");
}

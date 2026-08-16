import { BlockList, isIP } from "node:net";

const DNS = "https://cloudflare-dns.com/dns-query";

const blocked4 = new BlockList();
const blocked6 = new BlockList();
for (const [address, prefix] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]] as const) blocked4.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [["::", 128], ["::1", 128], ["::ffff:0:0", 96], ["64:ff9b:1::", 48], ["100::", 64], ["2001::", 32], ["2001:2::", 48], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20], ["5f00::", 16], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8]] as const) blocked6.addSubnet(address, prefix, "ipv6");

function isPublicIp(value: string): boolean {
	const version = isIP(value);
	return version !== 0 && !(version === 4 ? blocked4.check(value, "ipv4") : blocked6.check(value, "ipv6"));
}

async function addresses(hostname: string, type: "A" | "AAAA"): Promise<string[]> {
	const url = new URL(DNS);
	url.searchParams.set("name", hostname);
	url.searchParams.set("type", type);
	const response = await fetch(url, { headers: { accept: "application/dns-json" }, redirect: "manual", signal: AbortSignal.timeout(5_000) });
	if (!response.ok) throw new TypeError("Unable to resolve remote host");
	const body = await response.arrayBuffer();
	if (body.byteLength > 64_000) throw new TypeError("DNS response too large");
	const answer = (JSON.parse(new TextDecoder().decode(body)) as { Answer?: { type?: number; data?: string }[] }).Answer ?? [];
	const code = type === "A" ? 1 : 28;
	return answer.filter((item) => item.type === code && typeof item.data === "string").map((item) => item.data!);
}

export async function assertPublicHost(url: URL): Promise<void> {
	if (url.protocol !== "https:" || url.username || url.password || url.hash || url.port || isIP(url.hostname) || url.hostname === "localhost") throw new TypeError("Unsafe remote URL");
	const resolved = (await Promise.all([addresses(url.hostname, "A"), addresses(url.hostname, "AAAA")])).flat();
	if (!resolved.length || resolved.some((address) => !isPublicIp(address))) throw new TypeError("Remote host is not public");
}

export async function publicFetch(url: URL, init?: RequestInit): Promise<Response> {
	await assertPublicHost(url);
	return fetch(url, init);
}

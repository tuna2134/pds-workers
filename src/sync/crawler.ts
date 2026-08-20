export async function notifyCrawlers(config: string, pdsUrl: string): Promise<void> {
	const crawlers = JSON.parse(config) as unknown;
	if (!Array.isArray(crawlers) || crawlers.some((value) => typeof value !== "string")) throw new TypeError("CRAWLERS must be a JSON string array");
	const hostname = new URL(pdsUrl).host;
	await Promise.all(crawlers.map(async (crawler) => {
		const endpoint = new URL("/xrpc/com.atproto.sync.requestCrawl", crawler);
		if (endpoint.protocol !== "https:") throw new TypeError("Crawler URL must use HTTPS");
		const response = await fetch(endpoint, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ hostname }),
			signal: AbortSignal.timeout(5_000),
		});
		if (!response.ok) throw new Error(`Crawler rejected request (${response.status})`);
	}));
}

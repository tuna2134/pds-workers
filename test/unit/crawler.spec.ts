import { afterEach, describe, expect, it, vi } from "vitest";
import { notifyCrawlers } from "../../src/sync/crawler";

describe("crawler notifications", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("requests each configured relay with the PDS hostname", async () => {
		const fetch = vi.fn(async () => new Response(null, { status: 200 }));
		vi.stubGlobal("fetch", fetch);
		await notifyCrawlers('["https://relay.example"]', "https://pds.example.com");
		expect(fetch).toHaveBeenCalledWith(new URL("https://relay.example/xrpc/com.atproto.sync.requestCrawl"), expect.objectContaining({ method: "POST", body: '{"hostname":"pds.example.com"}' }));
	});
});

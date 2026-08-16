import { afterEach, describe, expect, it, vi } from "vitest";
import { normalizeHandle, resolveHandle } from "../../src/identity/handle";

afterEach(() => vi.unstubAllGlobals());

describe("identity", () => {
	it("validates and normalizes handles", () => {
		expect(normalizeHandle("Alice.Example.COM")).toBe("alice.example.com");
		expect(() => normalizeHandle("localhost")).toThrow("Invalid handle");
	});

	it("requires a bidirectional handle claim and prefers DNS", async () => {
		vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
			const url = new URL(String(input));
			if (url.hostname === "cloudflare-dns.com" && url.searchParams.get("type") === "A") return Response.json({ Answer: [{ type: 1, data: "93.184.216.34" }] });
			if (url.hostname === "cloudflare-dns.com" && url.searchParams.get("type") === "AAAA") return Response.json({ Answer: [] });
			if (url.hostname === "cloudflare-dns.com") return Response.json({ Answer: [{ data: '"did=did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"' }] });
			if (url.pathname.includes("atproto-did")) return new Response("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
			return Response.json({ id: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", alsoKnownAs: ["at://alice.example.com"] });
		}));
		expect(await resolveHandle("Alice.Example.com")).toBe("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
	});
});

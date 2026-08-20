import { describe, expect, it } from "vitest";
import { validateXrpcBody, validateXrpcOutput, validateXrpcRequest } from "../../src/lexicon/xrpc";
import { XrpcError, xrpcErrorResponse } from "../../src/xrpc/errors";

describe("official XRPC Lexicon validation", () => {
	it("validates parameters and JSON bodies", () => {
		expect(() => validateXrpcRequest("com.atproto.sync.getRepo", new Request("https://pds.test/xrpc/com.atproto.sync.getRepo?did=not-a-did"), new URLSearchParams({ did: "not-a-did" }))).toThrow();
		expect(() => validateXrpcBody("com.atproto.repo.createRecord", { repo: "did:plc:abcdefghijklmnopqrstuvwxyz", collection: "app.bsky.feed.post" })).toThrow();
		expect(() => validateXrpcBody("com.atproto.repo.createRecord", { repo: "did:plc:abcdefghijklmnopqrstuvwxyz", collection: "app.bsky.feed.post", record: { $type: "app.bsky.feed.post" } })).not.toThrow();
		expect(() => validateXrpcOutput("com.atproto.repo.createRecord", { uri: "not-an-at-uri", cid: "not-a-cid" }, Response.json({}))).toThrow();
		expect(() => validateXrpcRequest("app.bsky.feed.getAuthorFeed", new Request("https://pds.test/xrpc/app.bsky.feed.getAuthorFeed?actor=bad"), new URLSearchParams({ actor: "bad" }))).toThrow();
		expect(() => validateXrpcRequest("app.bsky.actor.getProfile", new Request("https://pds.test/xrpc/app.bsky.actor.getProfile"), new URLSearchParams())).toThrow();
	});
});

describe("XRPC errors", () => {
	it("never exposes internal 5xx details", async () => {
		const response = xrpcErrorResponse(new XrpcError(502, "UpstreamFailure", "Failed query: select password_hash secret"), "request-id");
		expect(response.status).toBe(502);
		expect(response.headers.get("x-request-id")).toBe("request-id");
		expect(await response.json()).toEqual({ error: "UpstreamFailure", message: "Internal server error" });
	});
});

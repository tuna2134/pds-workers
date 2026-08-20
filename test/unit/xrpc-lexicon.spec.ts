import { describe, expect, it } from "vitest";
import { validateXrpcBody, validateXrpcOutput, validateXrpcRequest } from "../../src/lexicon/xrpc";

describe("official XRPC Lexicon validation", () => {
	it("validates parameters and JSON bodies", () => {
		expect(() => validateXrpcRequest("com.atproto.sync.getRepo", new Request("https://pds.test/xrpc/com.atproto.sync.getRepo?did=not-a-did"), new URLSearchParams({ did: "not-a-did" }))).toThrow();
		expect(() => validateXrpcBody("com.atproto.repo.createRecord", { repo: "did:plc:abcdefghijklmnopqrstuvwxyz", collection: "app.bsky.feed.post" })).toThrow();
		expect(() => validateXrpcBody("com.atproto.repo.createRecord", { repo: "did:plc:abcdefghijklmnopqrstuvwxyz", collection: "app.bsky.feed.post", record: { $type: "app.bsky.feed.post" } })).not.toThrow();
		expect(() => validateXrpcOutput("com.atproto.repo.createRecord", { uri: "not-an-at-uri", cid: "not-a-cid" }, Response.json({}))).toThrow();
		expect(() => validateXrpcRequest("app.bsky.feed.getAuthorFeed", new Request("https://pds.test/xrpc/app.bsky.feed.getAuthorFeed?actor=bad"), new URLSearchParams({ actor: "bad" }))).toThrow();
	});
});

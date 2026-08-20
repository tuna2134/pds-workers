import { describe, expect, it } from "vitest";
import { validateRecord } from "../../src/lexicon/validator";
import { TidClock } from "../../src/repo/tid";

describe("official Lexicon validation", () => {
	it("validates known records and preserves unknown-schema semantics", () => {
		const tid = new TidClock().next();
		expect(validateRecord("app.bsky.feed.post", tid, { $type: "app.bsky.feed.post", text: "hello", createdAt: "2026-08-16T00:00:00.000Z" })).toBe("valid");
		expect(validateRecord("app.bsky.feed.threadgate", tid, { $type: "app.bsky.feed.threadgate", post: `at://did:plc:abcdefghijklmnopqrstuvwxyz/app.bsky.feed.post/${tid}`, createdAt: "2026-08-16T00:00:00.000Z" })).toBe("valid");
		expect(validateRecord("app.bsky.feed.postgate", tid, { $type: "app.bsky.feed.postgate", post: `at://did:plc:abcdefghijklmnopqrstuvwxyz/app.bsky.feed.post/${tid}`, createdAt: "2026-08-16T00:00:00.000Z" })).toBe("valid");
		expect(validateRecord("app.bsky.actor.status", "self", { $type: "app.bsky.actor.status", status: "app.bsky.actor.status#live", createdAt: "2026-08-16T00:00:00.000Z" })).toBe("valid");
		expect(() => validateRecord("app.bsky.actor.status", tid, { $type: "app.bsky.actor.status", status: "app.bsky.actor.status#live", createdAt: "2026-08-16T00:00:00.000Z" })).toThrow();
		expect(() => validateRecord("app.bsky.feed.post", tid, { $type: "app.bsky.feed.post", text: "hello" })).toThrow();
		expect(validateRecord("example.test.record", "key", { $type: "example.test.record" })).toBe("unknown");
		expect(() => validateRecord("example.test.record", "key", { $type: "example.test.record" }, true)).toThrow();
		expect(validateRecord("app.bsky.feed.post", "key", { malformed: true }, false)).toBe("unknown");
		expect(() => validateRecord("example.test.record", "key", { $type: "example.test.record", blob: { $type: "blob", ref: { $link: "not-a-cid" }, mimeType: "image/png", size: 1 } }, false)).toThrow();
	});
});

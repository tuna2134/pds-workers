import { describe, expect, it } from "vitest";
import { readBody } from "../../src/utils/body";

describe("bounded request bodies", () => {
	it("enforces the limit even without Content-Length", async () => {
		await expect(readBody(new Request("https://example.com", { method: "POST", body: "12345" }), 4)).rejects.toThrow("exceeds limit");
	});

	it("rejects a mismatched declared length", async () => {
		await expect(readBody(new Request("https://example.com", { method: "POST", headers: { "content-length": "4" }, body: "12345" }), 10)).rejects.toThrow("does not match");
	});
});

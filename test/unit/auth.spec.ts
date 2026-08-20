import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword, verifyPasswordOrDummy } from "../../src/auth/password";
import { signJwt, verifyJwt } from "../../src/crypto/jwt";
import { verifyServiceJwt } from "../../src/crypto/service-jwt";

describe("authentication primitives", () => {
	it("hashes passwords and domain-separates session tokens", async () => {
		const hash = await hashPassword("correct horse battery staple");
		expect(hash).toMatch(/^pbkdf2-sha256\$/);
		expect(await verifyPassword("correct horse battery staple", hash)).toBe(true);
		expect(await verifyPassword("wrong password", hash)).toBe(false);
		expect(await verifyPasswordOrDummy("irrelevant password")).toBe(false);
		const secret = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
		const claims = { sub: "did:plc:test", aud: "did:web:pds.test", scope: "com.atproto.access", iat: 1, exp: 4_102_444_800, jti: "test" };
		const access = await signJwt(claims, "at+jwt", secret);
		expect(await verifyJwt(access, "at+jwt", secret)).toMatchObject(claims);
		expect(await verifyJwt(access, "refresh+jwt", secret)).toBeNull();
		const now = Math.floor(Date.now() / 1000);
		const expired = await signJwt({ ...claims, iat: now - 120, exp: now - 60 }, "refresh+jwt", secret);
		expect(await verifyJwt(expired, "refresh+jwt", secret)).toBeNull();
		expect(await verifyJwt(expired, "refresh+jwt", secret, true)).toMatchObject({ exp: now - 60 });
		const malformed = await signJwt({ ...claims, scope: 1 } as unknown as typeof claims, "at+jwt", secret);
		expect(await verifyJwt(malformed, "at+jwt", secret)).toBeNull();
		await expect(signJwt(claims, "at+jwt", "c2hvcnQ")).rejects.toThrow("at least 32 bytes");
	});

	it("rejects unsafe service JWT timestamps", async () => {
		const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
		const header = encode({ alg: "ES256K", typ: "JWT", kid: "#atproto" });
		const payload = encode({ iss: "did:plc:issuer", aud: "did:web:pds.test", lxm: "com.atproto.server.createAccount", iat: Number.MAX_SAFE_INTEGER + 1, exp: Number.MAX_SAFE_INTEGER + 2, jti: "unsafe" });
		expect(await verifyServiceJwt(`${header}.${payload}.AA`, "did:plc:issuer", "did:web:pds.test", "com.atproto.server.createAccount")).toBe(false);
	});
});

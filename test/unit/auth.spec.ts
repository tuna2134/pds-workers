import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword, verifyPasswordOrDummy } from "../../src/auth/password";
import { signJwt, verifyJwt } from "../../src/crypto/jwt";

describe("authentication primitives", () => {
	it("hashes passwords and domain-separates session tokens", async () => {
		const hash = await hashPassword("correct horse battery staple");
		expect(hash).toMatch(/^(argon2id\$v=19|pbkdf2-sha256\$)/);
		expect(await verifyPassword("correct horse battery staple", hash)).toBe(true);
		expect(await verifyPassword("wrong password", hash)).toBe(false);
		expect(await verifyPasswordOrDummy("irrelevant password")).toBe(false);
		const secret = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
		const claims = { sub: "did:plc:test", aud: "did:web:pds.test", scope: "com.atproto.access", iat: 1, exp: 4_102_444_800, jti: "test" };
		const access = await signJwt(claims, "at+jwt", secret);
		expect(await verifyJwt(access, "at+jwt", secret)).toMatchObject(claims);
		expect(await verifyJwt(access, "refresh+jwt", secret)).toBeNull();
	});
});

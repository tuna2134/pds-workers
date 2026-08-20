import { applyD1Migrations, env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { AccountRepository } from "../src/db/accounts";
import { d1 } from "../src/db/d1";

beforeEach(() => applyD1Migrations(env.DB, env.TEST_D1_MIGRATIONS));

describe("PDS admin XRPC", () => {
	it("protects and queries account metadata without credential fields", async () => {
		const accounts = new AccountRepository(d1(env.DB));
		const first = await accounts.create({ did: "did:plc:adminone", handle: "admin-one.localhost", email: "one@example.com", passwordHash: "must-not-leak" });
		const second = await accounts.create({ did: "did:plc:admintwo", handle: "admin-two.localhost", email: "two@example.com", passwordHash: "must-not-leak" });
		const endpoint = `https://example.com/xrpc/com.atproto.admin.getAccountInfo?did=${first.did}`;
		expect((await SELF.fetch(endpoint)).status).toBe(401);
		const headers = { authorization: "Bearer a-secure-admin-test-secret-value" };
		const info = await SELF.fetch(endpoint, { headers });
		expect(info.status).toBe(200);
		const body = await info.json<Record<string, unknown>>();
		expect(body).toMatchObject({ did: first.did, handle: first.handle, email: first.email, indexedAt: expect.any(String) });
		expect(JSON.stringify(body)).not.toContain("must-not-leak");
		const infos = await SELF.fetch(`https://example.com/xrpc/com.atproto.admin.getAccountInfos?dids=${first.did}&dids=${second.did}`, { headers });
		expect(await infos.json()).toMatchObject({ infos: [{ did: first.did }, { did: second.did }] });
		const searched = await SELF.fetch("https://example.com/xrpc/com.atproto.admin.searchAccounts?email=two%40example.com&limit=1", { headers });
		expect(await searched.json()).toMatchObject({ accounts: [{ did: second.did }] });
	});

	it("protects PITR scheduling and requires an exact confirmation bookmark", async () => {
		const endpoint = "https://example.com/admin/pitr?kind=account&did=did%3Aplc%3Aadminone";
		expect((await SELF.fetch(endpoint)).status).toBe(401);
		const response = await SELF.fetch(endpoint, {
			method: "POST",
			headers: { authorization: "Bearer a-secure-admin-test-secret-value", "content-type": "application/json", "x-confirm-restore": "different" },
			body: JSON.stringify({ bookmark: "0000007b-0000b26e-00001538-0c3e87bb37b3db5cc52eedb93cd3b96b" }),
		});
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: "InvalidRequest" });
		const headers = { authorization: "Bearer a-secure-admin-test-secret-value", "content-type": "application/json" };
		expect((await SELF.fetch(endpoint, { method: "POST", headers, body: "{" })).status).toBe(400);
		expect((await SELF.fetch(endpoint, { method: "POST", headers, body: "x".repeat(2_049) })).status).toBe(413);
	});
});

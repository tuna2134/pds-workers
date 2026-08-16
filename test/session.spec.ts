import { applyD1Migrations, env, fetchMock, SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashPassword } from "../src/auth/password";
import { AccountRepository } from "../src/db/accounts";
import { d1 } from "../src/db/d1";
import { tokenHash } from "../src/crypto/jwt";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { auditLogs } from "../src/db/schema/d1";
import { formatDidKey, verifySignature } from "@atproto/crypto";
import { encodeBlock } from "../src/repo/cid";
import { buildRepoCommit } from "../src/repo/update";
import { formatTid } from "../src/repo/tid";
import * as dagCbor from "@ipld/dag-cbor";
import { EmailTokenRepository } from "../src/auth/email-token";

function b64(value: object | Uint8Array) { return Buffer.from(value instanceof Uint8Array ? value : new TextEncoder().encode(JSON.stringify(value))).toString("base64url"); }

async function dpop(key: CryptoKeyPair, jwk: JsonWebKey, method: string, url: string, nonce: string, jti = crypto.randomUUID(), accessToken?: string) {
	const header = b64({ typ: "dpop+jwt", alg: "ES256", jwk });
	const payload = b64({ jti, htm: method, htu: url, iat: Math.floor(Date.now() / 1000), nonce, ...(accessToken ? { ath: await tokenHash(accessToken) } : {}) });
	const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(`${header}.${payload}`)));
	return `${header}.${payload}.${b64(signature)}`;
}

async function clientAssertion(key: CryptoKeyPair, clientId: string, kid: string) {
	const now = Math.floor(Date.now() / 1000);
	const header = b64({ typ: "JWT", alg: "ES256", kid });
	const payload = b64({ iss: clientId, sub: clientId, aud: "https://pds.example.com", iat: now, exp: now + 60, jti: crypto.randomUUID() });
	const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(`${header}.${payload}`)));
	return `${header}.${payload}.${b64(signature)}`;
}

function serviceJwt(key: Uint8Array, did: string) {
	const now = Math.floor(Date.now() / 1000);
	const header = b64({ alg: "ES256K", typ: "JWT", kid: "#atproto" });
	const payload = b64({ iss: did, aud: "did:web:localhost", lxm: "com.atproto.server.createAccount", iat: now, exp: now + 60, jti: crypto.randomUUID() });
	const signature = secp256k1.sign(new TextEncoder().encode(`${header}.${payload}`), key, { prehash: true, format: "compact", lowS: true });
	return `${header}.${payload}.${b64(signature)}`;
}

beforeEach(() => applyD1Migrations(env.DB, env.TEST_D1_MIGRATIONS));
afterEach(() => fetchMock.deactivate());

describe("password sessions", () => {
	it("confirms email ownership and protects changes to a confirmed address", async () => {
		const did = "did:plc:emailconfirmation";
		const account = await new AccountRepository(d1(env.DB)).create({ did, handle: "email.localhost", email: "old@example.com", passwordHash: await hashPassword("a secure email password") });
		const login = await SELF.fetch("https://example.com/xrpc/com.atproto.server.createSession", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ identifier: account.handle, password: "a secure email password" }) });
		const loginBody = await login.json<{ accessJwt: string; emailConfirmed: boolean; emailAuthFactor: boolean }>();
		const { accessJwt } = loginBody;
		const auth = { authorization: `Bearer ${accessJwt}` };
		expect(loginBody).toMatchObject({ emailConfirmed: false, emailAuthFactor: false });
		expect((await SELF.fetch("https://example.com/xrpc/com.atproto.server.requestEmailConfirmation", { method: "POST", headers: auth })).status).toBe(200);
		const confirmToken = await new EmailTokenRepository(d1(env.DB)).create(account.id, "email-confirm");
		const confirmed = await SELF.fetch("https://example.com/xrpc/com.atproto.server.confirmEmail", { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify({ email: account.email, token: confirmToken }) });
		expect(confirmed.status, await confirmed.clone().text()).toBe(200);
		expect(await (await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: auth })).json()).toMatchObject({ email: account.email, emailConfirmed: true });
		expect(await (await SELF.fetch("https://example.com/xrpc/com.atproto.server.requestEmailUpdate", { method: "POST", headers: auth })).json()).toEqual({ tokenRequired: true });
		const newEmail = "new@example.com";
		const required = await SELF.fetch("https://example.com/xrpc/com.atproto.server.updateEmail", { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify({ email: newEmail }) });
		expect(await required.json()).toMatchObject({ error: "TokenRequired" });
		const updateToken = await new EmailTokenRepository(d1(env.DB)).create(account.id, "email-update");
		const updated = await SELF.fetch("https://example.com/xrpc/com.atproto.server.updateEmail", { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify({ email: newEmail, token: updateToken }) });
		expect(updated.status, await updated.clone().text()).toBe(200);
		expect(await (await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: auth })).json()).toMatchObject({ email: newEmail, emailConfirmed: false, emailAuthFactor: false });
	});

	it("resets a password without account enumeration and revokes existing sessions", async () => {
		const did = "did:plc:passwordresettest";
		const account = await new AccountRepository(d1(env.DB)).create({ did, handle: "reset.localhost", email: "reset@example.com", passwordHash: await hashPassword("the previous secure password") });
		const login = async (password: string) => SELF.fetch("https://example.com/xrpc/com.atproto.server.createSession", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ identifier: account.handle, password }) });
		const oldLogin = await login("the previous secure password");
		const { accessJwt } = await oldLogin.json<{ accessJwt: string }>();
		for (const email of [account.email, "missing@example.com"]) {
			const requested = await SELF.fetch("https://example.com/xrpc/com.atproto.server.requestPasswordReset", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email }) });
			expect(requested.status).toBe(200);
		}
		const token = await new EmailTokenRepository(d1(env.DB)).create(account.id, "password-reset");
		const reset = await SELF.fetch("https://example.com/xrpc/com.atproto.server.resetPassword", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "the replacement secure password" }) });
		expect(reset.status, await reset.clone().text()).toBe(200);
		expect((await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: { authorization: `Bearer ${accessJwt}` } })).status).toBe(401);
		expect((await login("the previous secure password")).status).toBe(401);
		expect((await login("the replacement secure password")).status).toBe(200);
		expect((await SELF.fetch("https://example.com/xrpc/com.atproto.server.resetPassword", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "another replacement password" }) })).status).toBe(400);
	});

	it("deletes account metadata, repository storage, blobs, and sessions after confirmation", async () => {
		const did = "did:plc:deleteaccounttest";
		const password = "a secure deletion password";
		const account = await new AccountRepository(d1(env.DB)).create({ did, handle: "delete.localhost", email: "delete@example.com", passwordHash: await hashPassword(password) });
		const accountRepo = env.ACCOUNT_REPO.getByName(did);
		await accountRepo.initialize(did);
		await accountRepo.applyWrites([{ action: "create", path: "app.bsky.feed.post/one", record: { $type: "app.bsky.feed.post", text: "delete me", createdAt: "2026-08-16T00:00:00.000Z" } }]);
		await env.BLOBS.put(`blobs/${did}/first`, "one");
		await env.BLOBS.put(`blobs/${did}/second`, "two");
		const login = await SELF.fetch("https://example.com/xrpc/com.atproto.server.createSession", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ identifier: account.handle, password }) });
		const { accessJwt } = await login.json<{ accessJwt: string }>();
		const requested = await SELF.fetch("https://example.com/xrpc/com.atproto.server.requestAccountDelete", { method: "POST", headers: { authorization: `Bearer ${accessJwt}` } });
		expect(requested.status, await requested.clone().text()).toBe(200);
		const token = await new EmailTokenRepository(d1(env.DB)).create(account.id, "account-delete");
		const invalid = await SELF.fetch("https://example.com/xrpc/com.atproto.server.deleteAccount", { method: "POST", headers: { authorization: `Bearer ${accessJwt}`, "content-type": "application/json" }, body: JSON.stringify({ did, password, token: "wrong" }) });
		expect(invalid.status).toBe(400);
		expect(await invalid.json()).toMatchObject({ error: "InvalidToken" });
		const deleted = await SELF.fetch("https://example.com/xrpc/com.atproto.server.deleteAccount", { method: "POST", headers: { authorization: `Bearer ${accessJwt}`, "content-type": "application/json" }, body: JSON.stringify({ did, password, token }) });
		expect(deleted.status, await deleted.clone().text()).toBe(200);
		expect(await new AccountRepository(d1(env.DB)).find(did)).toBeUndefined();
		expect((await env.BLOBS.list({ prefix: `blobs/${did}/` })).objects).toHaveLength(0);
		expect((await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getRepo?did=${did}`)).status).toBe(400);
		expect((await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: { authorization: `Bearer ${accessJwt}` } })).status).toBe(401);
	});

	it("imports an authenticated signed repository CAR", async () => {
		const did = "did:plc:cccccccccccccccccccccccc";
		const sourceKey = new Uint8Array(32).fill(21);
		const oldRotationKey = new Uint8Array(32).fill(23);
		const document = { id: did, alsoKnownAs: ["at://import.localhost"], verificationMethod: [{ id: `${did}#atproto`, type: "Multikey", controller: did, publicKeyMultibase: formatDidKey("ES256K", secp256k1.getPublicKey(sourceKey)).slice(8) }], service: [{ id: `${did}#atproto_pds`, type: "AtprotoPersonalDataServer", serviceEndpoint: "https://old.example.com" }] };
		fetchMock.activate();
		fetchMock.disableNetConnect();
		fetchMock.get("https://plc.directory").intercept({ method: "GET", path: `/${did}` }).reply(200, JSON.stringify(document), { headers: { "content-type": "application/json" } }).times(2);
		const created = await SELF.fetch("https://example.com/xrpc/com.atproto.server.createAccount", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${serviceJwt(sourceKey, did)}` }, body: JSON.stringify({ did, handle: "import.localhost", email: "import@example.com", password: "a secure import password" }) });
		expect(created.status, await created.clone().text()).toBe(200);
		const { accessJwt } = await created.json<{ accessJwt: string }>();
		const session = await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: { authorization: `Bearer ${accessJwt}` } });
		expect(await session.json()).toMatchObject({ active: false, status: "deactivated" });
		const preferences = [{ $type: "app.bsky.actor.defs#adultContentPref", enabled: true }];
		const putPreferences = await SELF.fetch("https://example.com/xrpc/app.bsky.actor.putPreferences", { method: "POST", headers: { authorization: `Bearer ${accessJwt}`, "content-type": "application/json" }, body: JSON.stringify({ preferences }) });
		expect(putPreferences.status, await putPreferences.clone().text()).toBe(200);
		const getPreferences = await SELF.fetch("https://example.com/xrpc/app.bsky.actor.getPreferences", { headers: { authorization: `Bearer ${accessJwt}` } });
		expect(await getPreferences.json()).toEqual({ preferences });
		const record = await encodeBlock({ $type: "app.bsky.feed.post", text: "migrated", createdAt: "2026-08-16T00:00:00.000Z" });
		const source = await buildRepoCommit({ did, privateKey: sourceKey, rev: formatTid(100n), entries: [["app.bsky.feed.post/imported", record]] });
		const imported = await SELF.fetch("https://example.com/xrpc/com.atproto.repo.importRepo", { method: "POST", headers: { authorization: `Bearer ${accessJwt}`, "content-type": "application/vnd.ipld.car", "content-length": String(source.diff.length) }, body: source.diff });
		expect(imported.status, await imported.clone().text()).toBe(200);
		expect(await env.ACCOUNT_REPO.getByName(did).getRecord("app.bsky.feed.post/imported")).toMatchObject({ value: { text: "migrated" } });
		expect((await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getRepo?did=${did}`)).status).toBe(400);
		const recommendedResponse = await SELF.fetch("https://example.com/xrpc/com.atproto.identity.getRecommendedDidCredentials", { headers: { authorization: `Bearer ${accessJwt}` } });
		expect(recommendedResponse.status).toBe(200);
		const recommended = await recommendedResponse.json<{ rotationKeys: string[]; verificationMethods: { atproto: string }; alsoKnownAs: string[]; services: { atproto_pds: { type: string; endpoint: string } } }>();
		const last = { type: "plc_operation", rotationKeys: [formatDidKey("ES256K", secp256k1.getPublicKey(oldRotationKey))], verificationMethods: { atproto: formatDidKey("ES256K", secp256k1.getPublicKey(sourceKey)) }, alsoKnownAs: ["at://import.localhost"], services: { atproto_pds: { type: "AtprotoPersonalDataServer", endpoint: "https://old.example.com" } }, prev: null, sig: "old" };
		const unsigned = { type: "plc_operation" as const, ...recommended, prev: (await encodeBlock(last)).cid.toString() };
		const operation = { ...unsigned, sig: b64(secp256k1.sign(dagCbor.encode(unsigned), oldRotationKey, { prehash: true, format: "compact", lowS: true })) };
		fetchMock.get("https://plc.directory").intercept({ method: "GET", path: `/${did}/data` }).reply(200, JSON.stringify({ did, ...last }));
		fetchMock.get("https://plc.directory").intercept({ method: "GET", path: `/${did}/log/last` }).reply(200, JSON.stringify(last));
		fetchMock.get("https://plc.directory").intercept({ method: "POST", path: `/${did}`, body: JSON.stringify(operation) }).reply(200, "");
		const submitted = await SELF.fetch("https://example.com/xrpc/com.atproto.identity.submitPlcOperation", { method: "POST", headers: { authorization: `Bearer ${accessJwt}`, "content-type": "application/json" }, body: JSON.stringify({ operation }) });
		expect(submitted.status, await submitted.clone().text()).toBe(200);
		const migratedDocument = { id: did, alsoKnownAs: recommended.alsoKnownAs, verificationMethod: [{ id: `${did}#atproto`, type: "Multikey", controller: did, publicKeyMultibase: recommended.verificationMethods.atproto.slice(8) }], service: [{ id: `${did}#atproto_pds`, type: "AtprotoPersonalDataServer", serviceEndpoint: recommended.services.atproto_pds.endpoint }] };
		fetchMock.get("https://plc.directory").intercept({ method: "GET", path: `/${did}` }).reply(200, JSON.stringify(migratedDocument), { headers: { "content-type": "application/json" } });
		const activated = await SELF.fetch("https://example.com/xrpc/com.atproto.server.activateAccount", { method: "POST", headers: { authorization: `Bearer ${accessJwt}` } });
		expect(activated.status, await activated.clone().text()).toBe(200);
		const activeSession = await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: { authorization: `Bearer ${accessJwt}` } });
		expect(await activeSession.json()).toMatchObject({ active: true, status: "active" });
		expect((await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getRepo?did=${did}`)).status).toBe(200);
		const deactivated = await SELF.fetch("https://example.com/xrpc/com.atproto.server.deactivateAccount", { method: "POST", headers: { authorization: `Bearer ${accessJwt}`, "content-type": "application/json" }, body: "{}" });
		expect(deactivated.status).toBe(200);
		expect((await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getRepo?did=${did}`)).status).toBe(400);
		fetchMock.assertNoPendingInterceptors();
	});

	it("creates a PLC account and initializes its signed repository", async () => {
		fetchMock.activate();
		fetchMock.disableNetConnect();
		fetchMock.get("https://plc.directory").intercept({ method: "POST", path: /^\/did:plc:[a-z2-7]{24}$/ }).reply(200, "");
		const response = await SELF.fetch("https://example.com/xrpc/com.atproto.server.createAccount", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ handle: "new.localhost", email: "new@example.com", password: "a secure account password" }) });
		expect(response.status).toBe(200);
		const account = await response.json<{ did: string; accessJwt: string }>();
		expect(account.did).toMatch(/^did:plc:[a-z2-7]{24}$/);
		expect((await env.ACCOUNT_REPO.getByName(account.did).describe()).did).toBe(account.did);
		expect(await d1(env.DB).select({ action: auditLogs.action, ipHash: auditLogs.ipHash, detail: auditLogs.detail }).from(auditLogs).get()).toMatchObject({ action: "account.created", ipHash: expect.any(String) });
		const authorization = { authorization: `Bearer ${account.accessJwt}` };
		const recommended = await (await SELF.fetch("https://example.com/xrpc/com.atproto.identity.getRecommendedDidCredentials", { headers: authorization })).json<{ rotationKeys: string[]; verificationMethods: { atproto: string }; alsoKnownAs: string[]; services: { atproto_pds: { type: "AtprotoPersonalDataServer"; endpoint: string } } }>();
		const last = { type: "plc_operation", ...recommended, prev: null, sig: "genesis" };
		const stored = await new AccountRepository(d1(env.DB)).find(account.did);
		await new AccountRepository(d1(env.DB)).confirmEmail(stored!.id);
		expect((await SELF.fetch("https://example.com/xrpc/com.atproto.identity.requestPlcOperationSignature", { method: "POST", headers: authorization })).status).toBe(200);
		const plcToken = await new EmailTokenRepository(d1(env.DB)).create(stored!.id, "plc-operation");
		fetchMock.get("https://plc.directory").intercept({ method: "GET", path: `/${account.did}/data` }).reply(200, JSON.stringify({ did: account.did, ...recommended }));
		fetchMock.get("https://plc.directory").intercept({ method: "GET", path: `/${account.did}/log/last` }).reply(200, JSON.stringify(last));
		const targetServices = { atproto_pds: { type: "AtprotoPersonalDataServer", endpoint: "https://new-pds.example.com" } };
		const signedResponse = await SELF.fetch("https://example.com/xrpc/com.atproto.identity.signPlcOperation", { method: "POST", headers: { ...authorization, "content-type": "application/json" }, body: JSON.stringify({ token: plcToken, services: targetServices }) });
		expect(signedResponse.status, await signedResponse.clone().text()).toBe(200);
		const { operation: signedOperation } = await signedResponse.json<{ operation: { sig: string; services: typeof targetServices } & Record<string, unknown> }>();
		const { sig, ...unsigned } = signedOperation;
		const signature = Uint8Array.from(atob(sig.replaceAll("-", "+").replaceAll("_", "/") + "=="), (value) => value.charCodeAt(0));
		expect(signedOperation.services).toEqual(targetServices);
		expect(await verifySignature(recommended.rotationKeys[0], dagCbor.encode(unsigned), signature)).toBe(true);
		expect((await SELF.fetch("https://example.com/xrpc/com.atproto.identity.signPlcOperation", { method: "POST", headers: { ...authorization, "content-type": "application/json" }, body: JSON.stringify({ token: plcToken, services: targetServices }) })).status).toBe(400);
		fetchMock.get("https://plc.directory").intercept({ method: "GET", path: `/${account.did}/data` }).reply(200, JSON.stringify({ did: account.did, ...recommended }));
		fetchMock.get("https://plc.directory").intercept({ method: "GET", path: `/${account.did}/log/last` }).reply(200, JSON.stringify(last));
		fetchMock.get("https://plc.directory").intercept({ method: "POST", path: `/${account.did}` }).reply(200, "");
		const renamed = await SELF.fetch("https://example.com/xrpc/com.atproto.identity.updateHandle", { method: "POST", headers: { ...authorization, "content-type": "application/json" }, body: JSON.stringify({ handle: "renamed.localhost" }) });
		expect(renamed.status, await renamed.clone().text()).toBe(200);
		expect(await (await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: authorization })).json()).toMatchObject({ handle: "renamed.localhost" });
		expect(await (await SELF.fetch("https://renamed.localhost/.well-known/atproto-did")).text()).toBe(account.did);
		fetchMock.assertNoPendingInterceptors();
	});

	it("completes PAR, browser authorization, and a DPoP-bound code exchange", async () => {
		const did = "did:plc:oauthaccount";
		await new AccountRepository(d1(env.DB)).create({ did, handle: "oauth.localhost", email: "oauth@example.com", passwordHash: await hashPassword("a secure oauth password") });
		await new AccountRepository(d1(env.DB)).create({ did: "did:plc:otheroauthaccount", handle: "other.localhost", email: "other@example.com", passwordHash: await hashPassword("another secure oauth password") });
		await env.ACCOUNT_REPO.getByName(did).initialize(did);
		const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
		const redirectUri = "http://127.0.0.1/callback";
		const requestedScope = "atproto repo:app.bsky.feed.post";
		const clientId = `http://localhost/?redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(requestedScope)}`;
		const verifier = "v".repeat(43);
		const body = new URLSearchParams({ client_id: clientId, response_type: "code", redirect_uri: redirectUri, scope: requestedScope, state: "client-state", code_challenge: await tokenHash(verifier), code_challenge_method: "S256", login_hint: "oauth.localhost" });
		const challenge = await SELF.fetch("https://example.com/oauth/par", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
		expect(challenge.status).toBe(400);
		const nonce = challenge.headers.get("dpop-nonce")!;
		const par = await SELF.fetch("https://example.com/oauth/par", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpop(pair, jwk, "POST", "https://pds.example.com/oauth/par", nonce) }, body });
		expect(par.status, await par.clone().text()).toBe(201);
		const { request_uri: requestUri } = await par.json<{ request_uri: string }>();
		const deniedRequest = new URLSearchParams(body);
		deniedRequest.set("state", "denied-state");
		deniedRequest.set("code_challenge", await tokenHash("d".repeat(43)));
		const deniedPar = await SELF.fetch("https://example.com/oauth/par", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpop(pair, jwk, "POST", "https://pds.example.com/oauth/par", par.headers.get("dpop-nonce")!) }, body: deniedRequest });
		const { request_uri: deniedUri } = await deniedPar.json<{ request_uri: string }>();
		const deniedPage = await SELF.fetch(`https://example.com/oauth/authorize?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(deniedUri)}`);
		const deniedCookie = deniedPage.headers.get("set-cookie")!;
		const deniedCsrf = /oauth_csrf=([^;]+)/.exec(deniedCookie)![1];
		const denial = new URLSearchParams({ request_uri: deniedUri, client_id: clientId, csrf: deniedCsrf, action: "deny" });
		const deniedRedirect = await SELF.fetch("https://example.com/oauth/authorize", { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", cookie: deniedCookie }, body: denial });
		const deniedCallback = new URL(deniedRedirect.headers.get("location")!);
		expect(Object.fromEntries(deniedCallback.searchParams)).toMatchObject({ error: "access_denied", state: "denied-state", iss: "https://pds.example.com" });
		expect(deniedRedirect.headers.get("set-cookie")).toContain("Max-Age=0");
		expect((await SELF.fetch("https://example.com/oauth/authorize", { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", cookie: deniedCookie }, body: denial })).status).toBe(400);
		const authorize = await SELF.fetch(`https://example.com/oauth/authorize?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(requestUri)}`);
		expect(authorize.status).toBe(200);
		const cookie = authorize.headers.get("set-cookie")!;
		const csrf = /oauth_csrf=([^;]+)/.exec(cookie)![1];
		const wrongAccount = await SELF.fetch("https://example.com/oauth/authorize", { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", cookie }, body: new URLSearchParams({ request_uri: requestUri, client_id: clientId, csrf, identifier: "other.localhost", password: "another secure oauth password", action: "approve" }) });
		expect(wrongAccount.status).toBe(401);
		const approved = await SELF.fetch("https://example.com/oauth/authorize", { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", cookie }, body: new URLSearchParams({ request_uri: requestUri, client_id: clientId, csrf, identifier: "oauth.localhost", password: "a secure oauth password", action: "approve" }) });
		expect(approved.status).toBe(303);
		const callback = new URL(approved.headers.get("location")!);
		expect(callback.searchParams.get("state")).toBe("client-state");
		expect(callback.searchParams.get("iss")).toBe("https://pds.example.com");
		expect(approved.headers.get("set-cookie")).toContain("Max-Age=0");
		const tokenNonce = par.headers.get("dpop-nonce")!;
		const token = await SELF.fetch("https://example.com/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpop(pair, jwk, "POST", "https://pds.example.com/oauth/token", tokenNonce) }, body: new URLSearchParams({ grant_type: "authorization_code", code: callback.searchParams.get("code")!, client_id: clientId, redirect_uri: redirectUri, code_verifier: verifier }) });
		expect(token.status).toBe(200);
		const tokens = await token.json<{ access_token: string; refresh_token: string }>();
		expect(tokens).toMatchObject({ token_type: "DPoP", sub: did, scope: requestedScope, access_token: expect.any(String), refresh_token: expect.any(String) });
		const accessNonce = token.headers.get("dpop-nonce")!;
		const session = await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: { authorization: `DPoP ${tokens.access_token}`, dpop: await dpop(pair, jwk, "GET", "https://pds.example.com/xrpc/com.atproto.server.getSession", accessNonce, crypto.randomUUID(), tokens.access_token) } });
		expect(session.status).toBe(200);
		const sessionBody = await session.json<Record<string, unknown>>();
		expect(sessionBody).toMatchObject({ did, handle: "oauth.localhost" });
		expect(sessionBody).not.toHaveProperty("email");
		const writeNonce = session.headers.get("dpop-nonce")!;
		const write = async (collection: string, nonceValue: string) => SELF.fetch("https://example.com/xrpc/com.atproto.repo.createRecord", { method: "POST", headers: { "content-type": "application/json", authorization: `DPoP ${tokens.access_token}`, dpop: await dpop(pair, jwk, "POST", "https://pds.example.com/xrpc/com.atproto.repo.createRecord", nonceValue, crypto.randomUUID(), tokens.access_token) }, body: JSON.stringify({ repo: did, collection, ...(collection.endsWith("post") ? {} : { rkey: "denied" }), record: { $type: collection, text: "oauth", createdAt: "2026-08-16T00:00:00.000Z" } }) });
		const allowed = await write("app.bsky.feed.post", writeNonce);
		expect(allowed.status).toBe(200);
		const denied = await write("app.bsky.feed.like", allowed.headers.get("dpop-nonce")!);
		expect(denied.status).toBe(403);
		expect(await denied.json()).toMatchObject({ error: "AuthScopeMismatch" });
		const revoke = await SELF.fetch("https://example.com/oauth/revoke", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpop(pair, jwk, "POST", "https://pds.example.com/oauth/revoke", denied.headers.get("dpop-nonce")!) }, body: new URLSearchParams({ token: tokens.refresh_token, client_id: clientId }) });
		expect(revoke.status).toBe(200);
		expect(revoke.headers.get("access-control-allow-origin")).toBe("*");
		expect(revoke.headers.get("access-control-expose-headers")).toContain("dpop-nonce");
		const revokedSession = await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: { authorization: `DPoP ${tokens.access_token}`, dpop: await dpop(pair, jwk, "GET", "https://pds.example.com/xrpc/com.atproto.server.getSession", revoke.headers.get("dpop-nonce")!, crypto.randomUUID(), tokens.access_token) } });
		expect(revokedSession.status).toBe(401);
	});

	it("binds confidential OAuth sessions to their private_key_jwt key", async () => {
		fetchMock.activate();
		fetchMock.disableNetConnect();
		const did = "did:plc:confidential";
		await new AccountRepository(d1(env.DB)).create({ did, handle: "confidential.localhost", email: "confidential@example.com", passwordHash: await hashPassword("a confidential password") });
		const clientId = "https://client.example/oauth.json";
		const redirectUri = "https://client.example/callback";
		const clientKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const otherKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const publicJwk = { ...await crypto.subtle.exportKey("jwk", clientKey.publicKey), kid: "client-key", alg: "ES256" };
		const otherJwk = { ...await crypto.subtle.exportKey("jwk", otherKey.publicKey), kid: "other-key", alg: "ES256" };
		const metadata = (keys: JsonWebKey[]) => JSON.stringify({ client_id: clientId, redirect_uris: [redirectUri], scope: "atproto", response_types: ["code"], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "private_key_jwt", token_endpoint_auth_signing_alg: "ES256", dpop_bound_access_tokens: true, jwks: { keys } });
		fetchMock.get("https://cloudflare-dns.com").intercept({ method: "GET", path: "/dns-query?name=client.example&type=A" }).reply(200, { Answer: [{ type: 1, data: "93.184.216.34" }] }, { headers: { "content-type": "application/dns-json" } });
		fetchMock.get("https://cloudflare-dns.com").intercept({ method: "GET", path: "/dns-query?name=client.example&type=AAAA" }).reply(200, { Answer: [] }, { headers: { "content-type": "application/dns-json" } });
		const mockMetadata = (keys: JsonWebKey[]) => fetchMock.get("https://client.example").intercept({ method: "GET", path: "/oauth.json" }).reply(200, metadata(keys), { headers: { "content-type": "application/json" } });
		const dpopKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
		const dpopJwk = await crypto.subtle.exportKey("jwk", dpopKey.publicKey);
		const verifier = "c".repeat(43);
		const base = new URLSearchParams({ client_id: clientId, response_type: "code", redirect_uri: redirectUri, scope: "atproto", state: "confidential-state", code_challenge: await tokenHash(verifier), code_challenge_method: "S256" });
		const challenge = await SELF.fetch("https://example.com/oauth/par", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: base });
		const nonce = challenge.headers.get("dpop-nonce")!;
		base.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		base.set("client_assertion", await clientAssertion(clientKey, clientId, "client-key"));
		mockMetadata([publicJwk, otherJwk]);
		const par = await SELF.fetch("https://example.com/oauth/par", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpop(dpopKey, dpopJwk, "POST", "https://pds.example.com/oauth/par", nonce) }, body: base });
		expect(par.status, await par.clone().text()).toBe(201);
		const { request_uri: requestUri } = await par.json<{ request_uri: string }>();
		const authorize = await SELF.fetch(`https://example.com/oauth/authorize?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(requestUri)}`);
		expect(await authorize.clone().text()).toContain(`Client: <code>${clientId}</code>`);
		expect(await authorize.clone().text()).toContain("Requested access: <code>atproto</code>");
		expect(authorize.headers.get("content-security-policy")).toBe("default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
		const cookie = authorize.headers.get("set-cookie")!;
		const csrf = /oauth_csrf=([^;]+)/.exec(cookie)![1];
		const approved = await SELF.fetch("https://example.com/oauth/authorize", { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", cookie }, body: new URLSearchParams({ request_uri: requestUri, client_id: clientId, csrf, identifier: "confidential.localhost", password: "a confidential password", action: "approve" }) });
		const code = new URL(approved.headers.get("location")!).searchParams.get("code")!;
		const tokenBody = new URLSearchParams({ grant_type: "authorization_code", code, client_id: clientId, redirect_uri: redirectUri, code_verifier: verifier, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await clientAssertion(clientKey, clientId, "client-key") });
		const token = await SELF.fetch("https://example.com/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpop(dpopKey, dpopJwk, "POST", "https://pds.example.com/oauth/token", par.headers.get("dpop-nonce")!) }, body: tokenBody });
		expect(token.status).toBe(200);
		const tokens = await token.json<{ refresh_token: string }>();
		const refreshBody = new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await clientAssertion(otherKey, clientId, "other-key") });
		const mismatched = await SELF.fetch("https://example.com/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpop(dpopKey, dpopJwk, "POST", "https://pds.example.com/oauth/token", token.headers.get("dpop-nonce")!) }, body: refreshBody });
		expect(mismatched.status).toBe(400);
		expect(await mismatched.json()).toMatchObject({ error: "invalid_grant" });
		fetchMock.assertNoPendingInterceptors();
	});

	it("authenticates and authorizes repository writes", async () => {
		const did = "did:plc:sessiontest";
		await new AccountRepository(d1(env.DB)).create({ did, handle: "alice.test", email: "alice@example.com", passwordHash: await hashPassword("a secure test password") });
		const signingKey = secp256k1.utils.randomSecretKey();
		await env.ACCOUNT_REPO.getByName(did).initialize(did, signingKey);

		const login = await SELF.fetch("https://example.com/xrpc/com.atproto.server.createSession", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ identifier: "alice.test", password: "a secure test password" }) });
		expect(login.status).toBe(200);
		const tokens = await login.json<{ accessJwt: string; refreshJwt: string }>();
		const serviceAuth = await SELF.fetch("https://example.com/xrpc/com.atproto.server.getServiceAuth?aud=did%3Aweb%3Aapi.example.com&lxm=app.bsky.feed.getTimeline", { headers: { authorization: `Bearer ${tokens.accessJwt}` } });
		expect(serviceAuth.status).toBe(200);
		const { token: serviceToken } = await serviceAuth.json<{ token: string }>();
		const [header, payload, signature] = serviceToken.split(".");
		expect(JSON.parse(Buffer.from(header, "base64url").toString())).toMatchObject({ alg: "ES256K", typ: "JWT", kid: "#atproto" });
		expect(JSON.parse(Buffer.from(payload, "base64url").toString())).toMatchObject({ iss: did, aud: "did:web:api.example.com", lxm: "app.bsky.feed.getTimeline" });
		expect(secp256k1.verify(Buffer.from(signature, "base64url"), new TextEncoder().encode(`${header}.${payload}`), secp256k1.getPublicKey(signingKey), { prehash: true, format: "compact", lowS: true })).toBe(true);
		const accountStatus = await SELF.fetch("https://example.com/xrpc/com.atproto.server.checkAccountStatus", { headers: { authorization: `Bearer ${tokens.accessJwt}` } });
		expect(await accountStatus.json()).toMatchObject({ activated: true, validDid: true, repoCommit: expect.any(String), repoRev: expect.any(String), indexedRecords: 0, expectedBlobs: 0, importedBlobs: 0 });
		const blobBytes = new TextEncoder().encode("blob payload");
		const uploaded = await SELF.fetch("https://example.com/xrpc/com.atproto.repo.uploadBlob", { method: "POST", headers: { authorization: `Bearer ${tokens.accessJwt}`, "content-type": "image/png", "content-length": String(blobBytes.length) }, body: blobBytes });
		expect(uploaded.status).toBe(200);
		const { blob } = await uploaded.json<{ blob: { $type: "blob"; ref: { $link: string }; mimeType: string; size: number } }>();
		const temporary = await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getBlob?did=${did}&cid=${blob.ref.$link}`);
		expect(temporary.status).toBe(400);
		expect(await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.listBlobs?did=${did}`).then((response) => response.json())).toEqual({ cids: [] });
		const wrongSize = await SELF.fetch("https://example.com/xrpc/com.atproto.repo.createRecord", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tokens.accessJwt}` }, body: JSON.stringify({ repo: did, collection: "app.bsky.feed.post", rkey: "wrong-size", validate: false, record: { $type: "app.bsky.feed.post", text: "invalid blob metadata", image: { ...blob, size: blob.size + 1 } } }) });
		expect(wrongSize.status).toBe(400);
		expect(await wrongSize.json()).toMatchObject({ error: "InvalidRequest", message: expect.stringContaining("size does not match") });

		const created = await SELF.fetch("https://example.com/xrpc/com.atproto.repo.createRecord", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tokens.accessJwt}` }, body: JSON.stringify({ repo: did, collection: "app.bsky.feed.post", rkey: "auth", validate: false, record: { $type: "app.bsky.feed.post", text: "authenticated", image: blob } }) });
		expect(created.status).toBe(200);
		expect(await created.json()).toMatchObject({ uri: `at://${did}/app.bsky.feed.post/auth` });
		const listed = await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.listBlobs?did=${did}`);
		expect(await listed.json()).toEqual({ cids: [blob.ref.$link] });
		const downloaded = await SELF.fetch(`https://example.com/xrpc/com.atproto.sync.getBlob?did=${did}&cid=${blob.ref.$link}`);
		expect(new Uint8Array(await downloaded.arrayBuffer())).toEqual(blobBytes);
		expect(downloaded.headers.get("content-security-policy")).toBe("default-src 'none'; sandbox");
		await env.BLOBS.delete(`blobs/${did}/${blob.ref.$link}`);
		const missing = await SELF.fetch("https://example.com/xrpc/com.atproto.repo.listMissingBlobs", { headers: { authorization: `Bearer ${tokens.accessJwt}` } });
		expect(await missing.json()).toEqual({ blobs: [{ cid: blob.ref.$link, recordUri: `at://${did}/app.bsky.feed.post/auth` }] });

		const refreshed = await SELF.fetch("https://example.com/xrpc/com.atproto.server.refreshSession", { method: "POST", headers: { authorization: `Bearer ${tokens.refreshJwt}` } });
		expect(refreshed.status).toBe(200);
		const reused = await SELF.fetch("https://example.com/xrpc/com.atproto.server.refreshSession", { method: "POST", headers: { authorization: `Bearer ${tokens.refreshJwt}` } });
		expect(reused.status).toBe(401);
	});

	it("proxies authenticated XRPC calls to a DID service", async () => {
		fetchMock.activate();
		fetchMock.disableNetConnect();
		const did = "did:plc:proxyaccount";
		await new AccountRepository(d1(env.DB)).create({ did, handle: "proxy.localhost", email: "proxy@example.com", passwordHash: await hashPassword("a secure proxy password") });
		await env.ACCOUNT_REPO.getByName(did).initialize(did);
		const login = await SELF.fetch("https://example.com/xrpc/com.atproto.server.createSession", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ identifier: "proxy.localhost", password: "a secure proxy password" }) });
		const { accessJwt } = await login.json<{ accessJwt: string }>();
		const audience = "did:web:api.example#appview";
		fetchMock.get("https://cloudflare-dns.com").intercept({ method: "GET", path: "/dns-query?name=api.example&type=A" }).reply(200, { Answer: [{ type: 1, data: "93.184.216.34" }] }).times(2);
		fetchMock.get("https://cloudflare-dns.com").intercept({ method: "GET", path: "/dns-query?name=api.example&type=AAAA" }).reply(200, { Answer: [] }).times(2);
		fetchMock.get("https://api.example").intercept({ method: "GET", path: "/.well-known/did.json" }).reply(200, JSON.stringify({ id: "did:web:api.example", service: [{ id: "#appview", type: "ExampleAppView", serviceEndpoint: "https://api.example" }] }), { headers: { "content-type": "application/json" } });
		fetchMock.get("https://api.example").intercept({ method: "GET", path: "/xrpc/app.example.getThing?value=1", headers: { authorization: /^Bearer /, "atproto-accept-labelers": "did:plc:labeler" } }).reply(200, JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", "atproto-content-labelers": "did:plc:labeler" } });
		const response = await SELF.fetch("https://example.com/xrpc/app.example.getThing?value=1", { headers: { authorization: `Bearer ${accessJwt}`, "atproto-proxy": audience, "atproto-accept-labelers": "did:plc:labeler" } });
		expect(response.status, await response.clone().text()).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
		expect(response.headers.get("atproto-content-labelers")).toBe("did:plc:labeler");
		fetchMock.assertNoPendingInterceptors();
	});

	it("returns one generic login failure", async () => {
		const response = await SELF.fetch("https://example.com/xrpc/com.atproto.server.createSession", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ identifier: "missing", password: "not a password" }) });
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "AuthenticationRequired", message: "Invalid identifier or password" });
	});

	it("creates, restricts, and revokes app passwords", async () => {
		const did = "did:plc:apppasswordtest";
		await new AccountRepository(d1(env.DB)).create({ did, handle: "app-password.test", email: "app-password@example.com", passwordHash: await hashPassword("a secure main password") });
		const login = async (password: string) => SELF.fetch("https://example.com/xrpc/com.atproto.server.createSession", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ identifier: "app-password.test", password }) });
		const main = await login("a secure main password");
		const mainTokens = await main.json<{ accessJwt: string }>();
		const authorization = { authorization: `Bearer ${mainTokens.accessJwt}`, "content-type": "application/json" };
		const created = await SELF.fetch("https://example.com/xrpc/com.atproto.server.createAppPassword", { method: "POST", headers: authorization, body: JSON.stringify({ name: "phone" }) });
		expect(created.status).toBe(200);
		const appPassword = await created.json<{ password: string }>();
		expect(appPassword.password).toMatch(/^[2-7a-z]{4}(?:-[2-7a-z]{4}){3}$/);

		const listed = await SELF.fetch("https://example.com/xrpc/com.atproto.server.listAppPasswords", { headers: { authorization: `Bearer ${mainTokens.accessJwt}` } });
		const listedBody = await listed.json<Record<string, unknown>>();
		expect(listedBody).toMatchObject({ passwords: [{ name: "phone", privileged: false }] });
		expect(JSON.stringify(listedBody)).not.toContain(appPassword.password);

		const appLogin = await login(appPassword.password);
		expect(appLogin.status).toBe(200);
		const appTokens = await appLogin.json<{ accessJwt: string; refreshJwt: string; email?: string }>();
		expect(appTokens).not.toHaveProperty("email");
		const forbidden = await SELF.fetch("https://example.com/xrpc/com.atproto.server.createAppPassword", { method: "POST", headers: { authorization: `Bearer ${appTokens.accessJwt}`, "content-type": "application/json" }, body: JSON.stringify({ name: "nested" }) });
		expect(forbidden.status).toBe(403);
		const refreshed = await SELF.fetch("https://example.com/xrpc/com.atproto.server.refreshSession", { method: "POST", headers: { authorization: `Bearer ${appTokens.refreshJwt}` } });
		expect(await refreshed.json()).not.toHaveProperty("email");

		const revoked = await SELF.fetch("https://example.com/xrpc/com.atproto.server.revokeAppPassword", { method: "POST", headers: authorization, body: JSON.stringify({ name: "phone" }) });
		expect(revoked.status).toBe(200);
		expect((await SELF.fetch("https://example.com/xrpc/com.atproto.server.getSession", { headers: { authorization: `Bearer ${appTokens.accessJwt}` } })).status).toBe(401);
		expect((await login(appPassword.password)).status).toBe(401);
	});
});

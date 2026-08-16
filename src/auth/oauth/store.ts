import { and, eq, gt, isNull, lt, or } from "drizzle-orm";
import { tokenHash } from "../../crypto/jwt";
import type { d1 } from "../../db/d1";
import { oauthClients, oauthDpopReplays, oauthSessions } from "../../db/schema/d1";
import type { ClientMetadata } from "./client-auth";

type Database = ReturnType<typeof d1>;

export function randomToken(bytes = 32): string {
	const value = crypto.getRandomValues(new Uint8Array(bytes));
	let binary = "";
	for (const byte of value) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}

export class OAuthStore {
	constructor(private readonly db: Database) {}

	async findClient(id: string): Promise<ClientMetadata | undefined> {
		return (await this.db.select().from(oauthClients).where(and(eq(oauthClients.id, id), gt(oauthClients.updatedAt, new Date(Date.now() - 5 * 60_000)))).get())?.metadata as ClientMetadata | undefined;
	}

	async saveClient(metadata: ClientMetadata) {
		const now = new Date();
		await this.db.insert(oauthClients).values({ id: metadata.client_id, metadata, createdAt: now, updatedAt: now }).onConflictDoUpdate({ target: oauthClients.id, set: { metadata, updatedAt: now } });
	}

	async createPar(input: { clientId: string; state: string; pkceChallenge: string; dpopJkt: string; redirectUri: string; scope: string; permissionsScope: string; loginHint?: string; clientAuth?: { kid: string; alg: string; jkt: string } }) {
		const requestUri = `urn:ietf:params:oauth:request_uri:${randomToken()}`;
		const now = new Date();
		await this.db.insert(oauthSessions).values({
			id: crypto.randomUUID(), clientId: input.clientId, stateHash: await tokenHash(input.state), state: input.state,
			pkceChallenge: input.pkceChallenge, dpopJkt: input.dpopJkt, requestUriHash: await tokenHash(requestUri), redirectUri: input.redirectUri,
			scope: input.scope, permissionsScope: input.permissionsScope, loginHint: input.loginHint, expiresAt: new Date(now.getTime() + 5 * 60_000), createdAt: now, updatedAt: now,
			clientAuthKid: input.clientAuth?.kid, clientAuthAlg: input.clientAuth?.alg, clientAuthJkt: input.clientAuth?.jkt,
		});
		return { requestUri };
	}

	findRequest(requestUri: string) {
		return tokenHash(requestUri).then((hash) => this.db.select().from(oauthSessions).where(and(eq(oauthSessions.requestUriHash, hash), gt(oauthSessions.expiresAt, new Date()))).get());
	}

	async prepareAuthorization(requestUri: string) {
		const csrf = randomToken();
		const [session] = await this.db.update(oauthSessions).set({ csrfHash: await tokenHash(csrf), updatedAt: new Date() }).where(and(eq(oauthSessions.requestUriHash, await tokenHash(requestUri)), isNull(oauthSessions.authorizedAt), gt(oauthSessions.expiresAt, new Date()))).returning();
		return session ? { session, csrf } : null;
	}

	async authorize(requestUri: string, csrf: string, accountId: string) {
		const requestHash = await tokenHash(requestUri);
		const csrfHash = await tokenHash(csrf);
		const code = randomToken();
		const [updated] = await this.db.update(oauthSessions).set({ accountId, codeHash: await tokenHash(code), authorizedAt: new Date(), updatedAt: new Date() }).where(and(eq(oauthSessions.requestUriHash, requestHash), eq(oauthSessions.csrfHash, csrfHash), isNull(oauthSessions.authorizedAt), gt(oauthSessions.expiresAt, new Date()))).returning();
		return updated ? { session: updated, code } : null;
	}

	async cancel(requestUri: string) {
		const [deleted] = await this.db.delete(oauthSessions).where(and(eq(oauthSessions.requestUriHash, await tokenHash(requestUri)), isNull(oauthSessions.authorizedAt), gt(oauthSessions.expiresAt, new Date()))).returning({ id: oauthSessions.id });
		return Boolean(deleted);
	}

	async findCode(code: string, clientId: string, redirectUri: string) {
		return this.db.select().from(oauthSessions).where(and(eq(oauthSessions.codeHash, await tokenHash(code)), eq(oauthSessions.clientId, clientId), eq(oauthSessions.redirectUri, redirectUri), isNull(oauthSessions.consumedAt), gt(oauthSessions.expiresAt, new Date()))).get();
	}

	async consumeCode(id: string, accessToken: string, refreshToken: string, expiresAt: Date) {
		const now = new Date();
		const [session] = await this.db.update(oauthSessions).set({ consumedAt: now, accessHash: await tokenHash(accessToken), refreshHash: await tokenHash(refreshToken), expiresAt, updatedAt: now }).where(and(eq(oauthSessions.id, id), isNull(oauthSessions.consumedAt), gt(oauthSessions.expiresAt, now))).returning();
		return session;
	}

	async findRefresh(refreshToken: string) {
		return this.db.select().from(oauthSessions).where(and(eq(oauthSessions.refreshHash, await tokenHash(refreshToken)), gt(oauthSessions.expiresAt, new Date()))).get();
	}

	async rotateRefresh(id: string, previousRefresh: string, accessToken: string, nextRefresh: string, expiresAt: Date) {
		const [session] = await this.db.update(oauthSessions).set({ accessHash: await tokenHash(accessToken), refreshHash: await tokenHash(nextRefresh), expiresAt, updatedAt: new Date() }).where(and(eq(oauthSessions.id, id), eq(oauthSessions.refreshHash, await tokenHash(previousRefresh)))).returning();
		return session;
	}

	async findAccess(accessToken: string) {
		return this.db.select().from(oauthSessions).where(and(eq(oauthSessions.accessHash, await tokenHash(accessToken)), gt(oauthSessions.expiresAt, new Date()), gt(oauthSessions.updatedAt, new Date(Date.now() - 5 * 60_000)))).get();
	}

	async findToken(token: string) {
		const hash = await tokenHash(token);
		return this.db.select().from(oauthSessions).where(or(eq(oauthSessions.accessHash, hash), eq(oauthSessions.refreshHash, hash))).get();
	}

	async revoke(token: string) {
		const hash = await tokenHash(token);
		await this.db.update(oauthSessions).set({ accessHash: null, refreshHash: null, updatedAt: new Date() }).where(or(eq(oauthSessions.accessHash, hash), eq(oauthSessions.refreshHash, hash)));
	}

	async recordProof(jkt: string, jti: string) {
		const now = new Date();
		await this.db.delete(oauthDpopReplays).where(lt(oauthDpopReplays.expiresAt, now));
		try { await this.db.insert(oauthDpopReplays).values({ id: crypto.randomUUID(), jkt, jti, expiresAt: new Date(now.getTime() + 5 * 60_000), createdAt: now }); }
		catch { throw new TypeError("DPoP proof replayed"); }
	}
}

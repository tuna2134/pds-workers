import { and, eq, gt, isNull } from "drizzle-orm";
import { tokenHash, signJwt, verifyJwt } from "../crypto/jwt";
import type { d1 } from "../db/d1";
import { sessions } from "../db/schema/d1";

type Database = ReturnType<typeof d1>;
const ACCESS_SECONDS = 120 * 60;
const REFRESH_SECONDS = 90 * 24 * 60 * 60;

export interface SessionAccount { id: string; did: string }

export class SessionRepository {
	constructor(private readonly db: Database, private readonly secret: string, private readonly audience: string) {}

	async create(account: SessionAccount, options?: { appPasswordId: string; privileged: boolean }) {
		const id = crypto.randomUUID();
		const now = Math.floor(Date.now() / 1000);
		const accessJwt = await signJwt({ sub: account.did, aud: this.audience, scope: "com.atproto.access", iat: now, exp: now + ACCESS_SECONDS, jti: crypto.randomUUID() }, "at+jwt", this.secret);
		const refreshJwt = await signJwt({ sub: account.did, aud: this.audience, scope: "com.atproto.refresh", iat: now, exp: now + REFRESH_SECONDS, jti: id }, "refresh+jwt", this.secret);
		const timestamp = new Date();
		const scope = options ? `transition:generic${options.privileged ? " transition:chat.bsky transition:email" : ""}` : "full";
		await this.db.insert(sessions).values({ id, accountId: account.id, appPasswordId: options?.appPasswordId, scope, accessHash: await tokenHash(accessJwt), refreshHash: await tokenHash(refreshJwt), expiresAt: new Date((now + REFRESH_SECONDS) * 1000), createdAt: timestamp, updatedAt: timestamp });
		return { accessJwt, refreshJwt };
	}

	async authenticate(token: string, type: "at+jwt" | "refresh+jwt") {
		const claims = await verifyJwt(token, type, this.secret);
		if (!claims || claims.aud !== this.audience) return null;
		const hash = await tokenHash(token);
		const session = await this.db.select().from(sessions).where(type === "at+jwt" ? eq(sessions.accessHash, hash) : eq(sessions.refreshHash, hash)).get();
		return session && !session.revokedAt && session.expiresAt > new Date() ? { claims, session } : null;
	}

	async refresh(token: string, account: SessionAccount) {
		const authenticated = await this.authenticate(token, "refresh+jwt");
		if (!authenticated || authenticated.session.accountId !== account.id) return null;
		const now = Math.floor(Date.now() / 1000);
		const accessJwt = await signJwt({ sub: account.did, aud: this.audience, scope: "com.atproto.access", iat: now, exp: now + ACCESS_SECONDS, jti: crypto.randomUUID() }, "at+jwt", this.secret);
		const refreshJwt = await signJwt({ sub: account.did, aud: this.audience, scope: "com.atproto.refresh", iat: now, exp: now + REFRESH_SECONDS, jti: crypto.randomUUID() }, "refresh+jwt", this.secret);
		const [rotated] = await this.db.update(sessions).set({ accessHash: await tokenHash(accessJwt), refreshHash: await tokenHash(refreshJwt), expiresAt: new Date((now + REFRESH_SECONDS) * 1000), updatedAt: new Date() }).where(and(
			eq(sessions.id, authenticated.session.id), eq(sessions.refreshHash, await tokenHash(token)), isNull(sessions.revokedAt), gt(sessions.expiresAt, new Date()),
		)).returning({ id: sessions.id });
		return rotated ? { accessJwt, refreshJwt } : null;
	}

	async revoke(id: string) { await this.db.update(sessions).set({ revokedAt: new Date(), updatedAt: new Date() }).where(eq(sessions.id, id)); }
}

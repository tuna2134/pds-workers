import { and, asc, eq, gt, inArray, like, ne, or } from "drizzle-orm";
import type { d1 } from "./d1";
import { accountPreferences, accounts, appPasswords, auditLogs, emailTokens, handles, identities, oauthSessions, sessions } from "./schema/d1";

type Database = ReturnType<typeof d1>;

export class AccountRepository {
	constructor(private readonly db: Database) {}

	find(identifier: string) {
		return this.db.select().from(accounts).where(or(eq(accounts.did, identifier), eq(accounts.handle, identifier), eq(accounts.email, identifier))).get();
	}

	findById(id: string) { return this.db.select().from(accounts).where(eq(accounts.id, id)).get(); }
	findMany(dids: string[]) { return dids.length ? this.db.select().from(accounts).where(inArray(accounts.did, dids)).all() : Promise.resolve([]); }

	async listHosted(cursor: string | undefined, limit: number) {
		const filters = [ne(accounts.status, "pending"), cursor ? gt(accounts.did, cursor) : undefined].filter((value) => value !== undefined);
		const rows = await this.db.select().from(accounts).where(and(...filters)).orderBy(asc(accounts.did)).limit(limit + 1).all();
		return { accounts: rows.slice(0, limit), ...(rows.length > limit ? { cursor: rows[limit - 1]!.did } : {}) };
	}

	search(input: { email?: string; cursor?: string; limit: number }) {
		const filters = [input.email ? like(accounts.email, `%${input.email}%`) : undefined, input.cursor ? gt(accounts.id, input.cursor) : undefined].filter((value) => value !== undefined);
		return this.db.select().from(accounts).where(filters.length ? and(...filters) : undefined).orderBy(asc(accounts.id)).limit(input.limit).all();
	}

	findIdentity(did: string) { return this.db.select().from(identities).where(eq(identities.did, did)).get(); }

	async create(input: { did: string; handle: string; email: string; passwordHash: string }) {
		const now = new Date();
		const account = { id: crypto.randomUUID(), ...input, status: "active", createdAt: now, updatedAt: now };
		await this.db.batch([this.db.insert(accounts).values(account), this.db.insert(handles).values({ handle: input.handle, did: input.did, verifiedAt: now, createdAt: now, updatedAt: now })]);
		return account;
	}

	async createPending(input: { did: string; handle: string; email: string; passwordHash: string; provider: string; wrappedRotationKey: string; document: object; status?: string }) {
		const now = new Date();
		const account = { id: crypto.randomUUID(), did: input.did, handle: input.handle, email: input.email, passwordHash: input.passwordHash, status: input.status ?? "pending", createdAt: now, updatedAt: now };
		await this.db.batch([
			this.db.insert(accounts).values(account),
			this.db.insert(identities).values({ did: input.did, accountId: account.id, provider: input.provider, signingKey: input.wrappedRotationKey, document: input.document, createdAt: now, updatedAt: now }),
			this.db.insert(handles).values({ handle: input.handle, did: input.did, verifiedAt: now, createdAt: now, updatedAt: now }),
		]);
		return account;
	}

	async activate(id: string) {
		await this.db.update(accounts).set({ status: "active", updatedAt: new Date() }).where(eq(accounts.id, id));
		return this.findById(id);
	}

	async setStatus(id: string, status: string) {
		await this.db.update(accounts).set({ status, updatedAt: new Date() }).where(eq(accounts.id, id));
		return this.findById(id);
	}

	async updateIdentity(did: string, document: object) {
		await this.db.update(identities).set({ document, updatedAt: new Date() }).where(eq(identities.did, did));
	}

	async confirmEmail(id: string) {
		await this.db.update(accounts).set({ emailConfirmed: true, updatedAt: new Date() }).where(eq(accounts.id, id));
		return this.findById(id);
	}

	async updateEmail(id: string, email: string) {
		await this.db.update(accounts).set({ email, emailConfirmed: false, emailAuthFactor: false, updatedAt: new Date() }).where(eq(accounts.id, id));
		return this.findById(id);
	}

	reserveHandle(did: string, handle: string) {
		const now = new Date();
		return this.db.insert(handles).values({ handle, did, verifiedAt: now, createdAt: now, updatedAt: now });
	}

	releaseHandle(did: string, handle: string) { return this.db.delete(handles).where(and(eq(handles.did, did), eq(handles.handle, handle))); }

	updateHandle(account: { id: string; did: string; handle: string }, handle: string, document: object) {
		const now = new Date();
		return this.db.batch([
			this.db.update(accounts).set({ handle, updatedAt: now }).where(eq(accounts.id, account.id)),
			this.db.update(identities).set({ document, updatedAt: now }).where(eq(identities.did, account.did)),
			this.db.delete(handles).where(eq(handles.handle, account.handle)),
			this.db.update(handles).set({ verifiedAt: now, updatedAt: now }).where(eq(handles.handle, handle)),
		]);
	}

	delete(account: { id: string; did: string }) {
		return this.db.batch([
			this.db.update(auditLogs).set({ accountId: null }).where(eq(auditLogs.accountId, account.id)),
			this.db.delete(sessions).where(eq(sessions.accountId, account.id)),
			this.db.delete(appPasswords).where(eq(appPasswords.accountId, account.id)),
			this.db.delete(oauthSessions).where(eq(oauthSessions.accountId, account.id)),
			this.db.delete(emailTokens).where(eq(emailTokens.accountId, account.id)),
			this.db.delete(accountPreferences).where(eq(accountPreferences.accountId, account.id)),
			this.db.delete(identities).where(eq(identities.accountId, account.id)),
			this.db.delete(handles).where(eq(handles.did, account.did)),
			this.db.delete(accounts).where(eq(accounts.id, account.id)),
		]);
	}

	resetPassword(accountId: string, passwordHash: string) {
		const now = new Date();
		return this.db.batch([
			this.db.update(accounts).set({ passwordHash, updatedAt: now }).where(eq(accounts.id, accountId)),
			this.db.delete(sessions).where(eq(sessions.accountId, accountId)),
			this.db.delete(appPasswords).where(eq(appPasswords.accountId, accountId)),
			this.db.delete(emailTokens).where(eq(emailTokens.accountId, accountId)),
		]);
	}
}

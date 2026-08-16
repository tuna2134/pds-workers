import { and, eq, gt, isNull } from "drizzle-orm";
import { tokenHash } from "../crypto/jwt";
import type { d1 } from "../db/d1";
import { emailTokens } from "../db/schema/d1";

type Database = ReturnType<typeof d1>;

function secret() {
	const bytes = crypto.getRandomValues(new Uint8Array(24));
	return btoa(String.fromCharCode(...bytes)).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}

export class EmailTokenRepository {
	constructor(private readonly db: Database) {}

	async create(accountId: string, purpose: string, lifetimeMs = 15 * 60_000) {
		const token = secret();
		const now = new Date();
		await this.db.batch([
			this.db.delete(emailTokens).where(and(eq(emailTokens.accountId, accountId), eq(emailTokens.purpose, purpose))),
			this.db.insert(emailTokens).values({ id: crypto.randomUUID(), accountId, purpose, tokenHash: await tokenHash(token), expiresAt: new Date(now.getTime() + lifetimeMs), createdAt: now, updatedAt: now }),
		]);
		return token;
	}

	async verify(accountId: string, purpose: string, token: string): Promise<"valid" | "expired" | "invalid"> {
		const row = await this.db.select().from(emailTokens).where(and(eq(emailTokens.accountId, accountId), eq(emailTokens.purpose, purpose), eq(emailTokens.tokenHash, await tokenHash(token)))).get();
		if (!row || row.consumedAt) return "invalid";
		return row.expiresAt > new Date() ? "valid" : "expired";
	}

	async consume(accountId: string, purpose: string, token: string): Promise<"valid" | "expired" | "invalid"> {
		const now = new Date();
		const consumed = await this.db.update(emailTokens).set({ consumedAt: now, updatedAt: now }).where(and(
			eq(emailTokens.accountId, accountId), eq(emailTokens.purpose, purpose), eq(emailTokens.tokenHash, await tokenHash(token)),
			isNull(emailTokens.consumedAt), gt(emailTokens.expiresAt, now),
		)).returning({ id: emailTokens.id }).get();
		return consumed ? "valid" : this.verify(accountId, purpose, token);
	}

	async find(purpose: string, token: string) {
		const row = await this.db.select().from(emailTokens).where(and(eq(emailTokens.purpose, purpose), eq(emailTokens.tokenHash, await tokenHash(token)))).get();
		if (!row || row.consumedAt) return { status: "invalid" as const };
		return row.expiresAt > new Date() ? { status: "valid" as const, accountId: row.accountId } : { status: "expired" as const };
	}

	async consumeByToken(purpose: string, token: string) {
		const now = new Date();
		const consumed = await this.db.update(emailTokens).set({ consumedAt: now, updatedAt: now }).where(and(
			eq(emailTokens.purpose, purpose), eq(emailTokens.tokenHash, await tokenHash(token)), isNull(emailTokens.consumedAt), gt(emailTokens.expiresAt, now),
		)).returning({ accountId: emailTokens.accountId }).get();
		return consumed ? { status: "valid" as const, accountId: consumed.accountId } : this.find(purpose, token);
	}

	revoke(accountId: string, purpose: string) {
		return this.db.delete(emailTokens).where(and(eq(emailTokens.accountId, accountId), eq(emailTokens.purpose, purpose)));
	}
}

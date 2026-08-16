import { and, eq } from "drizzle-orm";
import { tokenHash } from "../crypto/jwt";
import type { d1 } from "../db/d1";
import { appPasswords, sessions } from "../db/schema/d1";

type Database = ReturnType<typeof d1>;
const ALPHABET = "234567abcdefghijklmnopqrstuvwxyz";

function password(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(10));
	let bits = 0n;
	for (const byte of bytes) bits = bits << 8n | BigInt(byte);
	let value = "";
	for (let index = 0; index < 16; index++) { value += ALPHABET[Number(bits & 31n)]; bits >>= 5n; }
	return value.match(/.{4}/g)!.join("-");
}

export class AppPasswordRepository {
	constructor(private readonly db: Database) {}

	async create(accountId: string, nameInput: string, privileged = false) {
		const name = nameInput.trim();
		if (!name || name.length > 64 || [...name].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) throw new TypeError("App password name must contain 1 to 64 printable characters");
		const secret = password();
		const now = new Date();
		const row = { id: crypto.randomUUID(), accountId, name, passwordHash: await tokenHash(secret), privileged, createdAt: now, updatedAt: now };
		await this.db.insert(appPasswords).values(row);
		return { row, secret };
	}

	list(accountId: string) { return this.db.select().from(appPasswords).where(eq(appPasswords.accountId, accountId)).all(); }

	find(accountId: string, secret: string) { return tokenHash(secret).then((hash) => this.db.select().from(appPasswords).where(and(eq(appPasswords.accountId, accountId), eq(appPasswords.passwordHash, hash))).get()); }

	async revoke(accountId: string, name: string) {
		const rows = await this.db.select({ id: appPasswords.id }).from(appPasswords).where(and(eq(appPasswords.accountId, accountId), eq(appPasswords.name, name))).all();
		if (!rows.length) return;
		await this.db.batch([
			this.db.delete(sessions).where(eq(sessions.appPasswordId, rows[0].id)),
			this.db.delete(appPasswords).where(and(eq(appPasswords.accountId, accountId), eq(appPasswords.name, name))),
		]);
	}
}

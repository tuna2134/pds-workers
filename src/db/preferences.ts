import { eq } from "drizzle-orm";
import type { d1 } from "./d1";
import { accountPreferences } from "./schema/d1";

type Database = ReturnType<typeof d1>;
type Preference = Record<string, unknown>;

export class PreferencesRepository {
	constructor(private readonly db: Database) {}

	async get(accountId: string): Promise<Preference[]> {
		const row = await this.db.select({ value: accountPreferences.value }).from(accountPreferences).where(eq(accountPreferences.accountId, accountId)).get();
		return Array.isArray(row?.value) ? row.value as Preference[] : [];
	}

	put(accountId: string, value: Preference[]) {
		const now = new Date();
		return this.db.insert(accountPreferences).values({ accountId, value, createdAt: now, updatedAt: now })
			.onConflictDoUpdate({ target: accountPreferences.accountId, set: { value, updatedAt: now } });
	}
}

import type { d1 } from "./d1";
import { auditLogs } from "./schema/d1";

type Database = ReturnType<typeof d1>;

export class AuditRepository {
	constructor(private readonly db: Database) {}

	record(input: { action: string; accountId?: string; requestId?: string; ipHash?: string; detail?: Record<string, unknown> }) {
		return this.db.insert(auditLogs).values({ id: crypto.randomUUID(), action: input.action, accountId: input.accountId, requestId: input.requestId, ipHash: input.ipHash, detail: input.detail, createdAt: new Date() });
	}
}

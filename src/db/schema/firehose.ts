import { blob, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const firehoseEvents = sqliteTable("firehose_events", {
	seq: integer("seq").primaryKey({ autoIncrement: true }),
	id: text("id").notNull().unique(),
	type: text("type").notNull(),
	frame: blob("frame", { mode: "buffer" }).notNull(),
	createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});

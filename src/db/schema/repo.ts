import { blob, integer, primaryKey, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const repoState = sqliteTable("repo_state", {
	id: integer("id").primaryKey(), did: text("did").notNull().unique(), rev: text("rev"), rootCid: text("root_cid"), commitCid: text("commit_cid"), wrappedSigningKey: text("wrapped_signing_key").notNull(),
});
export const records = sqliteTable("records", {
	path: text("path").primaryKey(), cid: text("cid").notNull(), bytes: blob("bytes", { mode: "buffer" }).notNull(),
});
export const blocks = sqliteTable("blocks", {
	cid: text("cid").primaryKey(), bytes: blob("bytes", { mode: "buffer" }).notNull(), createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});
export const commits = sqliteTable("commits", {
	rev: text("rev").primaryKey(), cid: text("cid").notNull().unique(), rootCid: text("root_cid").notNull(), bytes: blob("bytes", { mode: "buffer" }).notNull(), createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});
export const blobRefs = sqliteTable("blob_refs", {
	recordPath: text("record_path").notNull().references(() => records.path, { onDelete: "cascade" }), cid: text("cid").notNull(), addedRev: text("added_rev").notNull(),
}, (table) => [primaryKey({ columns: [table.recordPath, table.cid] })]);

export const firehoseOutbox = sqliteTable("firehose_outbox", {
	id: text("id").primaryKey(), payload: blob("payload", { mode: "buffer" }).notNull(), createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});

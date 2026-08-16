import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

const timestamps = {
	createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
};

export const accounts = sqliteTable("accounts", {
	id: text("id").primaryKey(), did: text("did").notNull().unique(), handle: text("handle").notNull().unique(),
	email: text("email").notNull().unique(), emailConfirmed: integer("email_confirmed", { mode: "boolean" }).notNull().default(false), emailAuthFactor: integer("email_auth_factor", { mode: "boolean" }).notNull().default(false),
	passwordHash: text("password_hash").notNull(), status: text("status").notNull().default("active"), ...timestamps,
});
export const identities = sqliteTable("identities", {
	did: text("did").primaryKey(), accountId: text("account_id").notNull().references(() => accounts.id),
	provider: text("provider").notNull(), signingKey: text("signing_key").notNull(), document: text("document", { mode: "json" }).notNull(), ...timestamps,
});
export const handles = sqliteTable("handles", {
	handle: text("handle").primaryKey(), did: text("did").notNull(), verifiedAt: integer("verified_at", { mode: "timestamp_ms" }), ...timestamps,
}, (table) => [index("handles_did_idx").on(table.did)]);
export const appPasswords = sqliteTable("app_passwords", {
	id: text("id").primaryKey(), accountId: text("account_id").notNull().references(() => accounts.id), name: text("name").notNull(), passwordHash: text("password_hash").notNull(), privileged: integer("privileged", { mode: "boolean" }).notNull().default(false), ...timestamps,
}, (table) => [uniqueIndex("app_passwords_account_name_idx").on(table.accountId, table.name)]);
export const sessions = sqliteTable("sessions", {
	id: text("id").primaryKey(), accountId: text("account_id").notNull().references(() => accounts.id),
	appPasswordId: text("app_password_id").references(() => appPasswords.id), scope: text("scope").notNull().default("full"),
	accessHash: text("access_hash").notNull().unique(), refreshHash: text("refresh_hash").notNull().unique(),
	expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(), revokedAt: integer("revoked_at", { mode: "timestamp_ms" }), ...timestamps,
});
export const oauthClients = sqliteTable("oauth_clients", {
	id: text("id").primaryKey(), metadata: text("metadata", { mode: "json" }).notNull(), ...timestamps,
});
export const oauthSessions = sqliteTable("oauth_sessions", {
	id: text("id").primaryKey(), accountId: text("account_id").references(() => accounts.id), clientId: text("client_id").notNull(), stateHash: text("state_hash").notNull().unique(), pkceChallenge: text("pkce_challenge").notNull().unique(), dpopJkt: text("dpop_jkt"), expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(), consumedAt: integer("consumed_at", { mode: "timestamp_ms" }), ...timestamps,
	requestUriHash: text("request_uri_hash").unique(), redirectUri: text("redirect_uri"), scope: text("scope"), state: text("state"), loginHint: text("login_hint"), csrfHash: text("csrf_hash"), codeHash: text("code_hash").unique(), accessHash: text("access_hash").unique(), refreshHash: text("refresh_hash").unique(), authorizedAt: integer("authorized_at", { mode: "timestamp_ms" }),
	permissionsScope: text("permissions_scope"),
	clientAuthKid: text("client_auth_kid"), clientAuthAlg: text("client_auth_alg"), clientAuthJkt: text("client_auth_jkt"),
});
export const oauthDpopReplays = sqliteTable("oauth_dpop_replays", {
	id: text("id").primaryKey(), jkt: text("jkt").notNull(), jti: text("jti").notNull(), expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(), createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
}, (table) => [uniqueIndex("oauth_dpop_replays_jkt_jti_idx").on(table.jkt, table.jti)]);
export const emailTokens = sqliteTable("email_tokens", {
	id: text("id").primaryKey(), accountId: text("account_id").notNull().references(() => accounts.id), purpose: text("purpose").notNull(), tokenHash: text("token_hash").notNull().unique(), expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(), consumedAt: integer("consumed_at", { mode: "timestamp_ms" }), ...timestamps,
});
export const accountPreferences = sqliteTable("account_preferences", {
	accountId: text("account_id").primaryKey().references(() => accounts.id), value: text("value", { mode: "json" }).notNull(), ...timestamps,
});
export const serviceConfig = sqliteTable("service_config", {
	key: text("key").primaryKey(), value: text("value", { mode: "json" }).notNull(), ...timestamps,
});
export const auditLogs = sqliteTable("audit_logs", {
	id: text("id").primaryKey(), accountId: text("account_id").references(() => accounts.id), action: text("action").notNull(), requestId: text("request_id"), ipHash: text("ip_hash"), detail: text("detail", { mode: "json" }), createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
}, (table) => [index("audit_logs_account_created_idx").on(table.accountId, table.createdAt)]);

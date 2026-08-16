CREATE TABLE `oauth_dpop_replays` (
	`id` text PRIMARY KEY NOT NULL,
	`jkt` text NOT NULL,
	`jti` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_dpop_replays_jkt_jti_idx` ON `oauth_dpop_replays` (`jkt`,`jti`);--> statement-breakpoint
ALTER TABLE `oauth_sessions` ADD `request_uri_hash` text;--> statement-breakpoint
ALTER TABLE `oauth_sessions` ADD `redirect_uri` text;--> statement-breakpoint
ALTER TABLE `oauth_sessions` ADD `scope` text;--> statement-breakpoint
ALTER TABLE `oauth_sessions` ADD `login_hint` text;--> statement-breakpoint
ALTER TABLE `oauth_sessions` ADD `csrf_hash` text;--> statement-breakpoint
ALTER TABLE `oauth_sessions` ADD `code_hash` text;--> statement-breakpoint
ALTER TABLE `oauth_sessions` ADD `access_hash` text;--> statement-breakpoint
ALTER TABLE `oauth_sessions` ADD `refresh_hash` text;--> statement-breakpoint
ALTER TABLE `oauth_sessions` ADD `authorized_at` integer;--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_sessions_request_uri_hash_unique` ON `oauth_sessions` (`request_uri_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_sessions_code_hash_unique` ON `oauth_sessions` (`code_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_sessions_access_hash_unique` ON `oauth_sessions` (`access_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_sessions_refresh_hash_unique` ON `oauth_sessions` (`refresh_hash`);
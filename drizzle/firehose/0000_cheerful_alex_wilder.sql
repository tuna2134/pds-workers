CREATE TABLE `firehose_events` (
	`seq` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`id` text NOT NULL,
	`type` text NOT NULL,
	`frame` blob NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `firehose_events_id_unique` ON `firehose_events` (`id`);
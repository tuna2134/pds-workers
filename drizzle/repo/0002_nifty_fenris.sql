CREATE TABLE `firehose_outbox` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` blob NOT NULL,
	`created_at` integer NOT NULL
);

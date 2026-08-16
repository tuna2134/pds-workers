CREATE TABLE `blob_refs` (
	`record_path` text NOT NULL,
	`cid` text NOT NULL,
	PRIMARY KEY(`record_path`, `cid`),
	FOREIGN KEY (`record_path`) REFERENCES `records`(`path`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `blocks` (
	`cid` text PRIMARY KEY NOT NULL,
	`bytes` blob NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `commits` (
	`rev` text PRIMARY KEY NOT NULL,
	`cid` text NOT NULL,
	`root_cid` text NOT NULL,
	`bytes` blob NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `commits_cid_unique` ON `commits` (`cid`);--> statement-breakpoint
CREATE TABLE `records` (
	`path` text PRIMARY KEY NOT NULL,
	`cid` text NOT NULL,
	`bytes` blob NOT NULL
);
--> statement-breakpoint
CREATE TABLE `repo_state` (
	`id` integer PRIMARY KEY NOT NULL,
	`did` text NOT NULL,
	`rev` text,
	`root_cid` text,
	`commit_cid` text,
	`wrapped_signing_key` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `repo_state_did_unique` ON `repo_state` (`did`);
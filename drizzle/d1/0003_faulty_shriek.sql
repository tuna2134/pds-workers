ALTER TABLE `sessions` ADD `app_password_id` text REFERENCES app_passwords(id);--> statement-breakpoint
ALTER TABLE `sessions` ADD `scope` text DEFAULT 'full' NOT NULL;
ALTER TABLE `accounts` ADD `email_confirmed` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `accounts` ADD `email_auth_factor` integer DEFAULT false NOT NULL;
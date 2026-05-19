ALTER TABLE "transfers" ADD COLUMN "encrypted_title" varchar(1024);--> statement-breakpoint
ALTER TABLE "transfers" ADD COLUMN "encrypted_title_iv" varchar(32);
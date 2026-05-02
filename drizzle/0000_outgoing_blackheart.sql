CREATE TABLE IF NOT EXISTS "files" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"transfer_id" varchar(21) NOT NULL,
	"r2_key" varchar(255) NOT NULL,
	"storage_type" varchar(10) DEFAULT 'local' NOT NULL,
	"encrypted_name" varchar(1024) NOT NULL,
	"encrypted_name_iv" varchar(32) NOT NULL,
	"file_iv" varchar(32) NOT NULL,
	"size" bigint NOT NULL,
	"mime_type" varchar(127),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"is_deleted" boolean DEFAULT false NOT NULL,
	CONSTRAINT "files_r2_key_unique" UNIQUE("r2_key")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "transfer_events" (
	"id" serial PRIMARY KEY NOT NULL,
	"event" varchar(32) NOT NULL,
	"transfer_id" varchar(21) NOT NULL,
	"file_count" integer DEFAULT 0 NOT NULL,
	"total_bytes" bigint DEFAULT 0 NOT NULL,
	"download_count" integer DEFAULT 0 NOT NULL,
	"has_password" boolean DEFAULT false NOT NULL,
	"max_downloads" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "transfers" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"download_count" integer DEFAULT 0 NOT NULL,
	"max_downloads" integer,
	"is_deleted" boolean DEFAULT false NOT NULL,
	"is_completed" boolean DEFAULT false NOT NULL,
	"password_hash" varchar(255)
);
--> statement-breakpoint
DO $$ BEGIN
  ALTER TABLE "files" ADD CONSTRAINT "files_transfer_id_transfers_id_fk" FOREIGN KEY ("transfer_id") REFERENCES "public"."transfers"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

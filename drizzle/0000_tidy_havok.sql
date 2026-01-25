CREATE TABLE "files" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"r2_key" varchar(255) NOT NULL,
	"encrypted_name" varchar(512) NOT NULL,
	"encrypted_name_iv" varchar(32) NOT NULL,
	"size" bigint NOT NULL,
	"mime_type" varchar(127),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"download_count" integer DEFAULT 0 NOT NULL,
	"max_downloads" integer,
	"allow_download" boolean DEFAULT true NOT NULL,
	"is_deleted" boolean DEFAULT false NOT NULL,
	CONSTRAINT "files_r2_key_unique" UNIQUE("r2_key")
);

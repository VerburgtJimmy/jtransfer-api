CREATE TABLE "user_vaults" (
	"user_id" varchar(21) PRIMARY KEY NOT NULL,
	"salt_password" "bytea" NOT NULL,
	"salt_phrase" "bytea" NOT NULL,
	"wrap_password" "bytea" NOT NULL,
	"wrap_phrase" "bytea" NOT NULL,
	"kdf_version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"password_changed_at" timestamp with time zone,
	"phrase_regenerated_at" timestamp with time zone
);
--> statement-breakpoint
DROP TABLE "authenticator_prf_salts" CASCADE;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "vault_setup_completed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "user_vaults" ADD CONSTRAINT "user_vaults_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authenticators" DROP COLUMN "supports_prf";--> statement-breakpoint
ALTER TABLE "transfers" DROP COLUMN "wrap_credential_id";
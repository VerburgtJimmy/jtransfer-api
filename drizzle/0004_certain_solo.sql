CREATE TABLE "authenticator_prf_salts" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"credential_id" "bytea" NOT NULL,
	"purpose" varchar(32) NOT NULL,
	"salt" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "authenticators" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"user_id" varchar(21) NOT NULL,
	"credential_id" "bytea" NOT NULL,
	"public_key" "bytea" NOT NULL,
	"sign_count" bigint DEFAULT 0 NOT NULL,
	"transports" text[] DEFAULT '{}'::text[] NOT NULL,
	"device_type" varchar(16) NOT NULL,
	"backed_up" boolean NOT NULL,
	"supports_prf" boolean DEFAULT false NOT NULL,
	"nickname" varchar(64),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "webauthn_challenges" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"user_id" varchar(21),
	"challenge" "bytea" NOT NULL,
	"kind" varchar(16) NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "authenticators" ADD CONSTRAINT "authenticators_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webauthn_challenges" ADD CONSTRAINT "webauthn_challenges_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "authenticator_prf_salts_credential_purpose_unique" ON "authenticator_prf_salts" USING btree ("credential_id","purpose");--> statement-breakpoint
CREATE UNIQUE INDEX "authenticators_credential_id_unique" ON "authenticators" USING btree ("credential_id");--> statement-breakpoint
CREATE INDEX "authenticators_user_id_idx" ON "authenticators" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "webauthn_challenges_user_id_idx" ON "webauthn_challenges" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "webauthn_challenges_expires_at_idx" ON "webauthn_challenges" USING btree ("expires_at");
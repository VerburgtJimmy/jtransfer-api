CREATE TABLE "salts" (
	"id" serial PRIMARY KEY NOT NULL,
	"namespace" varchar(32) NOT NULL,
	"secret" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "auth_events" ADD COLUMN "country" varchar(2);--> statement-breakpoint
ALTER TABLE "auth_events" ADD COLUMN "asn" integer;--> statement-breakpoint
ALTER TABLE "auth_events" ADD COLUMN "ip_correlator" "bytea";--> statement-breakpoint
ALTER TABLE "auth_events" ADD COLUMN "salt_id" integer;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "country" varchar(2);--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "asn" integer;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "ip_hmac" "bytea";--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "correlation_secret" "bytea";--> statement-breakpoint
CREATE INDEX "salts_active_idx" ON "salts" USING btree ("namespace","created_at" DESC NULLS LAST) WHERE "salts"."retired_at" IS NULL;--> statement-breakpoint
ALTER TABLE "auth_events" ADD CONSTRAINT "auth_events_salt_id_salts_id_fk" FOREIGN KEY ("salt_id") REFERENCES "public"."salts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "auth_events_salt_correlator_idx" ON "auth_events" USING btree ("salt_id","ip_correlator");--> statement-breakpoint
ALTER TABLE "auth_events" DROP COLUMN "ip";--> statement-breakpoint
ALTER TABLE "magic_link_tokens" DROP COLUMN "ip";--> statement-breakpoint
ALTER TABLE "sessions" DROP COLUMN "ip";
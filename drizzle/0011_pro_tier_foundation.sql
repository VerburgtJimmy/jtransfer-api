CREATE TABLE "billing_events" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"polar_event_id" varchar(64) NOT NULL,
	"polar_event_type" varchar(64) NOT NULL,
	"subscription_id" varchar(21),
	"raw_payload" jsonb NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"processed_at" timestamp with time zone,
	"error" text
);
--> statement-breakpoint
CREATE TABLE "subscriptions" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"user_id" varchar(21) NOT NULL,
	"polar_subscription_id" varchar(64) NOT NULL,
	"status" varchar(16) NOT NULL,
	"current_period_end" timestamp with time zone NOT NULL,
	"cancel_at_period_end" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"canceled_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "polar_customer_id" varchar(64);--> statement-breakpoint
ALTER TABLE "billing_events" ADD CONSTRAINT "billing_events_subscription_id_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."subscriptions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "billing_events_polar_event_id_unique" ON "billing_events" USING btree ("polar_event_id");--> statement-breakpoint
CREATE INDEX "billing_events_subscription_id_idx" ON "billing_events" USING btree ("subscription_id");--> statement-breakpoint
CREATE UNIQUE INDEX "subscriptions_polar_subscription_id_unique" ON "subscriptions" USING btree ("polar_subscription_id");--> statement-breakpoint
CREATE INDEX "subscriptions_user_id_idx" ON "subscriptions" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "subscriptions_one_live_per_user" ON "subscriptions" USING btree ("user_id") WHERE "subscriptions"."status" IN ('active', 'past_due', 'trialing');--> statement-breakpoint
CREATE UNIQUE INDEX "users_polar_customer_id_unique" ON "users" USING btree ("polar_customer_id");
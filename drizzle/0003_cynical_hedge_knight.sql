ALTER TABLE "magic_link_tokens" ADD COLUMN "code_hash" varchar(64);--> statement-breakpoint
ALTER TABLE "magic_link_tokens" ADD COLUMN "pending_session_id" varchar(21);--> statement-breakpoint
ALTER TABLE "magic_link_tokens" ADD COLUMN "code_attempts" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
CREATE INDEX "magic_link_tokens_pending_session_idx" ON "magic_link_tokens" USING btree ("pending_session_id") WHERE "magic_link_tokens"."pending_session_id" IS NOT NULL;
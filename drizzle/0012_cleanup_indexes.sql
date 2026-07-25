DROP INDEX "transfers_user_id_idx";--> statement-breakpoint
ALTER TABLE "files" ALTER COLUMN "storage_type" SET DEFAULT 'r2';--> statement-breakpoint
CREATE INDEX "files_transfer_id_idx" ON "files" USING btree ("transfer_id");--> statement-breakpoint
CREATE INDEX "transfers_expires_at_idx" ON "transfers" USING btree ("expires_at") WHERE "transfers"."is_deleted" = false;--> statement-breakpoint
CREATE INDEX "transfers_abandoned_idx" ON "transfers" USING btree ("created_at") WHERE "transfers"."is_deleted" = false AND "transfers"."is_completed" = false;--> statement-breakpoint
CREATE INDEX "transfers_soft_deleted_idx" ON "transfers" USING btree ("created_at") WHERE "transfers"."is_deleted" = true;--> statement-breakpoint
CREATE INDEX "transfers_user_id_idx" ON "transfers" USING btree ("user_id","created_at") WHERE "transfers"."user_id" IS NOT NULL;--> statement-breakpoint
UPDATE "files" SET "storage_type" = 'r2' WHERE "storage_type" = 'local';

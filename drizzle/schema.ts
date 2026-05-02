import { pgTable, serial, varchar, integer, bigint, boolean, timestamp, foreignKey, unique } from "drizzle-orm/pg-core"
import { sql } from "drizzle-orm"



export const transferEvents = pgTable("transfer_events", {
	id: serial().primaryKey().notNull(),
	event: varchar({ length: 32 }).notNull(),
	transferId: varchar("transfer_id", { length: 21 }).notNull(),
	fileCount: integer("file_count").default(0).notNull(),
	// You can use { mode: "bigint" } if numbers are exceeding js number limitations
	totalBytes: bigint("total_bytes", { mode: "number" }).default(0).notNull(),
	downloadCount: integer("download_count").default(0).notNull(),
	hasPassword: boolean("has_password").default(false).notNull(),
	maxDownloads: integer("max_downloads"),
	createdAt: timestamp("created_at", { withTimezone: true, mode: 'string' }).defaultNow().notNull(),
});

export const files = pgTable("files", {
	id: varchar({ length: 21 }).primaryKey().notNull(),
	r2Key: varchar("r2_key", { length: 255 }).notNull(),
	encryptedName: varchar("encrypted_name", { length: 1024 }).notNull(),
	encryptedNameIv: varchar("encrypted_name_iv", { length: 32 }).notNull(),
	// You can use { mode: "bigint" } if numbers are exceeding js number limitations
	size: bigint({ mode: "number" }).notNull(),
	mimeType: varchar("mime_type", { length: 127 }),
	createdAt: timestamp("created_at", { withTimezone: true, mode: 'string' }).defaultNow().notNull(),
	isDeleted: boolean("is_deleted").default(false).notNull(),
	transferId: varchar("transfer_id", { length: 21 }).notNull(),
	fileIv: varchar("file_iv", { length: 32 }).notNull(),
	storageType: varchar("storage_type", { length: 10 }).default('local').notNull(),
}, (table) => [
	foreignKey({
			columns: [table.transferId],
			foreignColumns: [transfers.id],
			name: "files_transfer_id_transfers_id_fk"
		}),
	unique("files_r2_key_unique").on(table.r2Key),
]);

export const transfers = pgTable("transfers", {
	id: varchar({ length: 21 }).primaryKey().notNull(),
	createdAt: timestamp("created_at", { withTimezone: true, mode: 'string' }).defaultNow().notNull(),
	expiresAt: timestamp("expires_at", { withTimezone: true, mode: 'string' }).notNull(),
	downloadCount: integer("download_count").default(0).notNull(),
	maxDownloads: integer("max_downloads"),
	isDeleted: boolean("is_deleted").default(false).notNull(),
	passwordHash: varchar("password_hash", { length: 255 }),
	isCompleted: boolean("is_completed").default(false).notNull(),
});

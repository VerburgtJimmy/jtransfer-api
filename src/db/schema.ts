import { pgTable, varchar, bigint, timestamp, integer, boolean } from 'drizzle-orm/pg-core';

export const transfers = pgTable('transfers', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  downloadCount: integer('download_count').default(0).notNull(),
  maxDownloads: integer('max_downloads'), // NULL = unlimited
  isDeleted: boolean('is_deleted').default(false).notNull(),
  passwordHash: varchar('password_hash', { length: 255 }) // NULL = no password
});

export const files = pgTable('files', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  transferId: varchar('transfer_id', { length: 21 }).notNull().references(() => transfers.id),
  r2Key: varchar('r2_key', { length: 255 }).notNull().unique(), // Storage path (column name kept for DB compatibility)
  storageType: varchar('storage_type', { length: 10 }).default('local').notNull(), // Storage type (local only)
  encryptedName: varchar('encrypted_name', { length: 512 }).notNull(), // base64 encrypted filename
  encryptedNameIv: varchar('encrypted_name_iv', { length: 32 }).notNull(),
  fileIv: varchar('file_iv', { length: 32 }).notNull(), // IV for file content encryption
  size: bigint('size', { mode: 'number' }).notNull(),
  mimeType: varchar('mime_type', { length: 127 }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  isDeleted: boolean('is_deleted').default(false).notNull()
});

export type Transfer = typeof transfers.$inferSelect;
export type NewTransfer = typeof transfers.$inferInsert;
export type File = typeof files.$inferSelect;
export type NewFile = typeof files.$inferInsert;

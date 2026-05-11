import { pgTable, varchar, bigint, timestamp, integer, boolean, serial, uniqueIndex, index, inet, text } from 'drizzle-orm/pg-core';

export const transfers = pgTable('transfers', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  downloadCount: integer('download_count').default(0).notNull(),
  maxDownloads: integer('max_downloads'), // NULL = unlimited
  isDeleted: boolean('is_deleted').default(false).notNull(),
  isCompleted: boolean('is_completed').default(false).notNull(),
  passwordHash: varchar('password_hash', { length: 255 }) // NULL = no password
});

export const files = pgTable('files', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  transferId: varchar('transfer_id', { length: 21 }).notNull().references(() => transfers.id),
  r2Key: varchar('r2_key', { length: 255 }).notNull().unique(), // Storage path (column name kept for DB compatibility)
  storageType: varchar('storage_type', { length: 10 }).default('local').notNull(), // Storage type (local only)
  encryptedName: varchar('encrypted_name', { length: 1024 }).notNull(), // base64 encrypted filename (padded + AES-GCM tag)
  encryptedNameIv: varchar('encrypted_name_iv', { length: 32 }).notNull(),
  fileIv: varchar('file_iv', { length: 32 }).notNull(), // IV for file content encryption
  size: bigint('size', { mode: 'number' }).notNull(),
  mimeType: varchar('mime_type', { length: 127 }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  isDeleted: boolean('is_deleted').default(false).notNull()
});

// Immutable event log — no sensitive data, used for stats. Records survive transfer deletion.
export const transferEvents = pgTable('transfer_events', {
  id: serial('id').primaryKey(),
  event: varchar('event', { length: 32 }).notNull(), // completed | expired | aborted
  transferId: varchar('transfer_id', { length: 21 }).notNull(),
  fileCount: integer('file_count').default(0).notNull(),
  totalBytes: bigint('total_bytes', { mode: 'number' }).default(0).notNull(),
  downloadCount: integer('download_count').default(0).notNull(),
  hasPassword: boolean('has_password').default(false).notNull(),
  maxDownloads: integer('max_downloads'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export type TransferEvent = typeof transferEvents.$inferSelect;
export type Transfer = typeof transfers.$inferSelect;
export type NewTransfer = typeof transfers.$inferInsert;
export type File = typeof files.$inferSelect;
export type NewFile = typeof files.$inferInsert;

// Auth — magic-link primary, server-side sessions. See docs/audit/18-auth-security-baseline.md.
//
// Email is stored lowercased + trimmed (app-side normalisation) with a unique index.
// Token hashes are hex-encoded SHA-256 (64 chars) — never store plaintext bearer tokens.

export const users = pgTable('users', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  email: varchar('email', { length: 320 }).notNull(), // RFC 5321 max length
  tier: varchar('tier', { length: 16 }).default('free').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  deletedAt: timestamp('deleted_at', { withTimezone: true }),
}, (table) => ({
  emailUnique: uniqueIndex('users_email_unique').on(table.email),
}));

export const sessions = pgTable('sessions', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  userId: varchar('user_id', { length: 21 }).notNull().references(() => users.id),
  tokenHash: varchar('token_hash', { length: 64 }).notNull(), // hex SHA-256
  // Sliding idle expiry: refreshed to now + 30d on activity.
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  // Hard cap: created_at + 90d. Never refreshed.
  absoluteExpiresAt: timestamp('absolute_expires_at', { withTimezone: true }).notNull(),
  lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).defaultNow().notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  ip: inet('ip'),
  userAgent: text('user_agent'),
}, (table) => ({
  tokenHashUnique: uniqueIndex('sessions_token_hash_unique').on(table.tokenHash),
  userIdIdx: index('sessions_user_id_idx').on(table.userId),
}));

export const magicLinkTokens = pgTable('magic_link_tokens', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  email: varchar('email', { length: 320 }).notNull(),
  tokenHash: varchar('token_hash', { length: 64 }).notNull(), // hex SHA-256
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  consumedAt: timestamp('consumed_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  ip: inet('ip'),
  userAgent: text('user_agent'),
}, (table) => ({
  tokenHashUnique: uniqueIndex('magic_link_tokens_token_hash_unique').on(table.tokenHash),
  emailIdx: index('magic_link_tokens_email_idx').on(table.email),
}));

// 90-day retention; daily purge job. Per audit doc 18 §8.
export const authEvents = pgTable('auth_events', {
  id: serial('id').primaryKey(),
  userId: varchar('user_id', { length: 21 }), // nullable — pre-account events log only email
  email: varchar('email', { length: 320 }), // captured for pre-account events
  eventType: varchar('event_type', { length: 32 }).notNull(),
  ip: inet('ip'),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  createdAtIdx: index('auth_events_created_at_idx').on(table.createdAt),
  userIdIdx: index('auth_events_user_id_idx').on(table.userId),
}));

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type MagicLinkToken = typeof magicLinkTokens.$inferSelect;
export type NewMagicLinkToken = typeof magicLinkTokens.$inferInsert;
export type AuthEvent = typeof authEvents.$inferSelect;
export type NewAuthEvent = typeof authEvents.$inferInsert;

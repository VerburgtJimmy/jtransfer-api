import { sql } from 'drizzle-orm';
import { pgTable, varchar, bigint, timestamp, integer, boolean, serial, uniqueIndex, index, inet, text, customType } from 'drizzle-orm/pg-core';

// Drizzle ORM ships a `bytea` type only via the experimental column builder
// in some versions. customType is portable and lets us round-trip Uint8Array.
const bytea = customType<{ data: Uint8Array; default: false }>({
  dataType() {
    return 'bytea';
  },
});

export const transfers = pgTable('transfers', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  downloadCount: integer('download_count').default(0).notNull(),
  maxDownloads: integer('max_downloads'), // NULL = unlimited
  isDeleted: boolean('is_deleted').default(false).notNull(),
  isCompleted: boolean('is_completed').default(false).notNull(),
  passwordHash: varchar('password_hash', { length: 255 }), // NULL = no password
  // NULL = anonymous transfer. See docs/audit/20-transfer-ownership.md.
  userId: varchar('user_id', { length: 21 }).references(() => users.id),
  // Vault wrap layer — Phase F (doc 28). Both NULL on anonymous and on
  // signed-in-without-vault rows; both set together on vaulted rows. Per D-113.
  // wrappedKey wire layout: wrap_iv(12B) || ciphertext(32B) || tag(16B) = 60 bytes.
  // wrapCredentialId stays opaque bytes — no hard FK, see doc 28 §4.
  wrappedKey: bytea('wrapped_key'),
  wrapCredentialId: bytea('wrap_credential_id'),
}, (table) => ({
  userIdIdx: index('transfers_user_id_idx')
    .on(table.userId)
    .where(sql`${table.userId} IS NOT NULL`),
}));

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
  // Set on sessions minted via a passkey assertion (passkey/login/finish).
  // Drives the "Used to sign in here" hint and the pre-confirm warning on
  // /dashboard/settings. NULL for sessions minted via magic link / verify-code
  // and for any rows that pre-date the column — there is no backfill, so
  // legacy sessions render without the hint by construction.
  authenticatorId: varchar('authenticator_id', { length: 21 })
    .references(() => authenticators.id, { onDelete: 'set null' }),
}, (table) => ({
  tokenHashUnique: uniqueIndex('sessions_token_hash_unique').on(table.tokenHash),
  userIdIdx: index('sessions_user_id_idx').on(table.userId),
}));

export const magicLinkTokens = pgTable('magic_link_tokens', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  email: varchar('email', { length: 320 }).notNull(),
  tokenHash: varchar('token_hash', { length: 64 }).notNull(), // hex SHA-256
  // Cross-device 6-digit code: hex SHA-256 of zero-padded digits. Bound to
  // pendingSessionId — code alone is insufficient. See audit doc 21.
  codeHash: varchar('code_hash', { length: 64 }),
  pendingSessionId: varchar('pending_session_id', { length: 21 }),
  codeAttempts: integer('code_attempts').default(0).notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  consumedAt: timestamp('consumed_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  ip: inet('ip'),
  userAgent: text('user_agent'),
}, (table) => ({
  tokenHashUnique: uniqueIndex('magic_link_tokens_token_hash_unique').on(table.tokenHash),
  emailIdx: index('magic_link_tokens_email_idx').on(table.email),
  pendingSessionIdx: index('magic_link_tokens_pending_session_idx')
    .on(table.pendingSessionId)
    .where(sql`${table.pendingSessionId} IS NOT NULL`),
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

// WebAuthn / passkeys — alternative primary authenticator. See audit doc 27.
//
// One row per enrolled credential. No attestation statements retained
// (`attestation: none` at registration). `device_type` and `backed_up`
// come from the authenticator data BS/BE flags and drive UX badges
// ("Sync'd" vs "This device"). `supports_prf` is set true if the
// registration response surfaced PRF capability — consumed in Phase F.
export const authenticators = pgTable('authenticators', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  userId: varchar('user_id', { length: 21 }).notNull().references(() => users.id, { onDelete: 'cascade' }),
  credentialId: bytea('credential_id').notNull(), // raw rawId
  publicKey: bytea('public_key').notNull(), // COSE key blob
  signCount: bigint('sign_count', { mode: 'number' }).default(0).notNull(),
  transports: text('transports').array().default(sql`'{}'::text[]`).notNull(),
  deviceType: varchar('device_type', { length: 16 }).notNull(), // 'singleDevice' | 'multiDevice'
  backedUp: boolean('backed_up').notNull(),
  supportsPrf: boolean('supports_prf').default(false).notNull(),
  nickname: varchar('nickname', { length: 64 }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
}, (table) => ({
  credentialIdUnique: uniqueIndex('authenticators_credential_id_unique').on(table.credentialId),
  userIdIdx: index('authenticators_user_id_idx').on(table.userId),
}));

// One row per outstanding ceremony. `user_id` is nullable so
// resident-credential authentication (username-less) can issue a challenge
// before we know who is signing in. 5-min TTL; daily purge consumes
// expired rows via the existing cleanup job.
export const webauthnChallenges = pgTable('webauthn_challenges', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  userId: varchar('user_id', { length: 21 }).references(() => users.id, { onDelete: 'cascade' }),
  challenge: bytea('challenge').notNull(), // 32 random bytes
  kind: varchar('kind', { length: 16 }).notNull(), // 'registration' | 'authentication'
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  consumedAt: timestamp('consumed_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  userIdIdx: index('webauthn_challenges_user_id_idx').on(table.userId),
  expiresAtIdx: index('webauthn_challenges_expires_at_idx').on(table.expiresAt),
}));

// Per-credential per-purpose 32-byte salts for PRF-derived vault keys.
// Rows created lazily on first PRF use in Phase F (doc 28); empty table
// after Phase D landing. Salt rotation re-keys the purpose.
export const authenticatorPrfSalts = pgTable('authenticator_prf_salts', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  credentialId: bytea('credential_id').notNull(),
  purpose: varchar('purpose', { length: 32 }).notNull(),
  salt: bytea('salt').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  credentialPurposeUnique: uniqueIndex('authenticator_prf_salts_credential_purpose_unique')
    .on(table.credentialId, table.purpose),
}));

export type Authenticator = typeof authenticators.$inferSelect;
export type NewAuthenticator = typeof authenticators.$inferInsert;
export type WebauthnChallenge = typeof webauthnChallenges.$inferSelect;
export type NewWebauthnChallenge = typeof webauthnChallenges.$inferInsert;
export type AuthenticatorPrfSalt = typeof authenticatorPrfSalts.$inferSelect;
export type NewAuthenticatorPrfSalt = typeof authenticatorPrfSalts.$inferInsert;

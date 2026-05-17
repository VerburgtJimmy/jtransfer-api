// Per-user vault — stores opaque crypto blobs the server cannot read.
//
// The vault holds a random per-user `K_vault` wrapped twice: once under a
// password-derived KEK and once under a recovery-phrase-derived KEK.
// All KDF work happens client-side; the server only persists salts and
// wrap blobs. See docs/adr/0004-vault-redesign-password-and-recovery-phrase.md.
//
// Wrap blob layout is AES-GCM-256 over a 32-byte K_vault:
//   iv(12) || ciphertext(32) || tag(16)  = 60 bytes
//
// Salts are 16 bytes (Argon2id RFC 9106 minimum).

import { and, eq, isNull } from "drizzle-orm";
import { db } from "../db";
import { users, userVaults, type UserVault } from "../db/schema";

export const WRAP_BYTES = 60;
export const SALT_BYTES = 16;
export const CURRENT_KDF_VERSION = 1;

export interface VaultBlobs {
  saltPassword: Uint8Array;
  saltPhrase: Uint8Array;
  wrapPassword: Uint8Array;
  wrapPhrase: Uint8Array;
  kdfVersion: number;
}

/** Fetch the vault row for a user, or null if setup has not happened. */
export async function getUserVault(userId: string): Promise<UserVault | null> {
  const [row] = await db
    .select()
    .from(userVaults)
    .where(eq(userVaults.userId, userId))
    .limit(1);
  return row ?? null;
}

/**
 * One-shot vault setup. Inserts the row and stamps
 * `users.vault_setup_completed_at` in a single transaction. The user-row
 * stamp is the source of truth for the setup-guard middleware (cheap to
 * read on every request), and the vault row holds the blobs.
 *
 * Returns `{ ok: true }` on first-time setup, `{ ok: false, reason: 'already_setup' }`
 * if the row already exists. Idempotent under racing concurrent calls — the
 * unique PK on `user_id` collapses the second insert.
 */
export async function createUserVault(
  userId: string,
  blobs: VaultBlobs,
): Promise<{ ok: true } | { ok: false; reason: "already_setup" }> {
  const existing = await getUserVault(userId);
  if (existing) return { ok: false, reason: "already_setup" };

  return db.transaction(async (tx) => {
    const inserted = await tx
      .insert(userVaults)
      .values({
        userId,
        saltPassword: blobs.saltPassword,
        saltPhrase: blobs.saltPhrase,
        wrapPassword: blobs.wrapPassword,
        wrapPhrase: blobs.wrapPhrase,
        kdfVersion: blobs.kdfVersion,
      })
      .onConflictDoNothing({ target: userVaults.userId })
      .returning({ userId: userVaults.userId });

    if (inserted.length === 0) {
      return { ok: false, reason: "already_setup" } as const;
    }

    await tx
      .update(users)
      .set({ vaultSetupCompletedAt: new Date() })
      .where(and(eq(users.id, userId), isNull(users.vaultSetupCompletedAt)));

    return { ok: true } as const;
  });
}

/**
 * Rewrap K_vault under a new password-derived KEK. Caller has already
 * unwrapped K_vault client-side (either with the old password or the
 * recovery phrase) and re-wrapped it under the new password. The wrap
 * under the recovery phrase is untouched, so phrase recovery still
 * works after a password change.
 */
export async function updateVaultPasswordWrap(
  userId: string,
  saltPassword: Uint8Array,
  wrapPassword: Uint8Array,
  kdfVersion: number,
): Promise<boolean> {
  const result = await db
    .update(userVaults)
    .set({
      saltPassword,
      wrapPassword,
      kdfVersion,
      passwordChangedAt: new Date(),
    })
    .where(eq(userVaults.userId, userId))
    .returning({ userId: userVaults.userId });
  return result.length > 0;
}

/**
 * Rewrap K_vault under a freshly generated recovery phrase. Caller has
 * unwrapped K_vault with their password and re-wrapped under the new
 * phrase. The password wrap is untouched.
 */
export async function updateVaultPhraseWrap(
  userId: string,
  saltPhrase: Uint8Array,
  wrapPhrase: Uint8Array,
  kdfVersion: number,
): Promise<boolean> {
  const result = await db
    .update(userVaults)
    .set({
      saltPhrase,
      wrapPhrase,
      kdfVersion,
      phraseRegeneratedAt: new Date(),
    })
    .where(eq(userVaults.userId, userId))
    .returning({ userId: userVaults.userId });
  return result.length > 0;
}

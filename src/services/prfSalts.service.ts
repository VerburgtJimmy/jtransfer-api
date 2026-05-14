// Per-credential per-purpose PRF input salts. Rows are created lazily on
// first request and never rotated server-side (rotation = mint a new
// purpose string in client code; old rows become unused). See
// docs/audit/27-passkey-webauthn-prf.md §7 + §10 (D-110) and
// docs/audit/28-dashboard-transfer-key-vault.md §6.
//
// The salt is the byte string passed to `prf.eval.first` during a WebAuthn
// assertion. The PRF output is then fed to HKDF-SHA-256 client-side to
// produce the per-purpose vault key.

import { and, eq } from 'drizzle-orm';
import { nanoid } from 'nanoid';
import { db } from '../db';
import { authenticatorPrfSalts, authenticators } from '../db/schema';

// Hard-coded allowlist — purposes are part of the public client/server
// protocol and must not be caller-controlled. New purposes get a code change.
export const PRF_PURPOSES = ['jtransfer:vault:transfer-key:v1'] as const;
export type PrfPurpose = (typeof PRF_PURPOSES)[number];

export function isValidPurpose(p: string): p is PrfPurpose {
  return (PRF_PURPOSES as readonly string[]).includes(p);
}

// Race-safe get-or-create. Two concurrent first-use requests can both miss
// the SELECT — the unique index on (credential_id, purpose) collapses them
// to one row; the loser re-reads the winner's salt.
export async function getOrCreatePrfSalt(
  credentialId: Uint8Array,
  purpose: PrfPurpose,
): Promise<Uint8Array> {
  const existing = await db
    .select({ salt: authenticatorPrfSalts.salt })
    .from(authenticatorPrfSalts)
    .where(
      and(
        eq(authenticatorPrfSalts.credentialId, credentialId),
        eq(authenticatorPrfSalts.purpose, purpose),
      ),
    )
    .limit(1);
  if (existing[0]) return existing[0].salt;

  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);

  // ON CONFLICT collapses the loser of a race. We then re-read so we
  // always return the *winning* row's salt (not the bytes we tried to
  // insert), which matters because the lost insert's salt is discarded.
  await db
    .insert(authenticatorPrfSalts)
    .values({ id: nanoid(), credentialId, purpose, salt })
    .onConflictDoNothing({
      target: [authenticatorPrfSalts.credentialId, authenticatorPrfSalts.purpose],
    });

  const [row] = await db
    .select({ salt: authenticatorPrfSalts.salt })
    .from(authenticatorPrfSalts)
    .where(
      and(
        eq(authenticatorPrfSalts.credentialId, credentialId),
        eq(authenticatorPrfSalts.purpose, purpose),
      ),
    )
    .limit(1);

  if (!row) {
    // Should be impossible — the row either pre-existed or was inserted
    // (or lost the race to another inserter, but in either case exists).
    throw new Error('PRF salt row missing after insert');
  }
  return row.salt;
}

// All PRF-capable credentials owned by `userId`, paired with their salts
// for every known purpose. Used by the salt-fetch endpoint that primes the
// client for a PRF-enabled assertion (`evalByCredential`).
export interface PrfSaltEntry {
  credentialId: Uint8Array;
  purpose: PrfPurpose;
  salt: Uint8Array;
}

export async function listPrfSaltsForUser(userId: string): Promise<PrfSaltEntry[]> {
  const creds = await db
    .select({ credentialId: authenticators.credentialId })
    .from(authenticators)
    .where(and(eq(authenticators.userId, userId), eq(authenticators.supportsPrf, true)));

  const entries: PrfSaltEntry[] = [];
  for (const { credentialId } of creds) {
    for (const purpose of PRF_PURPOSES) {
      const salt = await getOrCreatePrfSalt(credentialId, purpose);
      entries.push({ credentialId, purpose, salt });
    }
  }
  return entries;
}

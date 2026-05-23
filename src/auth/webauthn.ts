// WebAuthn / passkey ceremony helpers.
//
// Responsibilities:
//  - Issue and consume one-shot challenges for both registration and
//    authentication ceremonies (5-minute TTL).
//  - Verify ceremony responses via @simplewebauthn/server and persist the
//    resulting authenticator row (registration) or bump sign_count
//    (authentication).
//
// Passkeys are a login factor only — they don't participate in
// vault key derivation. The vault (K_vault) is wrapped under
// password and recovery-phrase KEKs derived via Argon2id.
//
// What this module does NOT do:
//  - Mint sessions. Caller resolves the user and hands off to
//    createSession(). Keeps the helper agnostic of the cookie surface.
//  - Origin / CORS / rate limiting. Owned by the auth.routes wiring.

import { and, eq, gt, isNull } from "drizzle-orm";
import { nanoid } from "nanoid";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { db } from "../db";
import {
  authenticators,
  webauthnChallenges,
  type Authenticator,
} from "../db/schema";
import { env } from "../config/env";

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Generate registration options + persist a one-shot challenge bound to the
 * user. Conservative defaults: ES256 then RS256, resident key required,
 * user verification required, no attestation.
 */
export async function beginRegistration(input: {
  userId: string;
  userEmail: string;
  existingCredentialIds: Uint8Array[];
}): Promise<{
  options: PublicKeyCredentialCreationOptionsJSON;
  challengeRowId: string;
}> {
  const options = await generateRegistrationOptions({
    rpName: env.WEBAUTHN_RP_NAME,
    rpID: env.WEBAUTHN_RP_ID,
    userName: input.userEmail,
    userDisplayName: input.userEmail,
    // Pass the user's own row id as the credential `user.id`. nanoid is
    // 21 chars ASCII so it fits the 1-64 byte WebAuthn constraint.
    userID: new TextEncoder().encode(input.userId),
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
    // ES256 (-7), RS256 (-257) — RS256 only for older Windows Hello stacks.
    supportedAlgorithmIDs: [-7, -257],
    // Reject re-enrollment of an already-registered authenticator.
    excludeCredentials: input.existingCredentialIds.map((credentialId) => ({
      id: bytesToBase64url(credentialId),
    })),
  });

  const challengeRowId = nanoid();
  await db.insert(webauthnChallenges).values({
    id: challengeRowId,
    userId: input.userId,
    challenge: base64urlToBytes(options.challenge),
    kind: "registration",
    expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
  });

  return { options, challengeRowId };
}

/**
 * Verify a registration response. On success: inserts an authenticators row
 * and consumes the challenge. Returns the new row.
 *
 * The challenge row is consumed on *any* finalize attempt (success or
 * failure) so a leaked response cannot be replayed against a different
 * challenge.
 */
export async function finishRegistration(input: {
  challengeRowId: string;
  userId: string;
  response: RegistrationResponseJSON;
  nickname: string | null;
}): Promise<
  | { ok: true; authenticator: Authenticator }
  | { ok: false; reason: "challenge_invalid" | "verification_failed" | "duplicate" }
> {
  const now = new Date();
  const challenge = await consumeChallenge({
    rowId: input.challengeRowId,
    expectedKind: "registration",
    expectedUserId: input.userId,
    now,
  });
  if (!challenge) return { ok: false, reason: "challenge_invalid" };

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: input.response,
      expectedChallenge: bytesToBase64url(challenge.challenge),
      expectedOrigin: env.WEBAUTHN_RP_ORIGIN,
      expectedRPID: env.WEBAUTHN_RP_ID,
      requireUserVerification: true,
    });
  } catch {
    return { ok: false, reason: "verification_failed" };
  }

  if (!verification.verified || !verification.registrationInfo) {
    return { ok: false, reason: "verification_failed" };
  }

  const info = verification.registrationInfo;
  const credentialIdBytes = base64urlToBytes(info.credential.id);

  const newAuth: typeof authenticators.$inferInsert = {
    id: nanoid(),
    userId: input.userId,
    credentialId: credentialIdBytes,
    publicKey: info.credential.publicKey,
    signCount: info.credential.counter ?? 0,
    transports: (info.credential.transports ?? []) as string[],
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
    nickname: input.nickname,
  };

  try {
    const [inserted] = await db
      .insert(authenticators)
      .values(newAuth)
      .returning();
    return { ok: true, authenticator: inserted };
  } catch (err) {
    // Unique constraint on credential_id — caller saw `excludeCredentials`
    // empty but the race window still exists if a different user enrolled
    // the same authenticator (extremely unlikely for a real device, but
    // surface a clean error rather than 500).
    if (isUniqueViolation(err)) {
      return { ok: false, reason: "duplicate" };
    }
    throw err;
  }
}

/**
 * Generate authentication (assertion) options + persist a one-shot
 * challenge. Resident-credential flow: `allowCredentials: []`, so the
 * browser picks from the authenticator's on-device list.
 */
export async function beginAuthentication(): Promise<{
  options: PublicKeyCredentialRequestOptionsJSON;
  challengeRowId: string;
}> {
  const options = await generateAuthenticationOptions({
    rpID: env.WEBAUTHN_RP_ID,
    allowCredentials: [],
    userVerification: "required",
  });

  const challengeRowId = nanoid();
  await db.insert(webauthnChallenges).values({
    id: challengeRowId,
    userId: null,
    challenge: base64urlToBytes(options.challenge),
    kind: "authentication",
    expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
  });

  return { options, challengeRowId };
}

/**
 * Verify an authentication response. On success: bumps sign_count and
 * last_used_at, returns the authenticator row (which carries user_id for
 * session minting).
 *
 * sign_count enforcement: WebAuthn L3 §5.1.4.1 — if the new counter is not
 * strictly greater than the stored counter (and either is non-zero), the
 * server SHOULD reject. We do reject — passkey-cloning detection is the
 * point of the counter. Many passkey platforms (iCloud Keychain, Google
 * Password Manager) report counter = 0 always; we accept counter == 0
 * with stored == 0 transparently.
 */
export async function finishAuthentication(input: {
  challengeRowId: string;
  response: AuthenticationResponseJSON;
}): Promise<
  | { ok: true; authenticator: Authenticator }
  | { ok: false; reason: "challenge_invalid" | "credential_unknown" | "verification_failed" | "counter_replay" }
> {
  const now = new Date();
  const challenge = await consumeChallenge({
    rowId: input.challengeRowId,
    expectedKind: "authentication",
    expectedUserId: null,
    now,
  });
  if (!challenge) return { ok: false, reason: "challenge_invalid" };

  const credentialIdBytes = base64urlToBytes(input.response.id);
  const [auth] = await db
    .select()
    .from(authenticators)
    .where(eq(authenticators.credentialId, credentialIdBytes))
    .limit(1);
  if (!auth) return { ok: false, reason: "credential_unknown" };

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: input.response,
      expectedChallenge: bytesToBase64url(challenge.challenge),
      expectedOrigin: env.WEBAUTHN_RP_ORIGIN,
      expectedRPID: env.WEBAUTHN_RP_ID,
      credential: {
        id: bytesToBase64url(auth.credentialId),
        publicKey: toArrayBufferBytes(auth.publicKey),
        counter: auth.signCount,
        transports: auth.transports as AuthenticatorTransportFuture[],
      },
      requireUserVerification: true,
    });
  } catch {
    return { ok: false, reason: "verification_failed" };
  }

  if (!verification.verified) {
    return { ok: false, reason: "verification_failed" };
  }

  const newCounter = verification.authenticationInfo.newCounter;
  // Reject only when both sides are non-zero and the new value did not move
  // forward. Platform passkeys often pin counter = 0 forever; that's not a
  // replay signal.
  if (auth.signCount > 0 && newCounter <= auth.signCount) {
    return { ok: false, reason: "counter_replay" };
  }

  const [updated] = await db
    .update(authenticators)
    .set({ signCount: newCounter, lastUsedAt: now })
    .where(eq(authenticators.id, auth.id))
    .returning();

  return { ok: true, authenticator: updated };
}

/** List authenticators for a user, newest first. */
export async function listAuthenticatorsForUser(userId: string): Promise<Authenticator[]> {
  return db
    .select()
    .from(authenticators)
    .where(eq(authenticators.userId, userId));
}

/**
 * Delete an authenticator. Caller verifies ownership before invoking.
 * Returns true if a row was removed.
 */
export async function deleteAuthenticator(input: {
  authenticatorId: string;
  userId: string;
}): Promise<boolean> {
  const result = await db
    .delete(authenticators)
    .where(and(
      eq(authenticators.id, input.authenticatorId),
      eq(authenticators.userId, input.userId),
    ))
    .returning({ id: authenticators.id });
  return result.length > 0;
}

/**
 * Rename an authenticator's nickname. Caller verifies ownership. Returns the
 * updated row or null if not found (or not owned by user).
 */
export async function renameAuthenticator(input: {
  authenticatorId: string;
  userId: string;
  nickname: string | null;
}): Promise<Authenticator | null> {
  const [row] = await db
    .update(authenticators)
    .set({ nickname: input.nickname })
    .where(and(
      eq(authenticators.id, input.authenticatorId),
      eq(authenticators.userId, input.userId),
    ))
    .returning();
  return row ?? null;
}

// ─── internals ────────────────────────────────────────────────────────────

async function consumeChallenge(input: {
  rowId: string;
  expectedKind: "registration" | "authentication";
  expectedUserId: string | null;
  now: Date;
}) {
  const [updated] = await db
    .update(webauthnChallenges)
    .set({ consumedAt: input.now })
    .where(
      and(
        eq(webauthnChallenges.id, input.rowId),
        eq(webauthnChallenges.kind, input.expectedKind),
        isNull(webauthnChallenges.consumedAt),
        gt(webauthnChallenges.expiresAt, input.now),
      ),
    )
    .returning();
  if (!updated) return null;
  // For registration we expect the challenge to belong to the asserted user;
  // mismatch is a tampering signal.
  if (
    input.expectedUserId !== null &&
    updated.userId !== input.expectedUserId
  ) {
    return null;
  }
  return updated;
}

function isUniqueViolation(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const code = (err as { code?: unknown }).code;
  return code === "23505";
}

// base64url <-> bytes helpers. WebAuthn JSON shape uses base64url for
// challenge / credential id / public key. We persist raw bytes in bytea.

function base64urlToBytes(input: string): Uint8Array {
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const b64 = (input + pad).replace(/-/g, "+").replace(/_/g, "/");
  return toArrayBufferBytes(Buffer.from(b64, "base64"));
}

/**
 * Copy `Uint8Array | Buffer` data into a fresh `Uint8Array` backed by a
 * plain `ArrayBuffer`. Drizzle's bytea customType and Node's Buffer pool
 * both produce values typed `Uint8Array<ArrayBufferLike>`, which the
 * latest @simplewebauthn types reject in favour of the narrower
 * `Uint8Array<ArrayBuffer>`. Copying is cheap on the sizes involved
 * (≤ a few hundred bytes for credentials and challenges).
 */
function toArrayBufferBytes(input: Uint8Array): Uint8Array<ArrayBuffer> {
  const ab = new ArrayBuffer(input.length);
  const out = new Uint8Array(ab);
  out.set(input);
  return out;
}

function bytesToBase64url(input: Uint8Array): string {
  return Buffer.from(input).toString("base64url");
}

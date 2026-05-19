// Session lifecycle: create, validate (with sliding-idle refresh), revoke.
// See docs/audit/18-auth-security-baseline.md §3.
//
// IP minimization (audit doc 19, ADR-0002): each session carries a
// per-session 32-byte `correlationSecret` minted at create time. The
// stored `ipHmac` is HMAC-SHA-256(correlationSecret, raw_ip). On revoke
// or expiry the secret is wiped, after which the stored ipHmac is
// permanently un-correlatable to any IP.

import { randomBytes } from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../db";
import { sessions, type Session } from "../db/schema";
import { env } from "../config/env";
import { generateToken, hashToken } from "./tokens";
import type { IpContext } from "../utils/ipContext";

// The `__Host-` prefix requires the `Secure` flag, which browsers (correctly)
// only honour over HTTPS. Local dev runs on `http://localhost`, so we fall
// back to a plain `session` cookie there. Production keeps the full
// hardening: `__Host-session; Secure; HttpOnly; SameSite=Lax`.
export const SESSION_COOKIE_NAME = env.IS_PRODUCTION ? "__Host-session" : "session";

// ASVS 3.3.1 — sliding idle window.
export const SESSION_IDLE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
// ASVS 3.3.2 — absolute hard cap.
export const SESSION_ABSOLUTE_MS = 90 * 24 * 60 * 60 * 1000; // 90 days
// Refresh expires_at on activity, but only if the existing one is older than
// this threshold — avoids a DB write on every single request.
export const SESSION_REFRESH_THROTTLE_MS = 5 * 60 * 1000; // 5 minutes

interface CreateSessionInput {
  userId: string;
  ipContext: IpContext;
  userAgent: string | null;
  /**
   * The authenticator that minted this session, if any. Set only by the
   * passkey/login/finish path. Powers the "Used to sign in here" hint on
   * /dashboard/settings — no heuristic fallback.
   */
  authenticatorId?: string | null;
}

interface CreateSessionResult {
  session: Session;
  /** Plaintext token to set on the cookie. Never persisted. */
  token: string;
}

export async function createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
  const token = generateToken();
  const tokenHash = await hashToken(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_IDLE_MS);
  const absoluteExpiresAt = new Date(now.getTime() + SESSION_ABSOLUTE_MS);

  // Per-session correlation secret. Wiped on revoke/expiry, after which
  // the stored ipHmac is permanently un-correlatable.
  const correlationSecret = randomBytes(32);
  const ipHmac = input.ipContext.hmac(correlationSecret);

  const [session] = await db
    .insert(sessions)
    .values({
      id: nanoid(),
      userId: input.userId,
      tokenHash,
      expiresAt,
      absoluteExpiresAt,
      lastSeenAt: now,
      country: normaliseCountry(input.ipContext.country),
      asn: input.ipContext.asn,
      asnOrg: input.ipContext.asnOrg,
      ipHmac,
      correlationSecret,
      userAgent: input.userAgent,
      authenticatorId: input.authenticatorId ?? null,
    })
    .returning();

  if (!session) {
    throw new Error("Failed to create session");
  }

  return { session, token };
}

function normaliseCountry(country: string): string | null {
  if (!country || country === "unknown") return null;
  return country.toUpperCase().slice(0, 2);
}

/**
 * Resolve a cookie token to an active session, refreshing the sliding-idle
 * expiry on activity (throttled). Returns null if invalid, expired, or revoked.
 */
export async function validateSession(token: string): Promise<Session | null> {
  if (!token) return null;
  const tokenHash = await hashToken(token);
  const now = new Date();

  const [session] = await db
    .select()
    .from(sessions)
    .where(
      and(
        eq(sessions.tokenHash, tokenHash),
        isNull(sessions.revokedAt),
        gt(sessions.expiresAt, now),
        gt(sessions.absoluteExpiresAt, now),
      ),
    )
    .limit(1);

  if (!session) return null;

  // Throttled sliding refresh — write only if last_seen_at is stale enough.
  const lastSeen = session.lastSeenAt.getTime();
  if (now.getTime() - lastSeen > SESSION_REFRESH_THROTTLE_MS) {
    const newExpiresAt = new Date(
      Math.min(now.getTime() + SESSION_IDLE_MS, session.absoluteExpiresAt.getTime()),
    );
    await db
      .update(sessions)
      .set({ lastSeenAt: now, expiresAt: newExpiresAt })
      .where(eq(sessions.id, session.id));
    session.lastSeenAt = now;
    session.expiresAt = newExpiresAt;
  }

  return session;
}

export async function revokeSession(sessionId: string): Promise<void> {
  // Wipe correlation_secret + ip_hmac at revoke time (audit doc 19 §2.2,
  // ADR-0002). The row lingers ≤7d for audit visibility, but no derived
  // IP signal survives beyond the revoke moment.
  await db
    .update(sessions)
    .set({ revokedAt: new Date(), correlationSecret: null, ipHmac: null })
    .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt)));
}

export async function revokeAllSessionsForUser(userId: string): Promise<number> {
  const result = await db
    .update(sessions)
    .set({ revokedAt: new Date(), correlationSecret: null, ipHmac: null })
    .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
    .returning({ id: sessions.id });
  return result.length;
}

/**
 * Cookie attributes for the session cookie. In production the cookie name is
 * `__Host-session`, which mandates Secure + Path=/ + no Domain attribute
 * (RFC 6265bis §4.1.3.2). In dev we drop Secure so the cookie is accepted
 * over plain HTTP on localhost.
 */
export const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: env.IS_PRODUCTION,
  sameSite: "lax" as const,
  path: "/",
  // No Domain attribute — host-only.
} as const;

export function sessionCookieMaxAge(absoluteExpiresAt: Date): number {
  return Math.max(0, Math.floor((absoluteExpiresAt.getTime() - Date.now()) / 1000));
}

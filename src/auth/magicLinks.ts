// Magic-link token lifecycle: issue + consume. See docs/audit/18-auth-security-baseline.md §2.

import { and, eq, gt, isNull } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../db";
import { magicLinkTokens, type MagicLinkToken } from "../db/schema";
import { generateToken, hashToken, normaliseEmail } from "./tokens";

export const MAGIC_LINK_TTL_MS = 15 * 60 * 1000; // 15 minutes per ASVS 6.3.3

interface IssueMagicLinkInput {
  email: string;
  ip: string | null;
  userAgent: string | null;
}

interface IssueMagicLinkResult {
  token: string;
  expiresAt: Date;
}

export async function issueMagicLink(input: IssueMagicLinkInput): Promise<IssueMagicLinkResult> {
  const token = generateToken();
  const tokenHash = await hashToken(token);
  const expiresAt = new Date(Date.now() + MAGIC_LINK_TTL_MS);

  await db.insert(magicLinkTokens).values({
    id: nanoid(),
    email: normaliseEmail(input.email),
    tokenHash,
    expiresAt,
    ip: input.ip,
    userAgent: input.userAgent,
  });

  return { token, expiresAt };
}

interface ConsumeResult {
  ok: true;
  row: MagicLinkToken;
}

interface ConsumeFailure {
  ok: false;
  reason: "not_found" | "expired" | "consumed";
}

/**
 * Single-use consumption. Atomically marks the token consumed if and only if it
 * is currently unconsumed and unexpired. Returns the row on success.
 */
export async function consumeMagicLink(token: string): Promise<ConsumeResult | ConsumeFailure> {
  if (!token) return { ok: false, reason: "not_found" };
  const tokenHash = await hashToken(token);
  const now = new Date();

  // Look up first to distinguish reasons (for logging).
  const [row] = await db
    .select()
    .from(magicLinkTokens)
    .where(eq(magicLinkTokens.tokenHash, tokenHash))
    .limit(1);

  if (!row) return { ok: false, reason: "not_found" };
  if (row.consumedAt) return { ok: false, reason: "consumed" };
  if (row.expiresAt <= now) return { ok: false, reason: "expired" };

  // Atomic single-use: only succeed if not yet consumed.
  const consumed = await db
    .update(magicLinkTokens)
    .set({ consumedAt: now })
    .where(
      and(
        eq(magicLinkTokens.id, row.id),
        isNull(magicLinkTokens.consumedAt),
        gt(magicLinkTokens.expiresAt, now),
      ),
    )
    .returning();

  if (consumed.length === 0) {
    // Lost the race — another request consumed it between SELECT and UPDATE.
    return { ok: false, reason: "consumed" };
  }

  return { ok: true, row: { ...row, consumedAt: now } };
}

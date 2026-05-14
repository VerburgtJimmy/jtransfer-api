// Magic-link token lifecycle: issue + consume. See docs/audit/18-auth-security-baseline.md §2.
// Cross-device 6-digit code path: see audit doc 21 (smart-detection variant —
// the code is generated only when /verify is clicked on a device that does
// NOT carry the pending-login cookie, and is surfaced via URL fragment on a
// dedicated frontend page so it never lands in email or server logs).

import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../db";
import { magicLinkTokens, type MagicLinkToken } from "../db/schema";
import {
  constantTimeEqual,
  generateNumericCode,
  generateToken,
  hashToken,
  normaliseEmail,
} from "./tokens";

export const MAGIC_LINK_TTL_MS = 15 * 60 * 1000; // 15 minutes per ASVS 6.3.3

// Per audit doc 21 §4 — burn the row after this many wrong attempts on the
// code path. Honest typos get a small margin; brute force gets one row's
// worth of attempts before request-a-new-link is required.
export const CODE_MAX_ATTEMPTS = 3;

interface IssueMagicLinkInput {
  email: string;
  ip: string | null;
  userAgent: string | null;
}

interface IssueMagicLinkResult {
  token: string;
  pendingSessionId: string;
  expiresAt: Date;
}

export async function issueMagicLink(input: IssueMagicLinkInput): Promise<IssueMagicLinkResult> {
  const token = generateToken();
  const tokenHash = await hashToken(token);
  const pendingSessionId = nanoid();
  const expiresAt = new Date(Date.now() + MAGIC_LINK_TTL_MS);

  await db.insert(magicLinkTokens).values({
    id: nanoid(),
    email: normaliseEmail(input.email),
    tokenHash,
    pendingSessionId,
    // codeHash stays NULL — it's only minted on cross-device click in
    // claimMagicLinkOrIssueCode.
    expiresAt,
    ip: input.ip,
    userAgent: input.userAgent,
  });

  return { token, pendingSessionId, expiresAt };
}

interface ClaimSameDevice {
  ok: true;
  action: "signed_in";
  row: MagicLinkToken;
}

interface ClaimCrossDevice {
  ok: true;
  action: "code_issued";
  /** Plaintext code — display once, do not persist. */
  code: string;
  expiresAt: Date;
}

interface ClaimFailure {
  ok: false;
  reason: "not_found" | "expired" | "consumed" | "code_already_issued";
}

/**
 * Smart-detection magic-link click. Looks up the row by token hash, then
 * decides between sign-in-here and surface-a-code-for-the-other-device based
 * on whether the clicking device carries the matching pending-login cookie.
 *
 * Outcomes:
 * - Same device (cookie matches `pending_session_id`): atomically marks the
 *   row consumed and returns `action: "signed_in"`. Caller mints a session.
 * - Different device (cookie absent or mismatched): atomically sets the row's
 *   `code_hash`, returns the plaintext code via `action: "code_issued"`. The
 *   row remains unconsumed so the originating device can claim it through
 *   `/verify-code`. The link is one-shot for code issuance — re-clicking the
 *   same link from a non-matching device returns `code_already_issued`.
 */
export async function claimMagicLinkOrIssueCode(
  token: string,
  requestingPendingSessionId: string | null,
): Promise<ClaimSameDevice | ClaimCrossDevice | ClaimFailure> {
  if (!token) return { ok: false, reason: "not_found" };
  const tokenHash = await hashToken(token);
  const now = new Date();

  const [row] = await db
    .select()
    .from(magicLinkTokens)
    .where(eq(magicLinkTokens.tokenHash, tokenHash))
    .limit(1);

  if (!row) return { ok: false, reason: "not_found" };
  if (row.consumedAt) return { ok: false, reason: "consumed" };
  if (row.expiresAt <= now) return { ok: false, reason: "expired" };

  const sameDevice =
    typeof requestingPendingSessionId === "string" &&
    requestingPendingSessionId.length > 0 &&
    row.pendingSessionId === requestingPendingSessionId;

  if (sameDevice) {
    // Atomic single-use consume.
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

    if (consumed.length === 0) return { ok: false, reason: "consumed" };
    return { ok: true, action: "signed_in", row: { ...row, consumedAt: now } };
  }

  // Cross-device: mint the code once. Atomic guard: only succeed if code_hash
  // is still NULL — a second click on the same link gets the
  // already-issued-once error.
  const code = generateNumericCode();
  const codeHash = await hashToken(code);

  const issued = await db
    .update(magicLinkTokens)
    .set({ codeHash })
    .where(
      and(
        eq(magicLinkTokens.id, row.id),
        isNull(magicLinkTokens.consumedAt),
        isNull(magicLinkTokens.codeHash),
        gt(magicLinkTokens.expiresAt, now),
      ),
    )
    .returning({ id: magicLinkTokens.id });

  if (issued.length === 0) return { ok: false, reason: "code_already_issued" };
  return { ok: true, action: "code_issued", code, expiresAt: row.expiresAt };
}

interface ConsumeResult {
  ok: true;
  row: MagicLinkToken;
}

interface CodeFailure {
  ok: false;
  reason: "not_found" | "expired" | "consumed" | "wrong_code" | "burned";
}

/**
 * Cross-device code verification. The code is meaningless without the
 * matching pending-session cookie value, so we look up by `pendingSessionId`
 * and compare the candidate's hash with the stored hash in constant time.
 *
 * Attempt counter lives on the row: each wrong code increments `codeAttempts`;
 * reaching `CODE_MAX_ATTEMPTS` burns the row (sets `consumedAt`). Honest typos
 * within the margin are recoverable; brute force is bounded to one row of
 * attempts.
 *
 * Returns the row on success (and marks it consumed). Failures are intentionally
 * uniform in shape — call sites should not branch user-visible behaviour on
 * `reason`.
 */
export async function consumeMagicLinkByCode(
  code: string,
  pendingSessionId: string,
): Promise<ConsumeResult | CodeFailure> {
  if (!code || !pendingSessionId) return { ok: false, reason: "not_found" };
  const now = new Date();

  const [row] = await db
    .select()
    .from(magicLinkTokens)
    .where(eq(magicLinkTokens.pendingSessionId, pendingSessionId))
    .limit(1);

  if (!row) return { ok: false, reason: "not_found" };
  if (row.consumedAt) return { ok: false, reason: "consumed" };
  if (row.expiresAt <= now) return { ok: false, reason: "expired" };
  // No code has been issued yet for this pending session — the user must
  // click the link on a different device first.
  if (!row.codeHash) return { ok: false, reason: "not_found" };

  const candidateHash = await hashToken(code);
  const matches = constantTimeEqual(candidateHash, row.codeHash);

  if (!matches) {
    // Atomically increment attempts, guarded against an already-consumed row.
    // .returning() gives us the post-increment count so the burn decision
    // is race-safe — concurrent increments are serialised by the row lock,
    // and each caller sees a distinct attempt number. (The single-statement
    // CASE form fails parameter binding under postgres-js when a Date
    // sits inside the CASE arm; splitting the burn into its own statement
    // sidesteps the type-inference loss.)
    const [updated] = await db
      .update(magicLinkTokens)
      .set({ codeAttempts: sql`${magicLinkTokens.codeAttempts} + 1` })
      .where(
        and(
          eq(magicLinkTokens.id, row.id),
          isNull(magicLinkTokens.consumedAt),
        ),
      )
      .returning({ codeAttempts: magicLinkTokens.codeAttempts });

    if (!updated) {
      // Row was consumed (likely burned by a parallel request) before we
      // could increment — surface as consumed, same uniform failure to the
      // caller.
      return { ok: false, reason: "consumed" };
    }

    if (updated.codeAttempts >= CODE_MAX_ATTEMPTS) {
      // Burn. Re-guard on `consumed_at IS NULL` so a racing burn doesn't
      // overwrite an earlier sibling's timestamp.
      await db
        .update(magicLinkTokens)
        .set({ consumedAt: now })
        .where(
          and(
            eq(magicLinkTokens.id, row.id),
            isNull(magicLinkTokens.consumedAt),
          ),
        );
      return { ok: false, reason: "burned" };
    }

    return { ok: false, reason: "wrong_code" };
  }

  // Correct code — claim the row atomically.
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
    return { ok: false, reason: "consumed" };
  }

  return { ok: true, row: { ...row, consumedAt: now } };
}

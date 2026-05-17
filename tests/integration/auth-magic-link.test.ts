// Phase E (cross-device magic-link code, smart-detection variant) — direct
// helper coverage. See docs/audit/21-cross-device-magic-link-code.md §13.
//
// These tests exercise the magic-link state machine at the helper level
// (no HTTP), which is the layer that owns the atomic single-shot guards.
// HTTP coverage (cookie wiring, timing floors) is intentionally out of
// scope here — the helpers are the part that can race in production.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { db } from "../../src/db";
import { magicLinkTokens } from "../../src/db/schema";
import {
  CODE_MAX_ATTEMPTS,
  MAGIC_LINK_TTL_MS,
  claimMagicLinkOrIssueCode,
  consumeMagicLinkByCode,
  issueMagicLink,
} from "../../src/auth/magicLinks";
import { ensureMigrations, resetDb } from "../helpers/db";

beforeAll(async () => {
  await ensureMigrations();
});

beforeEach(async () => {
  await resetDb();
});

afterAll(async () => {
  await resetDb();
});

async function issue(email = "alice@example.test") {
  return issueMagicLink({
    email,
    userAgent: "bun-test",
  });
}

async function loadRow(pendingSessionId: string) {
  const [row] = await db
    .select()
    .from(magicLinkTokens)
    .where(eq(magicLinkTokens.pendingSessionId, pendingSessionId))
    .limit(1);
  return row;
}

// ─── issueMagicLink ───────────────────────────────────────────────────────

describe("issueMagicLink", () => {
  it("returns a token, pending session id, and TTL-aligned expiry", async () => {
    const before = Date.now();
    const { token, pendingSessionId, expiresAt } = await issue();
    const after = Date.now();

    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pendingSessionId).toHaveLength(21);
    // Expiry is approximately MAGIC_LINK_TTL_MS from issue time.
    expect(expiresAt.getTime()).toBeGreaterThanOrEqual(before + MAGIC_LINK_TTL_MS - 1000);
    expect(expiresAt.getTime()).toBeLessThanOrEqual(after + MAGIC_LINK_TTL_MS + 1000);
  });

  it("persists the row with code_hash NULL and code_attempts = 0", async () => {
    const { pendingSessionId } = await issue();
    const row = await loadRow(pendingSessionId);
    expect(row).toBeDefined();
    expect(row.codeHash).toBeNull();
    expect(row.codeAttempts).toBe(0);
    expect(row.consumedAt).toBeNull();
    expect(row.tokenHash).toHaveLength(64);
  });

  it("normalises the email to lowercase + trimmed", async () => {
    const { pendingSessionId } = await issueMagicLink({
      email: "  MIXED.Case@Example.test  ",
      userAgent: null,
    });
    const row = await loadRow(pendingSessionId);
    expect(row.email).toBe("mixed.case@example.test");
  });
});

// ─── claimMagicLinkOrIssueCode — same device ──────────────────────────────

describe("claimMagicLinkOrIssueCode — same device", () => {
  it("consumes the row when the requesting pendingSessionId matches", async () => {
    const { token, pendingSessionId } = await issue();

    const result = await claimMagicLinkOrIssueCode(token, pendingSessionId);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.action).toBe("signed_in");
    }

    const row = await loadRow(pendingSessionId);
    expect(row.consumedAt).not.toBeNull();
    // Code path stays untouched on the same-device branch.
    expect(row.codeHash).toBeNull();
  });

  it("rejects a second same-device claim as consumed", async () => {
    const { token, pendingSessionId } = await issue();
    await claimMagicLinkOrIssueCode(token, pendingSessionId);

    const second = await claimMagicLinkOrIssueCode(token, pendingSessionId);
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.reason).toBe("consumed");
    }
  });
});

// ─── claimMagicLinkOrIssueCode — cross device ─────────────────────────────

describe("claimMagicLinkOrIssueCode — cross device", () => {
  it("mints a 6-digit code without consuming the row when cookie is absent", async () => {
    const { token, pendingSessionId } = await issue();

    const result = await claimMagicLinkOrIssueCode(token, null);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.action).toBe("code_issued");
      if (result.action === "code_issued") {
        expect(result.code).toMatch(/^\d{6}$/);
      }
    }

    const row = await loadRow(pendingSessionId);
    expect(row.codeHash).not.toBeNull();
    expect(row.codeHash).toHaveLength(64);
    expect(row.consumedAt).toBeNull();
  });

  it("treats a mismatched pendingSessionId as cross-device", async () => {
    const { token, pendingSessionId } = await issue();

    const result = await claimMagicLinkOrIssueCode(token, "not-the-right-id");

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.action).toBe("code_issued");
    const row = await loadRow(pendingSessionId);
    expect(row.codeHash).not.toBeNull();
  });

  it("returns code_already_issued on a second cross-device click", async () => {
    const { token, pendingSessionId } = await issue();
    const first = await claimMagicLinkOrIssueCode(token, null);
    expect(first.ok).toBe(true);

    const second = await claimMagicLinkOrIssueCode(token, null);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe("code_already_issued");

    const row = await loadRow(pendingSessionId);
    expect(row.codeHash).not.toBeNull();
  });

  it("originator can still claim by clicking the link after code was minted", async () => {
    const { token, pendingSessionId } = await issue();
    // Code issued to a different device first…
    const issued = await claimMagicLinkOrIssueCode(token, null);
    expect(issued.ok).toBe(true);

    // …then the originator clicks their own link. Row is still unconsumed.
    const claim = await claimMagicLinkOrIssueCode(token, pendingSessionId);
    expect(claim.ok).toBe(true);
    if (claim.ok) expect(claim.action).toBe("signed_in");

    const row = await loadRow(pendingSessionId);
    expect(row.consumedAt).not.toBeNull();
  });
});

// ─── claimMagicLinkOrIssueCode — failure modes ────────────────────────────

describe("claimMagicLinkOrIssueCode — failures", () => {
  it("returns not_found for an unknown token", async () => {
    const result = await claimMagicLinkOrIssueCode("not-a-real-token", null);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("not_found");
  });

  it("returns not_found for an empty token", async () => {
    const result = await claimMagicLinkOrIssueCode("", null);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("not_found");
  });

  it("returns expired for a token past its TTL", async () => {
    const { token, pendingSessionId } = await issue();
    // Push expiry into the past.
    await db
      .update(magicLinkTokens)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(magicLinkTokens.pendingSessionId, pendingSessionId));

    const result = await claimMagicLinkOrIssueCode(token, pendingSessionId);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("expired");
  });
});

// ─── consumeMagicLinkByCode — happy path ──────────────────────────────────

describe("consumeMagicLinkByCode — happy path", () => {
  it("consumes the row when the code matches the pending session", async () => {
    const { token, pendingSessionId } = await issue();
    const issued = await claimMagicLinkOrIssueCode(token, null);
    expect(issued.ok).toBe(true);
    if (!issued.ok || issued.action !== "code_issued") throw new Error("setup failed");

    const result = await consumeMagicLinkByCode(issued.code, pendingSessionId);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.row.email).toBeDefined();
    }

    const row = await loadRow(pendingSessionId);
    expect(row.consumedAt).not.toBeNull();
  });

  it("accepts the canonicalised code (callers should pre-canonicalise)", async () => {
    const { token, pendingSessionId } = await issue();
    const issued = await claimMagicLinkOrIssueCode(token, null);
    if (!issued.ok || issued.action !== "code_issued") throw new Error("setup failed");

    // Callers (the HTTP handler) run canonicaliseCode first; this helper
    // only sees the clean 6-digit string. Confirm exact-match behaviour.
    const result = await consumeMagicLinkByCode(issued.code, pendingSessionId);
    expect(result.ok).toBe(true);
  });
});

// ─── consumeMagicLinkByCode — failure modes ───────────────────────────────

describe("consumeMagicLinkByCode — failures", () => {
  it("returns not_found when the pending session has never had a code issued", async () => {
    const { pendingSessionId } = await issue();
    const result = await consumeMagicLinkByCode("000000", pendingSessionId);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("not_found");
  });

  it("returns not_found for an unknown pending session", async () => {
    const result = await consumeMagicLinkByCode("000000", "no-such-pending-session");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("not_found");
  });

  it("returns wrong_code on a typo and increments code_attempts", async () => {
    const { token, pendingSessionId } = await issue();
    const issued = await claimMagicLinkOrIssueCode(token, null);
    if (!issued.ok || issued.action !== "code_issued") throw new Error("setup failed");

    // Pick a code that's guaranteed to differ from the issued one.
    const wrong = issued.code === "111111" ? "222222" : "111111";
    const result = await consumeMagicLinkByCode(wrong, pendingSessionId);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("wrong_code");

    const row = await loadRow(pendingSessionId);
    expect(row.codeAttempts).toBe(1);
    expect(row.consumedAt).toBeNull();
  });

  it("burns the row after CODE_MAX_ATTEMPTS wrong codes", async () => {
    const { token, pendingSessionId } = await issue();
    const issued = await claimMagicLinkOrIssueCode(token, null);
    if (!issued.ok || issued.action !== "code_issued") throw new Error("setup failed");

    const wrong = issued.code === "111111" ? "222222" : "111111";

    let lastReason: string | undefined;
    for (let i = 0; i < CODE_MAX_ATTEMPTS; i++) {
      const r = await consumeMagicLinkByCode(wrong, pendingSessionId);
      expect(r.ok).toBe(false);
      if (!r.ok) lastReason = r.reason;
    }

    // The last attempt should be the burn — same statement marks consumed.
    expect(lastReason).toBe("burned");

    const row = await loadRow(pendingSessionId);
    expect(row.codeAttempts).toBe(CODE_MAX_ATTEMPTS);
    expect(row.consumedAt).not.toBeNull();
  });

  it("rejects the correct code after the row was burned", async () => {
    const { token, pendingSessionId } = await issue();
    const issued = await claimMagicLinkOrIssueCode(token, null);
    if (!issued.ok || issued.action !== "code_issued") throw new Error("setup failed");

    const wrong = issued.code === "111111" ? "222222" : "111111";
    for (let i = 0; i < CODE_MAX_ATTEMPTS; i++) {
      await consumeMagicLinkByCode(wrong, pendingSessionId);
    }

    const result = await consumeMagicLinkByCode(issued.code, pendingSessionId);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("consumed");
  });

  it("returns expired when the code is correct but the row is past its TTL", async () => {
    const { token, pendingSessionId } = await issue();
    const issued = await claimMagicLinkOrIssueCode(token, null);
    if (!issued.ok || issued.action !== "code_issued") throw new Error("setup failed");

    await db
      .update(magicLinkTokens)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(magicLinkTokens.pendingSessionId, pendingSessionId));

    const result = await consumeMagicLinkByCode(issued.code, pendingSessionId);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("expired");
  });

  it("rejects missing inputs without touching the row", async () => {
    const { pendingSessionId } = await issue();
    const empty = await consumeMagicLinkByCode("", pendingSessionId);
    expect(empty.ok).toBe(false);

    const noSession = await consumeMagicLinkByCode("123456", "");
    expect(noSession.ok).toBe(false);

    const row = await loadRow(pendingSessionId);
    expect(row.codeAttempts).toBe(0);
  });
});

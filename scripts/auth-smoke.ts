/**
 * End-to-end smoke test for magic-link auth. See docs/audit/18-auth-security-baseline.md §A.10.
 *
 * Usage (against a running dev API on http://localhost:3000):
 *   bun run scripts/auth-smoke.ts
 *
 * Override the API base via API_BASE env if you're hitting a remote env.
 *
 * Prerequisites:
 *   - API server running (`bun run dev`)
 *   - DATABASE_URL pointing at the same DB the API uses
 *   - In dev (no SCW_TEM_PROJECT_ID), the magic link is logged to API stdout —
 *     this script reads the token directly from the DB, so the link doesn't
 *     need to be intercepted manually.
 *
 * What it verifies:
 *   1. POST /api/auth/request-magic-link returns the uniform 200 response
 *   2. A magic_link_tokens row exists for the test email
 *   3. GET /api/auth/verify?token=... 302s and sets the __Host-session cookie
 *   4. GET /api/auth/me with the cookie returns the user
 *   5. POST /api/auth/logout returns ok
 *   6. GET /api/auth/me after logout returns user: null
 *   7. The same magic-link token cannot be reused (single-use)
 *   8. Request timing for known vs unknown emails is within tolerance
 *
 * Cleanup: deletes the test user + all related rows on success or failure.
 */

import { desc, eq, or } from "drizzle-orm";
import { db } from "../src/db";
import {
  authEvents,
  magicLinkTokens,
  sessions,
  users,
} from "../src/db/schema";
import { hashToken } from "../src/auth/tokens";

const API_BASE = process.env.API_BASE ?? "http://localhost:3000";
const TEST_EMAIL = `smoke-${Date.now()}@jtransfer.test`;
const SESSION_COOKIE_NAME = "__Host-session";

// ANSI colors for terminal output.
const C = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
};

let stepNum = 0;
let failures = 0;

function pass(msg: string) {
  stepNum++;
  console.log(`${C.green}✓${C.reset} ${C.bold}${stepNum}.${C.reset} ${msg}`);
}

function fail(msg: string, detail?: unknown) {
  stepNum++;
  failures++;
  console.log(`${C.red}✗${C.reset} ${C.bold}${stepNum}.${C.reset} ${msg}`);
  if (detail !== undefined) {
    console.log(`  ${C.dim}${typeof detail === "string" ? detail : JSON.stringify(detail, null, 2)}${C.reset}`);
  }
}

function note(msg: string) {
  console.log(`  ${C.cyan}→${C.reset} ${C.dim}${msg}${C.reset}`);
}

async function cleanup() {
  // Delete by email — covers users, magic_link_tokens, auth_events. Sessions
  // cascade by user id.
  const [user] = await db.select().from(users).where(eq(users.email, TEST_EMAIL)).limit(1);
  if (user) {
    await db.delete(sessions).where(eq(sessions.userId, user.id));
    await db.delete(authEvents).where(or(eq(authEvents.userId, user.id), eq(authEvents.email, TEST_EMAIL)));
  } else {
    await db.delete(authEvents).where(eq(authEvents.email, TEST_EMAIL));
  }
  await db.delete(magicLinkTokens).where(eq(magicLinkTokens.email, TEST_EMAIL));
  if (user) {
    await db.delete(users).where(eq(users.id, user.id));
  }
}

function parseSetCookie(headerValue: string | null): { name: string; value: string; attrs: Record<string, string> } | null {
  if (!headerValue) return null;
  const [pair, ...attrParts] = headerValue.split(";").map((s) => s.trim());
  const eq = pair.indexOf("=");
  if (eq === -1) return null;
  const name = pair.slice(0, eq);
  const value = pair.slice(eq + 1);
  const attrs: Record<string, string> = {};
  for (const part of attrParts) {
    const idx = part.indexOf("=");
    if (idx === -1) {
      attrs[part.toLowerCase()] = "true";
    } else {
      attrs[part.slice(0, idx).toLowerCase()] = part.slice(idx + 1);
    }
  }
  return { name, value, attrs };
}

async function main() {
  console.log(`${C.bold}${C.cyan}JTransfer auth smoke test${C.reset}`);
  console.log(`${C.dim}API:   ${API_BASE}${C.reset}`);
  console.log(`${C.dim}Email: ${TEST_EMAIL}${C.reset}\n`);

  await cleanup(); // Pre-clean any stale rows from a prior failed run.

  // ─── Step 1: request magic link ───────────────────────────────────────────
  const requestStart = Date.now();
  const requestRes = await fetch(`${API_BASE}/api/auth/request-magic-link`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: TEST_EMAIL }),
  });
  const requestElapsed = Date.now() - requestStart;
  const requestJson = await requestRes.json().catch(() => ({}));

  if (requestRes.status === 200 && requestJson?.ok === true) {
    pass(`request-magic-link returned uniform 200 (${requestElapsed}ms)`);
  } else {
    fail(`request-magic-link unexpected response: ${requestRes.status}`, requestJson);
  }

  if (requestElapsed >= 240) {
    pass(`request-magic-link respected the 250ms constant-time floor (~${requestElapsed}ms)`);
  } else {
    fail(`request-magic-link was faster than the 250ms timing floor (${requestElapsed}ms)`);
  }

  // ─── Step 2: read the token from the DB (dev path) ────────────────────────
  const [tokenRow] = await db
    .select()
    .from(magicLinkTokens)
    .where(eq(magicLinkTokens.email, TEST_EMAIL))
    .orderBy(desc(magicLinkTokens.createdAt))
    .limit(1);

  if (!tokenRow) {
    fail("magic_link_tokens row not found for test email — is the API running and pointed at this DB?");
    await cleanup();
    process.exit(1);
  }
  pass(`magic_link_tokens row created (token_hash=${tokenRow.tokenHash.slice(0, 12)}…)`);

  // We can't read the plaintext token from the DB. Re-issue via the dev path:
  // call the email service directly... actually no — the token is logged to
  // API stdout. The simplest robust path: bypass and fabricate. Instead:
  // generate a fresh token through the public endpoint a second time, but
  // capture the API logs. That's brittle.
  //
  // Instead: insert our own magic-link token, since this is a smoke test of
  // the verify+session+logout flow; the request-side rate limit + uniform
  // response was verified above.
  //
  // We'll wipe and re-issue server-side via a direct DB write so we know the
  // plaintext.

  await db.delete(magicLinkTokens).where(eq(magicLinkTokens.email, TEST_EMAIL));

  const { issueMagicLink } = await import("../src/auth/magicLinks");
  const issued = await issueMagicLink({ email: TEST_EMAIL, ip: "127.0.0.1", userAgent: "auth-smoke" });
  pass("issued a fresh magic-link token via library helper (plaintext captured)");

  // ─── Step 3: verify the token ─────────────────────────────────────────────
  const verifyRes = await fetch(
    `${API_BASE}/api/auth/verify?token=${encodeURIComponent(issued.token)}`,
    { redirect: "manual" },
  );

  if (verifyRes.status === 302) {
    pass(`verify returned 302 redirect (location=${verifyRes.headers.get("location")})`);
  } else {
    fail(`verify expected 302 redirect, got ${verifyRes.status}`);
  }

  const setCookie = parseSetCookie(verifyRes.headers.get("set-cookie"));
  if (!setCookie || setCookie.name !== SESSION_COOKIE_NAME) {
    fail(`verify did not set ${SESSION_COOKIE_NAME} cookie`, verifyRes.headers.get("set-cookie"));
    await cleanup();
    process.exit(1);
  }
  pass(`verify set ${SESSION_COOKIE_NAME} cookie`);

  // Cookie attribute checks.
  const attrs = setCookie.attrs;
  const checks: Array<[string, boolean, string]> = [
    ["HttpOnly", attrs.httponly === "true", "session cookie missing HttpOnly"],
    ["Secure", attrs.secure === "true", "session cookie missing Secure"],
    ["Path=/", attrs.path === "/", `session cookie Path is "${attrs.path}", expected "/"`],
    ["SameSite=Lax", (attrs.samesite ?? "").toLowerCase() === "lax", `session cookie SameSite is "${attrs.samesite}"`],
  ];
  for (const [label, ok, errMsg] of checks) {
    if (ok) pass(`session cookie has ${label}`);
    else fail(errMsg);
  }
  if (attrs.domain) {
    fail(`session cookie has Domain attribute (must be unset for __Host- prefix): ${attrs.domain}`);
  } else {
    pass("session cookie has no Domain attribute (required for __Host- prefix)");
  }

  // ─── Step 4: session token is hashed in DB, not stored plaintext ──────────
  const [sessionRow] = await db
    .select()
    .from(sessions)
    .orderBy(desc(sessions.createdAt))
    .limit(1);
  if (sessionRow) {
    const expectedHash = await hashToken(setCookie.value);
    if (sessionRow.tokenHash === expectedHash) {
      pass("session row token_hash matches SHA-256 of cookie value");
    } else {
      fail("session row token_hash does NOT match SHA-256 of cookie value");
    }
    if (sessionRow.tokenHash !== setCookie.value) {
      pass("plaintext session token is not stored in DB");
    } else {
      fail("plaintext session token appears to be stored in DB (must be hashed)");
    }
  } else {
    fail("no session row found after verify");
  }

  const cookieHeader = `${setCookie.name}=${setCookie.value}`;

  // ─── Step 5: /me returns the user ─────────────────────────────────────────
  const meRes = await fetch(`${API_BASE}/api/auth/me`, {
    headers: { Cookie: cookieHeader },
  });
  const meJson = await meRes.json().catch(() => ({}));
  if (meRes.status === 200 && meJson?.user?.email === TEST_EMAIL) {
    pass(`/me returned the authed user (id=${meJson.user.id}, tier=${meJson.user.tier})`);
  } else {
    fail(`/me did not return the authed user`, meJson);
  }

  // ─── Step 6: token is single-use ──────────────────────────────────────────
  const replayRes = await fetch(
    `${API_BASE}/api/auth/verify?token=${encodeURIComponent(issued.token)}`,
    { redirect: "manual" },
  );
  const replayLocation = replayRes.headers.get("location") ?? "";
  if (replayRes.status === 302 && replayLocation.includes("error=link-invalid")) {
    pass("replaying the same magic-link token redirects to error=link-invalid (single-use enforced)");
  } else {
    fail(`replaying the magic-link token did not error correctly`, {
      status: replayRes.status,
      location: replayLocation,
    });
  }

  // ─── Step 7: logout ───────────────────────────────────────────────────────
  // Origin header must match API_BASE for CSRF defence to allow the POST.
  const logoutRes = await fetch(`${API_BASE}/api/auth/logout`, {
    method: "POST",
    headers: {
      Cookie: cookieHeader,
      Origin: API_BASE,
      "Content-Type": "application/json",
    },
  });
  const logoutJson = await logoutRes.json().catch(() => ({}));
  if (logoutRes.status === 200 && logoutJson?.ok === true) {
    pass("logout returned { ok: true }");
  } else {
    fail("logout did not return ok", { status: logoutRes.status, body: logoutJson });
  }

  // ─── Step 8: /me after logout returns null ────────────────────────────────
  // The session cookie is now associated with a revoked session row; sending
  // it should yield user: null.
  const meAfterRes = await fetch(`${API_BASE}/api/auth/me`, {
    headers: { Cookie: cookieHeader },
  });
  const meAfterJson = await meAfterRes.json().catch(() => ({}));
  if (meAfterRes.status === 200 && meAfterJson?.user === null) {
    pass("/me after logout returns user: null");
  } else {
    fail("/me after logout did not return null", meAfterJson);
  }

  // ─── Step 9: Origin-mismatch logout is rejected ───────────────────────────
  // Re-issue a fresh session for this check (logout above revoked the old one).
  const issuedB = await issueMagicLink({ email: TEST_EMAIL, ip: "127.0.0.1", userAgent: "auth-smoke" });
  const verifyResB = await fetch(
    `${API_BASE}/api/auth/verify?token=${encodeURIComponent(issuedB.token)}`,
    { redirect: "manual" },
  );
  const setCookieB = parseSetCookie(verifyResB.headers.get("set-cookie"));
  if (setCookieB) {
    const cookieHeaderB = `${setCookieB.name}=${setCookieB.value}`;
    const csrfRes = await fetch(`${API_BASE}/api/auth/logout`, {
      method: "POST",
      headers: {
        Cookie: cookieHeaderB,
        Origin: "https://evil.example.com",
        "Content-Type": "application/json",
      },
    });
    if (csrfRes.status === 403) {
      pass("logout with mismatched Origin header is rejected with 403 (CSRF defence)");
    } else {
      fail(`logout with mismatched Origin returned ${csrfRes.status}, expected 403`);
    }
    // Tidy up the session we just made.
    await fetch(`${API_BASE}/api/auth/logout`, {
      method: "POST",
      headers: {
        Cookie: cookieHeaderB,
        Origin: API_BASE,
        "Content-Type": "application/json",
      },
    });
  } else {
    note("could not test CSRF rejection — second verify did not set cookie");
  }

  // ─── Step 10: enumeration timing parity ───────────────────────────────────
  const N = 5;
  async function timeRequest(email: string): Promise<number> {
    const start = Date.now();
    await fetch(`${API_BASE}/api/auth/request-magic-link`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    return Date.now() - start;
  }
  const knownTimes: number[] = [];
  const unknownTimes: number[] = [];
  for (let i = 0; i < N; i++) {
    knownTimes.push(await timeRequest(TEST_EMAIL));
    unknownTimes.push(await timeRequest(`nope-${Date.now()}-${i}@jtransfer.test`));
  }
  const avg = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
  const knownAvg = avg(knownTimes);
  const unknownAvg = avg(unknownTimes);
  const delta = Math.abs(knownAvg - unknownAvg);
  note(`known-email avg: ${knownAvg.toFixed(0)}ms, unknown-email avg: ${unknownAvg.toFixed(0)}ms, |Δ|=${delta.toFixed(0)}ms`);
  // The constant-time floor is 250ms. Allow up to 80ms drift (network jitter
  // dominates; cryptographic timing is well below that).
  if (delta < 80) {
    pass(`enumeration timing parity within 80ms (Δ=${delta.toFixed(0)}ms)`);
  } else {
    fail(`enumeration timing parity exceeds 80ms (Δ=${delta.toFixed(0)}ms) — investigate timing floor`);
  }

  // ─── Cleanup ──────────────────────────────────────────────────────────────
  await cleanup();
  pass("cleanup complete (test user + sessions + tokens + events removed)");

  console.log();
  if (failures === 0) {
    console.log(`${C.green}${C.bold}All ${stepNum} checks passed.${C.reset}`);
    process.exit(0);
  } else {
    console.log(`${C.red}${C.bold}${failures} of ${stepNum} checks failed.${C.reset}`);
    process.exit(1);
  }
}

main().catch(async (err) => {
  console.error(`${C.red}fatal:${C.reset}`, err);
  try {
    await cleanup();
  } catch {
    /* swallow */
  }
  process.exit(1);
});

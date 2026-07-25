// POST /api/auth/verify: the fragment-based magic-link redemption path.
//
// The emailed link now points at /signin/verify#token=..., so the token never
// appears in a URL the server or CDN edge observes, and a mail scanner that
// prefetches the link cannot consume it. The SPA reads the fragment and POSTs
// here. Covers same-device sign-in, cross-device code issuance, the generic
// failure shape, and the Origin guard.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { createApp } from "../../src/app";
import { issueMagicLink } from "../../src/auth/magicLinks";
import { SESSION_COOKIE_NAME } from "../../src/auth/sessions";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const PENDING_COOKIE = "__Host-pending-login";

let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});

beforeEach(async () => {
  await resetDb();
});

afterAll(async () => {
  await resetDb();
});

function post(token: unknown, opts: { cookie?: string; origin?: string } = {}) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Origin: opts.origin ?? APP_URL,
  };
  if (opts.cookie) headers.Cookie = opts.cookie;
  return app.handle(
    new Request(`${APP_URL}/api/auth/verify`, {
      method: "POST",
      headers,
      body: JSON.stringify({ token }),
    }),
  );
}

async function issue(email = "alice@example.test") {
  return issueMagicLink({ email, userAgent: "test-agent" });
}

// ─── 1. Same device ─────────────────────────────────────────────────────────

describe("POST /api/auth/verify, same device", () => {
  it("signs in and sets the session cookie when the pending cookie matches", async () => {
    const { token, pendingSessionId } = await issue();

    const res = await post(token, { cookie: `${PENDING_COOKIE}=${pendingSessionId}` });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ action: "signed_in" });
    expect(res.headers.get("set-cookie")).toContain(`${SESSION_COOKIE_NAME}=`);
  });

  it("rejects a replay of the same token", async () => {
    const { token, pendingSessionId } = await issue();
    const cookie = `${PENDING_COOKIE}=${pendingSessionId}`;

    const first = await post(token, { cookie });
    expect(first.status).toBe(200);

    const second = await post(token, { cookie });
    expect(second.status).toBe(400);
    expect(await second.json()).toEqual({ error: "link-invalid" });
  });
});

// ─── 2. Cross device ────────────────────────────────────────────────────────

describe("POST /api/auth/verify, cross device", () => {
  it("issues a 6-digit code and does NOT sign in when the pending cookie is absent", async () => {
    const { token } = await issue();

    const res = await post(token);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { action: string; code: string; expiresIn: number };
    expect(body.action).toBe("code_issued");
    expect(body.code).toMatch(/^\d{6}$/);
    expect(body.expiresIn).toBeGreaterThan(0);
    // Critically: a token alone must never mint a session.
    expect(res.headers.get("set-cookie") ?? "").not.toContain(`${SESSION_COOKIE_NAME}=`);
  });

  it("treats a mismatched pending cookie as cross-device", async () => {
    const { token } = await issue();

    const res = await post(token, { cookie: `${PENDING_COOKIE}=not-the-right-id` });

    expect(res.status).toBe(200);
    expect((await res.json()).action).toBe("code_issued");
  });

  it("refuses a second cross-device click once the code exists", async () => {
    const { token } = await issue();

    expect((await post(token)).status).toBe(200);

    const second = await post(token);
    expect(second.status).toBe(400);
    expect(await second.json()).toEqual({ error: "link-invalid" });
  });
});

// ─── 3. Failure shape and Origin guard ──────────────────────────────────────

describe("POST /api/auth/verify, rejections", () => {
  it("collapses an unknown token to the same generic error", async () => {
    const res = await post("a".repeat(43));

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "link-invalid" });
  });

  it("rejects an empty token without leaking the reason", async () => {
    const res = await post("");

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "link-invalid" });
  });

  it("rejects a cross-origin POST with 403", async () => {
    const { token, pendingSessionId } = await issue();

    const res = await post(token, {
      cookie: `${PENDING_COOKIE}=${pendingSessionId}`,
      origin: "https://evil.example.com",
    });

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Forbidden" });
  });

  it("rejects an over-long token via schema validation", async () => {
    const res = await post("x".repeat(300));

    expect(res.status).toBe(400);
  });
});

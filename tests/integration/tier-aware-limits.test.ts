// Tier-aware caps and the /api/me/usage endpoint per ADR-0006.
//
// Verifies:
//   - Free/Anonymous expiry options stay capped at ≤72h (`expiresInHours`
//     ∉ [1,6,12,24,72] → 400 with `expiry_not_allowed_for_tier`).
//   - Pro accepts the longer-retention options (168h / 336h / 720h).
//   - `/api/me/usage` returns tier-resolved caps and the correct shape
//     for both Free and Pro.
//
// Volume-counter enforcement (the 2 GB vs 100 GB cap actually firing)
// shares Redis/memory state across the test process, so it's covered
// in the existing volume-limit tests rather than re-asserted here.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { users } from "../../src/db/schema";
import { authedRequest, createAuthedUser } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const ORIGIN_HEADER = { Origin: APP_URL, "Content-Type": "application/json" };

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

function jsonBody<T extends object>(body: T): RequestInit {
  return { method: "POST", headers: ORIGIN_HEADER, body: JSON.stringify(body) };
}

const GB = 1024 * 1024 * 1024;

// ─── Expiry options per tier ─────────────────────────────────────────────────

describe("create-transfer — tier-aware expiry options", () => {
  it("anonymous request: 72h allowed", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({ expiresInHours: 72 })),
    );
    expect(res.status).toBe(200);
  });

  it("anonymous request: 168h (7d) rejected with upgrade code", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({ expiresInHours: 168 })),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; code?: string; upgradeUrl?: string };
    expect(body.code).toBe("expiry_not_allowed_for_tier");
    expect(body.upgradeUrl).toBe("/pricing");
  });

  it("authed Free user: 168h (7d) rejected", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 168 }),
      ),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string };
    expect(body.code).toBe("expiry_not_allowed_for_tier");
  });

  it("authed Pro user: 168h (7d) accepted", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));

    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 168 }),
      ),
    );
    expect(res.status).toBe(200);
  });

  it("authed Pro user: 720h (30d) accepted", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));

    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 720 }),
      ),
    );
    expect(res.status).toBe(200);
  });

  it("authed Pro user: 999h (not in allow-list) rejected", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));

    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 999 }),
      ),
    );
    expect(res.status).toBe(400);
  });

  it("unknown tier value falls back to Free caps (fail-closed)", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "garbage" }).where(eq(users.id, user.id));

    // 168h should be rejected because unknown tier resolves to Free.
    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 168 }),
      ),
    );
    expect(res.status).toBe(400);
  });
});

// ─── /api/me/usage ───────────────────────────────────────────────────────────

interface UsageResponse {
  tier: string;
  monthlyVolume: { usedBytes: number; capBytes: number; resetAt: string };
  dailyTransfers: { used: number; cap: number; resetAt: string };
  caps: { maxFileSize: number; maxTransferSize: number; allowedExpiryHours: number[] };
}

describe("GET /api/me/usage", () => {
  it("401 when not authenticated", async () => {
    const res = await app.handle(new Request(`${APP_URL}/api/me/usage`));
    expect(res.status).toBe(401);
  });

  it("returns Free caps for a default user", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/usage`, { method: "GET" }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as UsageResponse;

    expect(body.tier).toBe("free");
    expect(body.monthlyVolume.capBytes).toBe(2 * GB);
    expect(body.dailyTransfers.cap).toBe(20);
    expect(body.caps.maxFileSize).toBe(1 * GB);
    expect(body.caps.maxTransferSize).toBe(1 * GB);
    expect(body.caps.allowedExpiryHours).toEqual([1, 6, 12, 24, 72]);
  });

  it("returns Pro caps when tier='pro'", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/usage`, { method: "GET" }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as UsageResponse;

    expect(body.tier).toBe("pro");
    expect(body.monthlyVolume.capBytes).toBe(100 * GB);
    expect(body.dailyTransfers.cap).toBe(100);
    expect(body.caps.maxFileSize).toBe(2 * GB);
    expect(body.caps.maxTransferSize).toBe(2 * GB);
    expect(body.caps.allowedExpiryHours).toContain(168);
    expect(body.caps.allowedExpiryHours).toContain(720);
  });

  it("usedBytes and used start at non-negative integers", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/usage`, { method: "GET" }),
    );
    const body = (await res.json()) as UsageResponse;

    // The exact value depends on prior state in the shared limiter
    // (memory in tests; we don't reset between processes). The
    // contract is: non-negative integers, and reset timestamps in
    // the future.
    expect(body.monthlyVolume.usedBytes).toBeGreaterThanOrEqual(0);
    expect(body.dailyTransfers.used).toBeGreaterThanOrEqual(0);
    expect(new Date(body.monthlyVolume.resetAt).getTime()).toBeGreaterThan(Date.now());
    expect(new Date(body.dailyTransfers.resetAt).getTime()).toBeGreaterThan(Date.now());
  });
});

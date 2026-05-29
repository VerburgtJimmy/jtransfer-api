// Account export invariants. See docs/audit/24-right-to-portability.md §11.
//
// Covers: positive-list scope (no token hashes / password hashes / R2 keys),
// owner scoping (anonymous + other-user exclusion), auth gate, rate limit,
// cache + Content-Disposition headers, account_exported audit row, and that
// no email is sent on a successful export (D-094, no notification per §9).

import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { eq } from "drizzle-orm";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { authEvents, transfers } from "../../src/db/schema";
import { createSession } from "../../src/auth/sessions";
import { issueMagicLink } from "../../src/auth/magicLinks";
import { logAuthEvent } from "../../src/auth/events";
import { createFile, createTransfer } from "../../src/services/file.service";
import { createAuthedUser, testIpContext } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;

let app: ReturnType<typeof createApp>;

// Track email sends across the suite. Reset in beforeEach. The export flow
// must not call the email service on success (D-095 was dropped).
const emailCalls: { fn: string; args: unknown[] }[] = [];
mock.module("../../src/services/email.service", () => ({
  sendMagicLink: async (...args: unknown[]) => {
    emailCalls.push({ fn: "sendMagicLink", args });
  },
  sendAccountDeletedNotification: async (...args: unknown[]) => {
    emailCalls.push({ fn: "sendAccountDeletedNotification", args });
  },
}));

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});

beforeEach(async () => {
  await resetDb();
  emailCalls.length = 0;
});

afterAll(async () => {
  await resetDb();
});

function getRequest(path: string, cookie?: string): Request {
  const headers: Record<string, string> = {};
  if (cookie) headers["Cookie"] = cookie;
  return new Request(`${APP_URL}${path}`, { method: "GET", headers });
}

async function seedFile(transferId: string, size = 1024) {
  return createFile({
    transferId,
    encryptedName: "x".repeat(32),
    encryptedNameIv: "y".repeat(24),
    fileIv: "z".repeat(24),
    size,
    mimeType: "application/octet-stream",
  });
}

// ─── 1. Happy path + positive-list scope ───────────────────────────────────

describe("GET /api/me/export — happy path", () => {
  it("returns a JSON attachment with the documented shape and excludes credential surrogates", async () => {
    const { user, cookie } = await createAuthedUser("export-me@tessil.test");

    // Seed a richer fixture: a second session, a magic link, an auth event,
    // and an owned transfer with two files (one soft-deletable scenario).
    await createSession({ userId: user.id, ipContext: testIpContext(), userAgent: "second-device" });
    await issueMagicLink({ email: user.email, userAgent: null });
    await logAuthEvent({
      eventType: "magic_link_consumed",
      userId: user.id,
      email: user.email,
      ipContext: testIpContext(),
    });
    const owned = await createTransfer(1, "secretpass", undefined, user.id);
    await seedFile(owned.id, 100);
    await seedFile(owned.id, 200);

    const res = await app.handle(getRequest("/api/me/export", cookie));
    expect(res.status).toBe(200);

    // Headers: JSON, attachment, no-store, no-cache.
    expect(res.headers.get("content-type") ?? "").toContain("application/json");
    const disposition = res.headers.get("content-disposition") ?? "";
    expect(disposition).toContain("attachment");
    expect(disposition).toContain(`filename="tessil-export-${user.id}-`);
    expect(disposition).toContain(".json");
    expect(res.headers.get("cache-control") ?? "").toContain("no-store");
    expect(res.headers.get("pragma") ?? "").toContain("no-cache");

    const body = (await res.json()) as Record<string, unknown>;

    // Top-level shape.
    expect(body.exportFormatVersion).toBe(1);
    expect(typeof body.exportedAt).toBe("string");

    // Account.
    expect(body.account).toMatchObject({
      id: user.id,
      email: user.email,
      tier: user.tier,
    });

    // Sessions: two of them, neither leaks a token hash.
    const sessions = body.sessions as Array<Record<string, unknown>>;
    expect(sessions.length).toBe(2);
    for (const s of sessions) {
      expect(s).not.toHaveProperty("tokenHash");
      expect(s).not.toHaveProperty("token_hash");
      expect(s).not.toHaveProperty("id");
    }

    // Magic-link requests: at least one (the cookie's source + the explicit
    // issueMagicLink call). Neither leaks a token hash.
    const magicLinkRequests = body.magicLinkRequests as Array<Record<string, unknown>>;
    expect(magicLinkRequests.length).toBeGreaterThanOrEqual(1);
    for (const m of magicLinkRequests) {
      expect(m).not.toHaveProperty("tokenHash");
      expect(m).not.toHaveProperty("token_hash");
      expect(m).not.toHaveProperty("email");
    }

    // Auth events: at least the magic_link_consumed we wrote.
    const events = body.authEvents as Array<Record<string, unknown>>;
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events.some((e) => e.eventType === "magic_link_consumed")).toBe(true);

    // Transfers: one of them, with hasPassword surfaced as boolean (not the hash).
    const exportTransfers = body.transfers as Array<Record<string, unknown>>;
    expect(exportTransfers.length).toBe(1);
    const t = exportTransfers[0];
    expect(t.id).toBe(owned.id);
    expect(t.hasPassword).toBe(true);
    expect(t).not.toHaveProperty("passwordHash");
    expect(t).not.toHaveProperty("password_hash");
    expect(t).not.toHaveProperty("userId");

    // Files: two, with encrypted-name material but no R2 key or internal id.
    const exportFiles = t.files as Array<Record<string, unknown>>;
    expect(exportFiles.length).toBe(2);
    for (const f of exportFiles) {
      expect(f.encryptedName).toBeTruthy();
      expect(f.encryptedNameIv).toBeTruthy();
      expect(f.fileIv).toBeTruthy();
      expect(f).not.toHaveProperty("r2Key");
      expect(f).not.toHaveProperty("r2_key");
      expect(f).not.toHaveProperty("id");
    }

    // No email of any kind on a successful export.
    expect(emailCalls).toHaveLength(0);
  });
});

// ─── 2. Anonymous transfers excluded ───────────────────────────────────────

describe("GET /api/me/export — anonymous transfers are excluded", () => {
  it("does not include anonymous (NULL user_id) transfers in the export", async () => {
    const { user, cookie } = await createAuthedUser();
    const anon = await createTransfer(1); // user_id = NULL
    const owned = await createTransfer(1, undefined, undefined, user.id);

    const res = await app.handle(getRequest("/api/me/export", cookie));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { transfers: Array<{ id: string }> };

    const ids = body.transfers.map((t) => t.id);
    expect(ids).toContain(owned.id);
    expect(ids).not.toContain(anon.id);
  });
});

// ─── 3. Other users' transfers excluded ───────────────────────────────────

describe("GET /api/me/export — other users' transfers are excluded", () => {
  it("only returns transfers owned by the calling user", async () => {
    const userA = await createAuthedUser("a@tessil.test");
    const userB = await createAuthedUser("b@tessil.test");

    const transferB = await createTransfer(1, undefined, undefined, userB.user.id);
    const transferA = await createTransfer(1, undefined, undefined, userA.user.id);

    const res = await app.handle(getRequest("/api/me/export", userA.cookie));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { transfers: Array<{ id: string }> };

    const ids = body.transfers.map((t) => t.id);
    expect(ids).toContain(transferA.id);
    expect(ids).not.toContain(transferB.id);
  });
});

// ─── 4. Auth gate ──────────────────────────────────────────────────────────

describe("GET /api/me/export — auth gate", () => {
  it("401 when no session cookie is present", async () => {
    const res = await app.handle(getRequest("/api/me/export"));
    expect(res.status).toBe(401);
  });
});

// ─── 5. Rate limit ─────────────────────────────────────────────────────────

describe("GET /api/me/export — rate limit", () => {
  it("4th call within the hour returns 429", async () => {
    const { cookie } = await createAuthedUser();

    for (let i = 0; i < 3; i++) {
      const res = await app.handle(getRequest("/api/me/export", cookie));
      expect(res.status).toBe(200);
    }
    const fourth = await app.handle(getRequest("/api/me/export", cookie));
    expect(fourth.status).toBe(429);
  });
});

// ─── 6. account_exported audit row ────────────────────────────────────────

describe("GET /api/me/export — audit log", () => {
  it("writes exactly one account_exported row per successful response", async () => {
    const { user, cookie } = await createAuthedUser();

    const res = await app.handle(getRequest("/api/me/export", cookie));
    expect(res.status).toBe(200);

    const rows = await db
      .select()
      .from(authEvents)
      .where(eq(authEvents.userId, user.id));
    const exportRows = rows.filter((r) => r.eventType === "account_exported");
    expect(exportRows).toHaveLength(1);
    expect(exportRows[0].email).toBe(user.email);

    // Make TS happy about the otherwise unused transfers import.
    void transfers;
  });
});

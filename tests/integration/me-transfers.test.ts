// Phase B authz invariants. See docs/audit/20-transfer-ownership.md §8.
//
// Covers: owner-only enforcement on every mutating endpoint, anonymous
// transfer flow remains intact, /me/transfers list correctness, idempotent
// owner-delete, and the §8 backfill case (NULL user_id rows stay usable).

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { transfers, files } from "../../src/db/schema";
import { createTransfer, createFile, completeTransfer } from "../../src/services/file.service";
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
  // Leave the test DB in a clean state for the next run.
  await resetDb();
});

function jsonBody<T extends object>(body: T): RequestInit {
  return { method: "POST", headers: ORIGIN_HEADER, body: JSON.stringify(body) };
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

// ─── 1. Ownership is bound at creation (D-087) ──────────────────────────────

describe("POST /api/upload/create-transfer — ownership at creation", () => {
  it("anonymous request creates a transfer with user_id = NULL", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({ expiresInHours: 1 })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { transferId: string };

    const [row] = await db.select().from(transfers).where(eq(transfers.id, body.transferId));
    expect(row.userId).toBeNull();
  });

  it("signed-in request creates a transfer with user_id = me.id", async () => {
    const { user, cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/create-transfer`, jsonBody({ expiresInHours: 1 })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { transferId: string };

    const [row] = await db.select().from(transfers).where(eq(transfers.id, body.transferId));
    expect(row.userId).toBe(user.id);
  });
});

// ─── 2. Mutating endpoints: non-owner = 404 (D-088) ─────────────────────────

describe("Mutating endpoints — non-owner returns 404 (not 403)", () => {
  it("init-multipart: non-owner gets 404 on an owned transfer", async () => {
    const { user: owner } = await createAuthedUser();
    const { cookie: stranger } = await createAuthedUser();

    const owned = await createTransfer(1, undefined, undefined, owner.id);
    const res = await app.handle(
      authedRequest(stranger, `${APP_URL}/api/upload/init-multipart`, jsonBody({
        transferId: owned.id,
        contentType: "application/octet-stream",
        encryptedName: "x".repeat(32),
        encryptedNameIv: "y".repeat(24),
        fileIv: "z".repeat(24),
        size: 1024,
      })),
    );
    expect(res.status).toBe(404);
  });

  it("complete: non-owner gets 404 on an owned transfer", async () => {
    const { user: owner } = await createAuthedUser();
    const { cookie: stranger } = await createAuthedUser();

    const owned = await createTransfer(1, undefined, undefined, owner.id);
    await seedFile(owned.id);

    const res = await app.handle(
      authedRequest(stranger, `${APP_URL}/api/upload/complete`, jsonBody({ transferId: owned.id })),
    );
    expect(res.status).toBe(404);
  });

  it("abort: non-owner gets 404 on an owned transfer", async () => {
    const { user: owner } = await createAuthedUser();
    const { cookie: stranger } = await createAuthedUser();

    const owned = await createTransfer(1, undefined, undefined, owner.id);
    const res = await app.handle(
      authedRequest(stranger, `${APP_URL}/api/upload/abort`, jsonBody({ transferId: owned.id })),
    );
    expect(res.status).toBe(404);
  });

  it("anonymous request to an owned transfer also gets 404", async () => {
    const { user: owner } = await createAuthedUser();
    const owned = await createTransfer(1, undefined, undefined, owner.id);

    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
        transferId: owned.id,
        contentType: "application/octet-stream",
        encryptedName: "x".repeat(32),
        encryptedNameIv: "y".repeat(24),
        fileIv: "z".repeat(24),
        size: 1024,
      })),
    );
    expect(res.status).toBe(404);
  });
});

// ─── 3. Anonymous flow + backfill compatibility ─────────────────────────────

describe("Anonymous transfer flow (and NULL-owner backfill rows)", () => {
  it("anonymous user can upload + complete a NULL-owner transfer end-to-end", async () => {
    const anon = await createTransfer(1);
    expect(anon.userId).toBeNull();

    const uploadRes = await app.handle(
      new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
        transferId: anon.id,
        contentType: "application/octet-stream",
        encryptedName: "x".repeat(32),
        encryptedNameIv: "y".repeat(24),
        fileIv: "z".repeat(24),
        size: 1024,
      })),
    );
    expect(uploadRes.status).toBe(200);

    const completeRes = await app.handle(
      new Request(`${APP_URL}/api/upload/complete`, jsonBody({ transferId: anon.id })),
    );
    expect(completeRes.status).toBe(200);
  });

  it("signed-in user can still complete an unclaimed (NULL-owner) transfer", async () => {
    // Models the pre-Phase-B backfill: a NULL-owner row remains accessible to
    // any URL holder, signed-in or not.
    const { cookie } = await createAuthedUser();
    const anon = await createTransfer(1);
    await seedFile(anon.id);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/complete`, jsonBody({ transferId: anon.id })),
    );
    expect(res.status).toBe(200);
  });
});

// ─── 4. GET /api/me/transfers ───────────────────────────────────────────────

describe("GET /api/me/transfers", () => {
  it("401 when unauthenticated", async () => {
    const res = await app.handle(new Request(`${APP_URL}/api/me/transfers`));
    expect(res.status).toBe(401);
  });

  it("returns only the caller's transfers, excludes anonymous and other users'", async () => {
    const { user: a, cookie: cookieA } = await createAuthedUser();
    const { user: b } = await createAuthedUser();

    const ownByA = await createTransfer(1, undefined, undefined, a.id);
    await createTransfer(1, undefined, undefined, b.id);
    await createTransfer(1); // anonymous

    const res = await app.handle(authedRequest(cookieA, `${APP_URL}/api/me/transfers`));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { transfers: { id: string }[]; nextCursor: string | null };
    expect(body.transfers).toHaveLength(1);
    expect(body.transfers[0].id).toBe(ownByA.id);
  });

  it("excludes soft-deleted rows", async () => {
    const { user, cookie } = await createAuthedUser();
    const keep = await createTransfer(1, undefined, undefined, user.id);
    const drop = await createTransfer(1, undefined, undefined, user.id);

    await db.update(transfers).set({ isDeleted: true }).where(eq(transfers.id, drop.id));

    const res = await app.handle(authedRequest(cookie, `${APP_URL}/api/me/transfers`));
    const body = (await res.json()) as { transfers: { id: string }[] };
    expect(body.transfers.map((t) => t.id)).toEqual([keep.id]);
  });

  it("aggregates fileCount + totalBytes correctly", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);
    await seedFile(t.id, 100);
    await seedFile(t.id, 250);

    const res = await app.handle(authedRequest(cookie, `${APP_URL}/api/me/transfers`));
    const body = (await res.json()) as { transfers: { fileCount: number; totalBytes: number }[] };
    expect(body.transfers[0].fileCount).toBe(2);
    expect(body.transfers[0].totalBytes).toBe(350);
  });

  it("paginates via cursor", async () => {
    const { user, cookie } = await createAuthedUser();
    // Insert 3 transfers with staggered created_at so cursor order is stable.
    for (let i = 0; i < 3; i++) {
      const t = await createTransfer(1, undefined, undefined, user.id);
      await db.update(transfers).set({ createdAt: new Date(Date.now() - i * 1000) }).where(eq(transfers.id, t.id));
    }

    const firstRes = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers?limit=2`),
    );
    const first = (await firstRes.json()) as { transfers: { id: string }[]; nextCursor: string | null };
    expect(first.transfers).toHaveLength(2);
    expect(first.nextCursor).not.toBeNull();

    const secondRes = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers?limit=2&cursor=${encodeURIComponent(first.nextCursor!)}`),
    );
    const second = (await secondRes.json()) as { transfers: { id: string }[]; nextCursor: string | null };
    expect(second.transfers).toHaveLength(1);

    // No overlap.
    const idsFirst = new Set(first.transfers.map((t) => t.id));
    for (const t of second.transfers) {
      expect(idsFirst.has(t.id)).toBe(false);
    }
  });
});

// ─── 5. DELETE /api/me/transfers/:id ────────────────────────────────────────

describe("DELETE /api/me/transfers/:id", () => {
  it("401 when unauthenticated", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/me/transfers/aaaaaaaaaaaaaaaaaaaaa`, { method: "DELETE" }),
    );
    expect(res.status).toBe(401);
  });

  it("owner can soft-delete (sets is_deleted=true)", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}`, { method: "DELETE" }),
    );
    expect(res.status).toBe(204);

    const [row] = await db.select().from(transfers).where(eq(transfers.id, t.id));
    expect(row.isDeleted).toBe(true);
  });

  it("non-owner gets 404 (existence oracle prevention, D-088)", async () => {
    const { user: owner } = await createAuthedUser();
    const { cookie: stranger } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, owner.id);

    const res = await app.handle(
      authedRequest(stranger, `${APP_URL}/api/me/transfers/${t.id}`, { method: "DELETE" }),
    );
    expect(res.status).toBe(404);

    // Confirm: stranger did NOT mutate owner's row.
    const [row] = await db.select().from(transfers).where(eq(transfers.id, t.id));
    expect(row.isDeleted).toBe(false);
  });

  it("anonymous transfer (NULL owner) returns 404 — cannot be deleted via /me", async () => {
    const { cookie } = await createAuthedUser();
    const anon = await createTransfer(1);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${anon.id}`, { method: "DELETE" }),
    );
    expect(res.status).toBe(404);
  });

  it("is idempotent — second delete on already-deleted row returns 404", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);

    const first = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}`, { method: "DELETE" }),
    );
    expect(first.status).toBe(204);

    const second = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}`, { method: "DELETE" }),
    );
    expect(second.status).toBe(404);
  });

  it("malformed transfer id returns 404 (not 400 — no shape leak)", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/not-a-nanoid`, { method: "DELETE" }),
    );
    expect(res.status).toBe(404);
  });
});

// ─── 6. Completed transfer is not exposed via /me incorrectly ────────────────

describe("Completed-transfer lifecycle vs. /me/transfers", () => {
  it("listing includes completed owned transfers with isCompleted=true", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);
    await completeTransfer(t.id);

    const res = await app.handle(authedRequest(cookie, `${APP_URL}/api/me/transfers`));
    const body = (await res.json()) as { transfers: { id: string; isCompleted: boolean }[] };
    expect(body.transfers).toHaveLength(1);
    expect(body.transfers[0].isCompleted).toBe(true);
  });
});

// Make TS happy about unused import.
void files;

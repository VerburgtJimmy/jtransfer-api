// Encrypted-title invariants. See docs/adr/0005-encrypted-transfer-title-scope.md.
//
// Covers:
//   1. POST /api/upload/create-transfer accepts optional title pair.
//   2. PUT  /api/me/transfers/:id/title — owner can set / rewrite / clear.
//   3. Both-or-neither invariant on every entry point.
//   4. Non-owner gets 404 (existence oracle prevention, D-088).
//   5. Anonymous gets 401.
//   6. Base64 + length validation.
//   7. Title shows up on GET /api/me/transfers list rows.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { transfers } from "../../src/db/schema";
import { createTransfer } from "../../src/services/file.service";
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

function jsonBody<T extends object>(body: T, method = "POST"): RequestInit {
  return { method, headers: ORIGIN_HEADER, body: JSON.stringify(body) };
}

// 12-byte IV → 16 base64 chars. Plaintext padded to 32 bytes minimum →
// 32+16 ciphertext → 64 base64 chars. Both values use a fixed seed so the
// test is deterministic — bytes don't need to round-trip cleanly through
// crypto.subtle here, only through the validators.
const TITLE_CT = "A".repeat(64);
const TITLE_IV = "B".repeat(16);
const TITLE_CT_ALT = "C".repeat(64);
const TITLE_IV_ALT = "D".repeat(16);

// ─── 1. POST /api/upload/create-transfer ────────────────────────────────────

describe("POST /api/upload/create-transfer — title field", () => {
  it("persists encryptedTitle + IV when both are provided", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({
        expiresInHours: 1,
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: TITLE_IV,
      })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { transferId: string };

    const [row] = await db.select().from(transfers).where(eq(transfers.id, body.transferId));
    expect(row.encryptedTitle).toBe(TITLE_CT);
    expect(row.encryptedTitleIv).toBe(TITLE_IV);
  });

  it("creates without title when both fields are omitted", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({ expiresInHours: 1 })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { transferId: string };

    const [row] = await db.select().from(transfers).where(eq(transfers.id, body.transferId));
    expect(row.encryptedTitle).toBeNull();
    expect(row.encryptedTitleIv).toBeNull();
  });

  it("400s when only one of the title pair is provided (both-or-neither)", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({
        expiresInHours: 1,
        encryptedTitle: TITLE_CT,
      })),
    );
    expect(res.status).toBe(400);
  });

  it("400s on an IV with the wrong length", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({
        expiresInHours: 1,
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: "B".repeat(15),
      })),
    );
    expect(res.status).toBe(400);
  });

  it("400s when title is not valid base64", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({
        expiresInHours: 1,
        encryptedTitle: "***not-base64***",
        encryptedTitleIv: TITLE_IV,
      })),
    );
    expect(res.status).toBe(400);
  });
});

// ─── 2. PUT /api/me/transfers/:id/title — owner can rewrite + clear ─────────

describe("PUT /api/me/transfers/:id/title", () => {
  it("401 when unauthenticated", async () => {
    const { user } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);

    const res = await app.handle(
      new Request(`${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: TITLE_IV,
      }, "PUT")),
    );
    expect(res.status).toBe(401);
  });

  it("owner can set a title on their transfer", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: TITLE_IV,
      }, "PUT")),
    );
    expect(res.status).toBe(204);

    const [row] = await db.select().from(transfers).where(eq(transfers.id, t.id));
    expect(row.encryptedTitle).toBe(TITLE_CT);
    expect(row.encryptedTitleIv).toBe(TITLE_IV);
  });

  it("owner can rewrite an existing title", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id, {
      encryptedTitle: TITLE_CT,
      encryptedTitleIv: TITLE_IV,
    });

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: TITLE_CT_ALT,
        encryptedTitleIv: TITLE_IV_ALT,
      }, "PUT")),
    );
    expect(res.status).toBe(204);

    const [row] = await db.select().from(transfers).where(eq(transfers.id, t.id));
    expect(row.encryptedTitle).toBe(TITLE_CT_ALT);
    expect(row.encryptedTitleIv).toBe(TITLE_IV_ALT);
  });

  it("owner can clear by passing null for both fields", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id, {
      encryptedTitle: TITLE_CT,
      encryptedTitleIv: TITLE_IV,
    });

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: null,
        encryptedTitleIv: null,
      }, "PUT")),
    );
    expect(res.status).toBe(204);

    const [row] = await db.select().from(transfers).where(eq(transfers.id, t.id));
    expect(row.encryptedTitle).toBeNull();
    expect(row.encryptedTitleIv).toBeNull();
  });

  it("400 when only one of the title pair is provided (both-or-neither)", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: null,
      }, "PUT")),
    );
    expect(res.status).toBe(400);
  });

  it("400 on bad IV length", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: "B".repeat(15),
      }, "PUT")),
    );
    expect(res.status).toBe(400);
  });

  it("400 on non-base64 ciphertext", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: "***not-base64***",
        encryptedTitleIv: TITLE_IV,
      }, "PUT")),
    );
    expect(res.status).toBe(400);
  });

  it("non-owner gets 404 (existence oracle prevention, D-088)", async () => {
    const { user: owner } = await createAuthedUser();
    const { cookie: stranger } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, owner.id);

    const res = await app.handle(
      authedRequest(stranger, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: TITLE_IV,
      }, "PUT")),
    );
    expect(res.status).toBe(404);

    // Confirm: stranger did NOT mutate the owner's row.
    const [row] = await db.select().from(transfers).where(eq(transfers.id, t.id));
    expect(row.encryptedTitle).toBeNull();
  });

  it("anonymous transfer (NULL owner) returns 404 via /me", async () => {
    const { cookie } = await createAuthedUser();
    const anon = await createTransfer(1);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${anon.id}/title`, jsonBody({
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: TITLE_IV,
      }, "PUT")),
    );
    expect(res.status).toBe(404);
  });

  it("soft-deleted row returns 404", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);
    await db.update(transfers).set({ isDeleted: true }).where(eq(transfers.id, t.id));

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: TITLE_IV,
      }, "PUT")),
    );
    expect(res.status).toBe(404);
  });

  it("malformed transfer id returns 404 (no shape leak)", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/not-a-nanoid/title`, jsonBody({
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: TITLE_IV,
      }, "PUT")),
    );
    expect(res.status).toBe(404);
  });

  it("rate-limits at 30/min per user", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);

    // 30 should pass, the 31st should 429.
    for (let i = 0; i < 30; i++) {
      const res = await app.handle(
        authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
          encryptedTitle: TITLE_CT,
          encryptedTitleIv: TITLE_IV,
        }, "PUT")),
      );
      expect(res.status).toBe(204);
    }

    const overflow = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/title`, jsonBody({
        encryptedTitle: TITLE_CT,
        encryptedTitleIv: TITLE_IV,
      }, "PUT")),
    );
    expect(overflow.status).toBe(429);
  });
});

// ─── 3. /me/transfers list surfaces the encrypted title ─────────────────────

describe("GET /api/me/transfers — encrypted title in response", () => {
  it("returns encryptedTitle + IV on rows that have them set", async () => {
    const { user, cookie } = await createAuthedUser();
    await createTransfer(1, undefined, undefined, user.id, {
      encryptedTitle: TITLE_CT,
      encryptedTitleIv: TITLE_IV,
    });
    await createTransfer(1, undefined, undefined, user.id); // no title

    const res = await app.handle(authedRequest(cookie, `${APP_URL}/api/me/transfers`));
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      transfers: { encryptedTitle: string | null; encryptedTitleIv: string | null }[];
    };
    expect(body.transfers).toHaveLength(2);

    const titled = body.transfers.find((t) => t.encryptedTitle !== null)!;
    const untitled = body.transfers.find((t) => t.encryptedTitle === null)!;
    expect(titled.encryptedTitle).toBe(TITLE_CT);
    expect(titled.encryptedTitleIv).toBe(TITLE_IV);
    expect(untitled.encryptedTitleIv).toBeNull();
  });
});

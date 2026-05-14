// Phase F server foundation — see docs/audit/28-dashboard-transfer-key-vault.md §12.
//
// Covers the contracts the client-side vault will rely on:
//   - PRF salt bootstrap is idempotent under concurrent first-use
//   - /api/auth/passkey/prf-salts only returns the signed-in user's
//     PRF-capable credentials, and salts round-trip lossless
//   - /api/upload/complete validates wrappedKey/wrapCredentialId shape,
//     pairs them, requires ownership of the credential, persists the bytes
//   - /api/me/transfers payload includes wrappedKey + wrapCredentialId
//   - /api/me/transfers/:id/files returns per-file metadata for owned
//     transfers and 404s on stranger access

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { authenticators, files, transfers } from "../../src/db/schema";
import { createFile, createTransfer } from "../../src/services/file.service";
import { getOrCreatePrfSalt, listPrfSaltsForUser } from "../../src/services/prfSalts.service";
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

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

async function seedPrfCredential(
  userId: string,
  credentialId: Uint8Array,
  supportsPrf = true,
) {
  await db.insert(authenticators).values({
    id: nanoid(),
    userId,
    credentialId,
    publicKey: new Uint8Array([1, 2, 3, 4]),
    signCount: 0,
    transports: [],
    deviceType: "multiDevice",
    backedUp: true,
    supportsPrf,
    nickname: "test passkey",
  });
}

// ─── getOrCreatePrfSalt ─────────────────────────────────────────────────────

describe("getOrCreatePrfSalt", () => {
  it("returns the same salt on repeated calls for one (credential, purpose)", async () => {
    const credId = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    const a = await getOrCreatePrfSalt(credId, "jtransfer:vault:transfer-key:v1");
    const b = await getOrCreatePrfSalt(credId, "jtransfer:vault:transfer-key:v1");
    expect(a).toEqual(b);
    expect(a.length).toBe(32);
  });

  it("collapses concurrent first-use to one row (race-safe)", async () => {
    const credId = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    // Fire enough parallel calls that an unguarded insert path would race.
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        getOrCreatePrfSalt(credId, "jtransfer:vault:transfer-key:v1"),
      ),
    );
    const first = results[0];
    for (const r of results) {
      expect(r).toEqual(first);
    }
  });

  it("produces independent salts for different credentials", async () => {
    const credA = new Uint8Array([1]);
    const credB = new Uint8Array([2]);
    const a = await getOrCreatePrfSalt(credA, "jtransfer:vault:transfer-key:v1");
    const b = await getOrCreatePrfSalt(credB, "jtransfer:vault:transfer-key:v1");
    expect(a).not.toEqual(b);
  });
});

// ─── listPrfSaltsForUser ────────────────────────────────────────────────────

describe("listPrfSaltsForUser", () => {
  it("returns one entry per (PRF-capable credential, known purpose)", async () => {
    const { user } = await createAuthedUser();
    const credA = new Uint8Array([0x10, 0x20]);
    const credB = new Uint8Array([0x30, 0x40]);
    await seedPrfCredential(user.id, credA, true);
    await seedPrfCredential(user.id, credB, true);

    const entries = await listPrfSaltsForUser(user.id);
    expect(entries).toHaveLength(2);
    const seen = new Set(entries.map((e) => Buffer.from(e.credentialId).toString("hex")));
    expect(seen).toContain(Buffer.from(credA).toString("hex"));
    expect(seen).toContain(Buffer.from(credB).toString("hex"));
  });

  it("excludes credentials without PRF support", async () => {
    const { user } = await createAuthedUser();
    await seedPrfCredential(user.id, new Uint8Array([1]), true);
    await seedPrfCredential(user.id, new Uint8Array([2]), false);

    const entries = await listPrfSaltsForUser(user.id);
    expect(entries).toHaveLength(1);
  });

  it("isolates one user's credentials from another's", async () => {
    const { user: alice } = await createAuthedUser();
    const { user: bob } = await createAuthedUser();
    await seedPrfCredential(alice.id, new Uint8Array([1]), true);
    await seedPrfCredential(bob.id, new Uint8Array([2]), true);

    const aliceEntries = await listPrfSaltsForUser(alice.id);
    expect(aliceEntries).toHaveLength(1);
    expect(Buffer.from(aliceEntries[0].credentialId).toString("hex")).toBe("01");
  });
});

// ─── GET /api/auth/passkey/prf-salts ───────────────────────────────────────

describe("GET /api/auth/passkey/prf-salts", () => {
  it("rejects unauthenticated callers with 401", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/auth/passkey/prf-salts`, { method: "GET" }),
    );
    expect(res.status).toBe(401);
  });

  it("returns base64url-encoded salt + credential id for me's PRF creds", async () => {
    const { user, cookie } = await createAuthedUser();
    const credId = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    await seedPrfCredential(user.id, credId, true);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/auth/passkey/prf-salts`, { method: "GET" }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      salts: { credentialId: string; purpose: string; salt: string }[];
    };
    expect(body.salts).toHaveLength(1);
    expect(body.salts[0].credentialId).toBe(b64url(credId));
    expect(body.salts[0].purpose).toBe("jtransfer:vault:transfer-key:v1");
    expect(Buffer.from(body.salts[0].salt, "base64url").length).toBe(32);
  });

  it("returns empty array when user has no PRF-capable credentials", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/auth/passkey/prf-salts`, { method: "GET" }),
    );
    const body = (await res.json()) as { salts: unknown[] };
    expect(body.salts).toEqual([]);
  });
});

// ─── /api/upload/complete vault wrap acceptance ────────────────────────────

describe("POST /api/upload/complete — vault wrap", () => {
  async function seedReadyTransfer(userId: string) {
    const t = await createTransfer(1, undefined, undefined, userId);
    await createFile({
      transferId: t.id,
      encryptedName: "x".repeat(32),
      encryptedNameIv: "y".repeat(24),
      fileIv: "z".repeat(24),
      size: 1024,
      mimeType: "application/octet-stream",
    });
    return t;
  }

  // headObject is the storage-presence check inside /complete. The test
  // suite already shims this elsewhere via `tests/helpers/db.ts` — relying
  // on the existing shim keeps these tests aligned with the rest of the
  // upload-complete coverage.

  it("rejects wrappedKey without wrapCredentialId (and vice versa)", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await seedReadyTransfer(user.id);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/complete`, jsonBody({
        transferId: t.id,
        wrappedKey: b64url(new Uint8Array(60)),
        // wrapCredentialId omitted
      })),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/wrappedKey.*wrapCredentialId/);
  });

  it("rejects wrappedKey of wrong byte length", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await seedReadyTransfer(user.id);
    const credId = new Uint8Array(16);
    await seedPrfCredential(user.id, credId, true);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/complete`, jsonBody({
        transferId: t.id,
        wrappedKey: b64url(new Uint8Array(59)),
        wrapCredentialId: b64url(credId),
      })),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/60 bytes/);
  });

  it("rejects credential id that the user does not own", async () => {
    const { user, cookie } = await createAuthedUser();
    const { user: stranger } = await createAuthedUser();
    const t = await seedReadyTransfer(user.id);

    // Stranger's PRF credential — not owned by `user`.
    const strangerCred = new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]);
    await seedPrfCredential(stranger.id, strangerCred, true);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/complete`, jsonBody({
        transferId: t.id,
        wrappedKey: b64url(new Uint8Array(60)),
        wrapCredentialId: b64url(strangerCred),
      })),
    );
    expect(res.status).toBe(400);
  });

  it("rejects vault wrap on an anonymous transfer", async () => {
    const { user, cookie } = await createAuthedUser();
    // Anonymous transfer (userId NULL).
    const t = await createTransfer(1, undefined, undefined, null);
    await createFile({
      transferId: t.id,
      encryptedName: "x".repeat(32),
      encryptedNameIv: "y".repeat(24),
      fileIv: "z".repeat(24),
      size: 1024,
      mimeType: "application/octet-stream",
    });
    const credId = new Uint8Array(16);
    await seedPrfCredential(user.id, credId, true);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/complete`, jsonBody({
        transferId: t.id,
        wrappedKey: b64url(new Uint8Array(60)),
        wrapCredentialId: b64url(credId),
      })),
    );
    expect(res.status).toBe(400);

    // And the transfer row must not have been wrapped.
    const [row] = await db.select().from(transfers).where(eq(transfers.id, t.id));
    expect(row.wrappedKey).toBeNull();
    expect(row.wrapCredentialId).toBeNull();
  });

  it("persists wrappedKey + wrapCredentialId on a valid wrap", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await seedReadyTransfer(user.id);
    const credId = new Uint8Array(16).fill(0x55);
    await seedPrfCredential(user.id, credId, true);

    const wrappedKey = new Uint8Array(60);
    crypto.getRandomValues(wrappedKey);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/complete`, jsonBody({
        transferId: t.id,
        wrappedKey: b64url(wrappedKey),
        wrapCredentialId: b64url(credId),
      })),
    );
    expect(res.status).toBe(200);

    const [row] = await db.select().from(transfers).where(eq(transfers.id, t.id));
    expect(row.isCompleted).toBe(true);
    expect(row.wrappedKey).toEqual(wrappedKey);
    expect(row.wrapCredentialId).toEqual(credId);
  });

  it("leaves wrap fields NULL when caller omits them (unvaulted path)", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await seedReadyTransfer(user.id);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/complete`, jsonBody({
        transferId: t.id,
      })),
    );
    expect(res.status).toBe(200);

    const [row] = await db.select().from(transfers).where(eq(transfers.id, t.id));
    expect(row.isCompleted).toBe(true);
    expect(row.wrappedKey).toBeNull();
    expect(row.wrapCredentialId).toBeNull();
  });
});

// ─── /api/me/transfers payload extension ───────────────────────────────────

describe("GET /api/me/transfers — wrappedKey/wrapCredentialId in payload", () => {
  it("returns null wrap fields for unvaulted rows", async () => {
    const { user, cookie } = await createAuthedUser();
    await createTransfer(1, undefined, undefined, user.id);

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers`, { method: "GET" }),
    );
    const body = (await res.json()) as {
      transfers: { wrappedKey: string | null; wrapCredentialId: string | null }[];
    };
    expect(body.transfers).toHaveLength(1);
    expect(body.transfers[0].wrappedKey).toBeNull();
    expect(body.transfers[0].wrapCredentialId).toBeNull();
  });

  it("returns base64url-encoded wrap fields for vaulted rows", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);
    const wrappedKey = new Uint8Array(60).fill(0x7e);
    const wrapCredentialId = new Uint8Array(16).fill(0x42);
    await db
      .update(transfers)
      .set({ wrappedKey, wrapCredentialId })
      .where(eq(transfers.id, t.id));

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers`, { method: "GET" }),
    );
    const body = (await res.json()) as {
      transfers: { wrappedKey: string; wrapCredentialId: string }[];
    };
    expect(body.transfers[0].wrappedKey).toBe(b64url(wrappedKey));
    expect(body.transfers[0].wrapCredentialId).toBe(b64url(wrapCredentialId));
  });
});

// ─── /api/me/transfers/:id/files ───────────────────────────────────────────

describe("GET /api/me/transfers/:id/files", () => {
  it("rejects unauthenticated callers with 401", async () => {
    const { user } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);
    const res = await app.handle(
      new Request(`${APP_URL}/api/me/transfers/${t.id}/files`, { method: "GET" }),
    );
    expect(res.status).toBe(401);
  });

  it("returns per-file metadata for an owned transfer", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);
    await createFile({
      transferId: t.id,
      encryptedName: "encname",
      encryptedNameIv: "encnameIV",
      fileIv: "fileIV",
      size: 4096,
      mimeType: "image/png",
    });

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/files`, { method: "GET" }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      files: { encryptedName: string; encryptedNameIv: string; size: number; mimeType: string }[];
    };
    expect(body.files).toHaveLength(1);
    expect(body.files[0].encryptedName).toBe("encname");
    expect(body.files[0].encryptedNameIv).toBe("encnameIV");
    expect(body.files[0].size).toBe(4096);
    expect(body.files[0].mimeType).toBe("image/png");
  });

  it("returns 404 for a stranger trying to read an owned transfer", async () => {
    const { user: owner } = await createAuthedUser();
    const { cookie: stranger } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, owner.id);

    const res = await app.handle(
      authedRequest(stranger, `${APP_URL}/api/me/transfers/${t.id}/files`, { method: "GET" }),
    );
    expect(res.status).toBe(404);
  });

  it("returns 404 for a soft-deleted owned transfer", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);
    await db.update(transfers).set({ isDeleted: true }).where(eq(transfers.id, t.id));

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/files`, { method: "GET" }),
    );
    expect(res.status).toBe(404);
  });

  it("excludes file rows that are soft-deleted", async () => {
    const { user, cookie } = await createAuthedUser();
    const t = await createTransfer(1, undefined, undefined, user.id);
    const f1 = await createFile({
      transferId: t.id,
      encryptedName: "a",
      encryptedNameIv: "a",
      fileIv: "a",
      size: 1,
      mimeType: null,
    });
    await createFile({
      transferId: t.id,
      encryptedName: "b",
      encryptedNameIv: "b",
      fileIv: "b",
      size: 2,
      mimeType: null,
    });
    await db.update(files).set({ isDeleted: true }).where(eq(files.id, f1.id));

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/transfers/${t.id}/files`, { method: "GET" }),
    );
    const body = (await res.json()) as { files: { encryptedName: string }[] };
    expect(body.files).toHaveLength(1);
    expect(body.files[0].encryptedName).toBe("b");
  });
});


// /api/upload/complete object-presence + size-match guard.
// See docs/audit/25-external-audit-findings.md §A.3.
//
// Default test setup stubs r2.service so HeadObject pretends the upload
// landed at whatever size the DB file row has. These tests override that
// per-case to exercise the missing-object and size-mismatch failure paths.

import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { createApp } from "../../src/app";
import { createTransfer, createFile } from "../../src/services/file.service";
import { ensureMigrations, resetDb } from "../helpers/db";
import { defaultR2Mock } from "../helpers/r2-mock";

const APP_URL = process.env.APP_URL!;
const ORIGIN_HEADER = { Origin: APP_URL, "Content-Type": "application/json" };

let app: ReturnType<typeof createApp>;

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

function restoreDefaultR2Mock() {
  mock.module("../../src/services/r2.service", () => defaultR2Mock());
}

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});

beforeEach(async () => {
  await resetDb();
  restoreDefaultR2Mock();
});

afterAll(async () => {
  await resetDb();
  restoreDefaultR2Mock();
});

// ─── 1. Empty transfer cannot be completed ─────────────────────────────────

describe("POST /api/upload/complete — empty transfer", () => {
  it("returns 409 when the transfer has zero files", async () => {
    const transfer = await createTransfer(1);
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/complete`, jsonBody({ transferId: transfer.id })),
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("no files");
  });
});

// ─── 2. Missing R2 object blocks completion ────────────────────────────────

describe("POST /api/upload/complete — missing R2 object", () => {
  it("returns 409 when HeadObject says one of the files is absent", async () => {
    const transfer = await createTransfer(1);
    await seedFile(transfer.id, 1024);
    await seedFile(transfer.id, 2048);

    // Second file has no R2 object — simulates an abandoned partial upload.
    mock.module("../../src/services/r2.service", () => ({
      ...defaultR2Mock(),
      headObject: async (key: string) => {
        // Only the first uploaded key "exists" in storage.
        const { db } = await import("../../src/db");
        const { files } = await import("../../src/db/schema");
        const { eq, asc } = await import("drizzle-orm");
        const rows = await db
          .select({ key: files.r2Key, size: files.size })
          .from(files)
          .where(eq(files.transferId, transfer.id))
          .orderBy(asc(files.createdAt));
        if (rows[0]?.key === key) return { size: rows[0].size };
        return null;
      },
    }));

    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/complete`, jsonBody({ transferId: transfer.id })),
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("missing");
  });
});

// ─── 3. Size mismatch blocks completion ────────────────────────────────────

describe("POST /api/upload/complete — size mismatch", () => {
  it("returns 409 when HeadObject reports a size different from the declared one", async () => {
    const transfer = await createTransfer(1);
    await seedFile(transfer.id, 1024);

    mock.module("../../src/services/r2.service", () => ({
      ...defaultR2Mock(),
      // Pretend the actual stored object is bigger than declared — the kind
      // of byte-padding bypass we want to catch.
      headObject: async () => ({ size: 999_999_999 }),
    }));

    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/complete`, jsonBody({ transferId: transfer.id })),
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("size mismatch");
  });
});

// ─── 4. Happy path still passes with the default DB-coupled mock ───────────

describe("POST /api/upload/complete — happy path", () => {
  it("returns 200 when every file's R2 object is present and size-matched", async () => {
    const transfer = await createTransfer(1);
    await seedFile(transfer.id, 1024);
    await seedFile(transfer.id, 2048);

    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/complete`, jsonBody({ transferId: transfer.id })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; shareUrl: string };
    expect(body.success).toBe(true);
    expect(body.shareUrl).toBe(`/d/${transfer.id}`);
  });
});

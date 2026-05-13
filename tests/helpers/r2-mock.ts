// Default in-process R2 mock used by `tests/setup.ts` and by individual tests
// that need to override + restore the stub. Extracted so the default headObject
// behaviour (pretend the upload succeeded with the size from the DB row) stays
// in sync across files — without this, an inline `mock.module` override in one
// test file would leak a degraded stub into every later test file that shares
// the same Bun process.

export function defaultR2Mock() {
  return {
    getPresignedUploadUrl: async (key: string) => ({
      url: `https://r2.test.invalid/${key}`,
      expiresAt: new Date(Date.now() + 60_000),
    }),
    getPresignedDownloadUrl: async (key: string) => ({
      url: `https://r2.test.invalid/${key}`,
      expiresAt: new Date(Date.now() + 15 * 60_000),
    }),
    deleteFromR2: async () => undefined,
    headObject: async (key: string) => {
      const { db } = await import("../../src/db");
      const { files } = await import("../../src/db/schema");
      const { eq } = await import("drizzle-orm");
      const [row] = await db
        .select({ size: files.size })
        .from(files)
        .where(eq(files.r2Key, key))
        .limit(1);
      return row ? { size: row.size } : null;
    },
  };
}

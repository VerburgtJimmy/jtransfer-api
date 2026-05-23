// Default in-process R2 mock used by `tests/setup.ts` and by individual tests
// that need to override + restore the stub. Extracted so the default headObject
// behaviour (pretend the upload succeeded with the size from the DB row) stays
// in sync across files — without this, an inline `mock.module` override in one
// test file would leak a degraded stub into every later test file that shares
// the same Bun process.

// Multipart Part size matches the production constant (16 MB) so test
// fixtures compute the same number of Parts the orchestrator would
// see in real use.
const MULTIPART_PART_SIZE = 16 * 1024 * 1024;

export function defaultR2Mock() {
  return {
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
    // Multipart stubs (ADR-0009). The mocked uploadId is deterministic
    // so tests can assert against it without snapshotting random values.
    MULTIPART_PART_SIZE,
    initMultipartUpload: async (key: string, totalBytes: number) => {
      const partCount = Math.max(1, Math.ceil(totalBytes / MULTIPART_PART_SIZE));
      const partUrls = Array.from({ length: partCount }, (_, i) => {
        const partNumber = i + 1;
        const offset = i * MULTIPART_PART_SIZE;
        const isLast = i === partCount - 1;
        const contentLength = isLast ? totalBytes - offset : MULTIPART_PART_SIZE;
        return {
          partNumber,
          url: `https://r2.test.invalid/${key}?partNumber=${partNumber}`,
          contentLength,
        };
      });
      return { uploadId: `mock-upload-${key}`, key, partUrls };
    },
    completeMultipartUpload: async () => undefined,
    abortMultipartUpload: async () => undefined,
  };
}

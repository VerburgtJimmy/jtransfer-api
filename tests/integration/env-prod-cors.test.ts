// Production boot-time guard against `CORS_ORIGINS=*`.
// See docs/audit/25-external-audit-findings.md §B.3.
//
// env.ts asserts that `*` is never present in CORS_ORIGINS when
// NODE_ENV=production — a wildcard + credentials combination would let any
// site read cookied API responses. We spawn a child Bun process to import
// the module fresh; setting NODE_ENV in-process is not enough because the
// assertions run at module-load time and env.ts is already cached.

import { describe, expect, it } from "bun:test";

function bunImportEnv(extraEnv: Record<string, string>): Promise<{
  exitCode: number;
  stderr: string;
}> {
  const proc = Bun.spawn({
    cmd: ["bun", "--eval", "await import('./src/config/env'); console.log('ok')"],
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      // Minimum env to clear the other prod assertions, so the only thing
      // that can fail is the CORS check we're testing.
      DATABASE_URL: "postgresql://u:p@localhost/x",
      R2_ENDPOINT: "https://r2.test.invalid",
      R2_ACCESS_KEY_ID: "x",
      R2_SECRET_ACCESS_KEY: "x",
      R2_BUCKET_NAME: "x",
      APP_URL: "https://example.test",
      SCW_TEM_PROJECT_ID: "p",
      SCW_TEM_SECRET_KEY: "s",
      EMAIL_FROM: "noreply@example.test",
      DOWNLOAD_TOKEN_SECRET: "test-secret-32-bytes-base64url-padded",
      ...extraEnv,
    },
    stderr: "pipe",
    stdout: "pipe",
  });

  return Promise.all([
    proc.exited,
    new Response(proc.stderr).text(),
  ]).then(([exitCode, stderr]) => ({ exitCode, stderr }));
}

describe("env.ts — production CORS guard", () => {
  it("throws when CORS_ORIGINS contains `*` in production", async () => {
    const { exitCode, stderr } = await bunImportEnv({
      NODE_ENV: "production",
      CORS_ORIGINS: "*",
    });
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("CORS_ORIGINS must not contain `*`");
  });

  it("throws when `*` appears alongside other origins in production", async () => {
    const { exitCode, stderr } = await bunImportEnv({
      NODE_ENV: "production",
      CORS_ORIGINS: "https://jtransfer.app,*",
    });
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("CORS_ORIGINS must not contain `*`");
  });

  it("accepts explicit production origins", async () => {
    const { exitCode, stderr } = await bunImportEnv({
      NODE_ENV: "production",
      CORS_ORIGINS: "https://jtransfer.app",
    });
    expect(exitCode).toBe(0);
    expect(stderr).toBe("");
  });

  it("does not enforce the guard outside production", async () => {
    const { exitCode } = await bunImportEnv({
      NODE_ENV: "development",
      CORS_ORIGINS: "*",
    });
    expect(exitCode).toBe(0);
  });
});

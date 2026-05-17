// Test fixtures for authenticated requests: create a user + active session
// and return the cookie header to attach to in-process requests.

import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../../src/db";
import { users, type User } from "../../src/db/schema";
import { createSession, SESSION_COOKIE_NAME } from "../../src/auth/sessions";
import { resolveIpContext, type IpContext } from "../../src/utils/ipContext";

/**
 * Fixture IpContext for in-process tests. Resolves against an empty headers
 * bag so country = "unknown", asn = null, city = null, and hmac() keys
 * against a constant null-byte input. Deterministic — never call MMDB.
 */
export function testIpContext(): IpContext {
  return resolveIpContext(new Headers());
}

export async function createTestUser(email?: string): Promise<User> {
  const [user] = await db
    .insert(users)
    .values({
      id: nanoid(),
      // Production always stores normaliseEmail()-lowercased emails. Mirror
      // that invariant here so confirmation/lookup logic behaves the same.
      email: (email ?? `test-${nanoid(8)}@jtransfer.test`).toLowerCase(),
    })
    .returning();
  if (!user) throw new Error("createTestUser: insert returned no row");
  return user;
}

export async function createAuthedUser(email?: string): Promise<{ user: User; cookie: string }> {
  const user = await createTestUser(email);
  const { token } = await createSession({
    userId: user.id,
    ipContext: testIpContext(),
    userAgent: "bun-test",
  });
  return { user, cookie: `${SESSION_COOKIE_NAME}=${token}` };
}

export async function loadUser(id: string): Promise<User | null> {
  const [u] = await db.select().from(users).where(eq(users.id, id)).limit(1);
  return u ?? null;
}

// Build a Request with the session cookie attached. Adds Origin on
// state-changing methods so the auth middleware's CSRF check accepts it.
export function authedRequest(
  cookie: string,
  url: string,
  init: RequestInit = {},
): Request {
  const headers = new Headers(init.headers);
  headers.set("Cookie", cookie);
  if (init.method && init.method !== "GET") {
    headers.set("Origin", process.env.APP_URL!);
  }
  return new Request(url, { ...init, headers });
}

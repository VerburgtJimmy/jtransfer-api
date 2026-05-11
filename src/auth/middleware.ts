// Elysia plugin that derives the current user from the session cookie on every
// request. Routes can read `me` from context; null when unauthenticated.
//
// Origin-header check on state-changing methods provides CSRF defence
// alongside SameSite=Lax (per audit doc 18 §6, ASVS 4.2.2).

import { Elysia } from "elysia";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { users, type User } from "../db/schema";
import { env } from "../config/env";
import { SESSION_COOKIE_NAME, validateSession } from "./sessions";

const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

const corsOrigins = env.CORS_ORIGINS.split(",")
  .map((o) => o.trim())
  .filter(Boolean);

function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) return false;
  if (corsOrigins.includes("*")) return true;
  return corsOrigins.includes(origin);
}

export const authPlugin = new Elysia({ name: "auth" })
  .derive({ as: "scoped" }, async ({ cookie, request }) => {
    // Origin check on state-changing requests. Read-only requests are
    // protected by the same-origin policy; the magic-link verify is a GET
    // whose token entropy is the auth (audit doc 18 §6).
    if (STATE_CHANGING_METHODS.has(request.method)) {
      const origin = request.headers.get("origin");
      if (origin && !isAllowedOrigin(origin)) {
        // Don't load `me` for cross-origin POSTs — caller will reject.
        return { me: null as User | null, sessionId: null as string | null, originRejected: true };
      }
    }

    const sessionCookie = cookie?.[SESSION_COOKIE_NAME];
    const token = sessionCookie?.value;
    if (!token || typeof token !== "string") {
      return { me: null as User | null, sessionId: null as string | null, originRejected: false };
    }

    const session = await validateSession(token);
    if (!session) {
      return { me: null as User | null, sessionId: null as string | null, originRejected: false };
    }

    const [user] = await db.select().from(users).where(eq(users.id, session.userId)).limit(1);
    if (!user || user.deletedAt) {
      return { me: null as User | null, sessionId: null as string | null, originRejected: false };
    }

    return {
      me: user as User | null,
      sessionId: session.id as string | null,
      originRejected: false,
    };
  });

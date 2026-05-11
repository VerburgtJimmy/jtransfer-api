// Auth-event audit log writer. See docs/audit/18-auth-security-baseline.md §8.
// 90-day retention enforced by a separate purge job.

import { db } from "../db";
import { authEvents } from "../db/schema";

export type AuthEventType =
  | "magic_link_requested"
  | "magic_link_consumed"
  | "login_success"
  | "logout"
  | "logout_all"
  | "session_revoked_admin";

interface LogAuthEventInput {
  eventType: AuthEventType;
  userId?: string | null;
  email?: string | null;
  ip?: string | null;
  userAgent?: string | null;
}

export async function logAuthEvent(input: LogAuthEventInput): Promise<void> {
  try {
    await db.insert(authEvents).values({
      eventType: input.eventType,
      userId: input.userId ?? null,
      email: input.email ?? null,
      ip: input.ip ?? null,
      userAgent: input.userAgent ?? null,
    });
  } catch (err) {
    // Never let audit-log writes break the auth flow itself. Surface to logs.
    console.error(`[auth-events] failed to log ${input.eventType}:`, err);
  }
}

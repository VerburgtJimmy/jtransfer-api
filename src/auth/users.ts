// User lookup + silent auto-create for the magic-link flow.
// See docs/audit/18-auth-security-baseline.md §5 + D-078.

import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../db";
import { users, type User } from "../db/schema";
import { normaliseEmail } from "./tokens";

export async function findUserByEmail(email: string): Promise<User | null> {
  const normalised = normaliseEmail(email);
  const [user] = await db.select().from(users).where(eq(users.email, normalised)).limit(1);
  return user ?? null;
}

export async function findOrCreateUserByEmail(email: string): Promise<User> {
  const normalised = normaliseEmail(email);
  const existing = await findUserByEmail(normalised);
  if (existing) return existing;

  // Race-safe: rely on the unique index. If two requests race, one will
  // conflict and we re-read.
  try {
    const [created] = await db
      .insert(users)
      .values({ id: nanoid(), email: normalised })
      .returning();
    if (created) return created;
  } catch {
    // Likely a unique-violation race; fall through to re-read.
  }

  const recheck = await findUserByEmail(normalised);
  if (recheck) return recheck;
  throw new Error("Failed to create or load user");
}

export async function findUserById(id: string): Promise<User | null> {
  const [user] = await db.select().from(users).where(eq(users.id, id)).limit(1);
  return user ?? null;
}

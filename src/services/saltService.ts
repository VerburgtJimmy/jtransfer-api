// Rotating per-purpose HMAC salts for IP correlation.
// See audit doc 19 §4.3, ADR-0002, D-082.
//
// Two namespaces with intentionally different cadences:
//
//   - 'auth_events'  — rotate every 24h, retain 30d. Privacy-critical:
//                      cross-event correlation is bounded to one day.
//   - 'ratelimit'    — rotate every 35d, retain 35d. Picked as
//                      max(rate-limit window) + 5d buffer so a single
//                      salt always covers a full monthlyUploadGB (30d)
//                      window. The counter's TTL expires before the
//                      salt does, so the Redis key naturally drops out
//                      when the window ends — no rehash needed.
//
// HMAC is one-way: once a counter is keyed `HMAC(salt_old, ip)`, we
// cannot migrate it to `HMAC(salt_new, ip)`. Cadences therefore differ
// for access-pattern reasons, not arbitrary choice.

import { randomBytes } from "node:crypto";
import { and, desc, eq, isNull, lt } from "drizzle-orm";
import { db } from "../db";
import { salts, type Salt } from "../db/schema";

export type SaltNamespace = "auth_events" | "ratelimit";

interface NamespaceConfig {
  rotateAfterMs: number;
  retainForMs: number;
}

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const NAMESPACES: Record<SaltNamespace, NamespaceConfig> = {
  auth_events: { rotateAfterMs: 24 * HOUR_MS, retainForMs: 30 * DAY_MS },
  ratelimit: { rotateAfterMs: 35 * DAY_MS, retainForMs: 35 * DAY_MS },
};

// Per-process cache of the active salt per namespace. Invalidated on
// rotation in this process; other processes pick up the new salt within
// CACHE_TTL_MS.
const CACHE_TTL_MS = 60 * 1000;
const activeCache = new Map<SaltNamespace, { salt: Salt; expiresAt: number }>();

/**
 * Return the currently-active salt for the namespace, creating one if
 * none exists. Callers HMAC their input under `salt.secret` and persist
 * `salt.id` alongside the result so verification can re-key later.
 */
export async function getActiveSalt(namespace: SaltNamespace): Promise<Salt> {
  const cached = activeCache.get(namespace);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.salt;
  }

  const [existing] = await db
    .select()
    .from(salts)
    .where(and(eq(salts.namespace, namespace), isNull(salts.retiredAt)))
    .orderBy(desc(salts.createdAt))
    .limit(1);

  if (existing) {
    activeCache.set(namespace, { salt: existing, expiresAt: Date.now() + CACHE_TTL_MS });
    return existing;
  }

  return await mintSalt(namespace);
}

/**
 * Fetch a specific salt by id — used by verification paths that need to
 * reproduce a correlator under a past (but not yet purged) salt.
 */
export async function getSaltById(id: number): Promise<Salt | null> {
  const [row] = await db.select().from(salts).where(eq(salts.id, id)).limit(1);
  return row ?? null;
}

/**
 * Insert a fresh salt for the namespace and retire the previously-active
 * one in the same transaction. Caller is responsible for invalidating
 * any in-process state derived from the old salt.
 */
async function mintSalt(namespace: SaltNamespace): Promise<Salt> {
  const secret = randomBytes(32);
  const inserted = await db.transaction(async (tx) => {
    await tx
      .update(salts)
      .set({ retiredAt: new Date() })
      .where(and(eq(salts.namespace, namespace), isNull(salts.retiredAt)));
    const [row] = await tx
      .insert(salts)
      .values({ namespace, secret })
      .returning();
    return row;
  });
  if (!inserted) {
    throw new Error(`[saltService] failed to mint salt for ${namespace}`);
  }
  activeCache.set(namespace, { salt: inserted, expiresAt: Date.now() + CACHE_TTL_MS });
  return inserted;
}

/**
 * Periodic rotation + purge. Called by cleanup.service.ts.
 *
 * For each namespace:
 *   1. If the active salt is older than `rotateAfterMs`, mint a new one
 *      and retire the old. The retired row stays for `retainForMs`
 *      so existing correlators remain verifiable.
 *   2. Delete any row where `retired_at < now - retainForMs`. Dependent
 *      `auth_events.salt_id` columns are `ON DELETE SET NULL` —
 *      surviving rows lose their salt_id and become permanently
 *      un-correlatable, which is the goal.
 */
export async function rotateSalts(now: Date = new Date()): Promise<{
  rotated: SaltNamespace[];
  purged: number;
}> {
  const rotated: SaltNamespace[] = [];
  let purged = 0;

  for (const [ns, cfg] of Object.entries(NAMESPACES) as [SaltNamespace, NamespaceConfig][]) {
    const active = await getActiveSalt(ns);
    if (now.getTime() - active.createdAt.getTime() >= cfg.rotateAfterMs) {
      await mintSalt(ns);
      rotated.push(ns);
    }

    const purgeCutoff = new Date(now.getTime() - cfg.retainForMs);
    const deleted = await db
      .delete(salts)
      .where(and(eq(salts.namespace, ns), lt(salts.retiredAt, purgeCutoff)))
      .returning({ id: salts.id });
    purged += deleted.length;
  }

  return { rotated, purged };
}

// Test helper — never call from production code.
export function __resetSaltCacheForTests(): void {
  activeCache.clear();
}

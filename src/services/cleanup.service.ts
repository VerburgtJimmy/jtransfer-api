import { lt, or, and, isNotNull } from 'drizzle-orm';
import { getExpiredTransfers, getAbandonedTransfers, deleteExpiredTransfer, abortTransfer } from './file.service';
import { db } from '../db';
import { authEvents, magicLinkTokens, sessions } from '../db/schema';

export async function cleanupExpiredTransfers(): Promise<number> {
  const expiredTransfers = await getExpiredTransfers();
  let count = 0;

  for (const transfer of expiredTransfers) {
    try {
      await deleteExpiredTransfer(transfer);
      count++;
    } catch (error) {
      console.error(`[cleanup] Failed to delete expired transfer ${transfer.id}:`, error);
    }
  }

  return count;
}

export async function cleanupAbandonedTransfers(): Promise<number> {
  const abandoned = await getAbandonedTransfers();
  let count = 0;

  for (const transfer of abandoned) {
    try {
      await abortTransfer(transfer.id);
      count++;
    } catch (error) {
      console.error(`[cleanup] Failed to delete abandoned transfer ${transfer.id}:`, error);
    }
  }

  return count;
}

// Auth-related purges. See docs/audit/18-auth-security-baseline.md §8.
export async function cleanupAuthArtefacts(): Promise<{ tokens: number; sessions: number; events: number }> {
  const now = new Date();
  // Magic-link tokens: drop rows that expired or were consumed > 1h ago.
  const tokenCutoff = new Date(now.getTime() - 60 * 60 * 1000);
  const tokens = await db
    .delete(magicLinkTokens)
    .where(
      or(
        lt(magicLinkTokens.expiresAt, tokenCutoff),
        and(isNotNull(magicLinkTokens.consumedAt), lt(magicLinkTokens.consumedAt, tokenCutoff)),
      ),
    )
    .returning({ id: magicLinkTokens.id });

  // Sessions: drop rows past absolute expiry, or revoked > 7 days ago.
  const revokeCutoff = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const sess = await db
    .delete(sessions)
    .where(
      or(
        lt(sessions.absoluteExpiresAt, now),
        and(isNotNull(sessions.revokedAt), lt(sessions.revokedAt, revokeCutoff)),
      ),
    )
    .returning({ id: sessions.id });

  // Auth events: 90-day retention.
  const eventCutoff = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
  const events = await db
    .delete(authEvents)
    .where(lt(authEvents.createdAt, eventCutoff))
    .returning({ id: authEvents.id });

  return { tokens: tokens.length, sessions: sess.length, events: events.length };
}

export function startCleanupJob(): void {
  const INTERVAL_MS = 15 * 60 * 1000; // 15 minutes

  const runCleanup = async () => {
    const expired = await cleanupExpiredTransfers();
    const abandoned = await cleanupAbandonedTransfers();
    if (expired + abandoned > 0) {
      console.log(`[cleanup] Deleted ${expired} expired, ${abandoned} abandoned transfers`);
    }
    try {
      const auth = await cleanupAuthArtefacts();
      if (auth.tokens + auth.sessions + auth.events > 0) {
        console.log(
          `[cleanup] Auth: ${auth.tokens} tokens, ${auth.sessions} sessions, ${auth.events} events purged`,
        );
      }
    } catch (err) {
      console.error('[cleanup] Auth purge failed:', err);
    }
  };

  runCleanup();
  setInterval(runCleanup, INTERVAL_MS);
}

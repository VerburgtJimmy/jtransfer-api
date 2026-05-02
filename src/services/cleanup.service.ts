import { getExpiredTransfers, getAbandonedTransfers, deleteExpiredTransfer, abortTransfer } from './file.service';

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

export function startCleanupJob(): void {
  const INTERVAL_MS = 15 * 60 * 1000; // 15 minutes

  const runCleanup = async () => {
    const expired = await cleanupExpiredTransfers();
    const abandoned = await cleanupAbandonedTransfers();
    if (expired + abandoned > 0) {
      console.log(`[cleanup] Deleted ${expired} expired, ${abandoned} abandoned transfers`);
    }
  };

  runCleanup();
  setInterval(runCleanup, INTERVAL_MS);
}

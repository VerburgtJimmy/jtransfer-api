import { getExpiredTransfers, getFilesForTransfer, markTransferAsDeleted, markFileAsDeleted } from './file.service';
import { deleteFromR2 } from './r2.service';

export async function cleanupExpiredTransfers(): Promise<number> {
  const expiredTransfers = await getExpiredTransfers();
  let deletedCount = 0;

  for (const transfer of expiredTransfers) {
    try {
      // Get all files for this transfer
      const files = await getFilesForTransfer(transfer.id);

      // Delete each file from R2 storage
      for (const file of files) {
        try {
          await deleteFromR2(file.r2Key);
          await markFileAsDeleted(file.id);
        } catch (error) {
          console.error(`Failed to delete file ${file.id}:`, error);
        }
      }

      // Mark transfer as deleted
      await markTransferAsDeleted(transfer.id);
      deletedCount++;
      console.log(`Deleted expired transfer: ${transfer.id} (${files.length} files)`);
    } catch (error) {
      console.error(`Failed to delete transfer ${transfer.id}:`, error);
    }
  }

  return deletedCount;
}

// Start cleanup interval (runs every hour)
export function startCleanupJob(): void {
  const HOUR_MS = 60 * 60 * 1000;

  // Run immediately on startup
  cleanupExpiredTransfers().then((count) => {
    if (count > 0) {
      console.log(`Initial cleanup: deleted ${count} expired transfers`);
    }
  });

  // Then run every hour
  setInterval(async () => {
    const count = await cleanupExpiredTransfers();
    if (count > 0) {
      console.log(`Cleanup job: deleted ${count} expired transfers`);
    }
  }, HOUR_MS);
}

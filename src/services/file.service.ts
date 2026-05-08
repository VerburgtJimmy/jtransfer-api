import { eq, and, lt, sql } from 'drizzle-orm';
import { nanoid } from 'nanoid';
import { db } from '../db';
import { transfers, files, transferEvents, type NewTransfer, type NewFile, type Transfer, type File } from '../db/schema';

// Transfer operations
export async function createTransfer(
  expiresInHours: number,
  password?: string,
  maxDownloads?: number
): Promise<Transfer> {
  const id = nanoid();
  const expiresAt = new Date();
  expiresAt.setTime(expiresAt.getTime() + expiresInHours * 60 * 60 * 1000);

  // Hash password if provided (Argon2id via Bun)
  const passwordHash = password ? await Bun.password.hash(password) : null;

  const [transfer] = await db.insert(transfers).values({
    id,
    expiresAt,
    passwordHash,
    maxDownloads: maxDownloads ?? null,
    isCompleted: false
  }).returning();

  return transfer;
}

export async function completeTransfer(id: string): Promise<void> {
  await db
    .update(transfers)
    .set({ isCompleted: true })
    .where(eq(transfers.id, id));
}

export async function verifyTransferPassword(transferId: string, password: string): Promise<boolean> {
  const transfer = await getTransferById(transferId);
  if (!transfer || !transfer.passwordHash) return false;

  return Bun.password.verify(password, transfer.passwordHash);
}

export async function getTransferById(id: string): Promise<Transfer | null> {
  const [transfer] = await db
    .select()
    .from(transfers)
    .where(
      and(
        eq(transfers.id, id),
        eq(transfers.isDeleted, false)
      )
    )
    .limit(1);

  return transfer ?? null;
}

export async function getValidTransfer(id: string): Promise<Transfer | null> {
  const transfer = await getTransferById(id);

  if (!transfer) return null;

  // Check if expired
  if (new Date(transfer.expiresAt) < new Date()) {
    return null;
  }

  // Check download limit
  if (transfer.maxDownloads !== null && transfer.downloadCount >= transfer.maxDownloads) {
    return null;
  }

  return transfer;
}

export async function getCompletedValidTransfer(id: string): Promise<Transfer | null> {
  const transfer = await getValidTransfer(id);
  if (!transfer) return null;

  // Only expose completed transfers to downloaders
  if (!transfer.isCompleted) return null;

  return transfer;
}

export async function incrementTransferDownloadCount(id: string): Promise<void> {
  await db
    .update(transfers)
    .set({ downloadCount: sql`${transfers.downloadCount} + 1` })
    .where(eq(transfers.id, id));
}

async function logTransferEvent(
  event: 'completed' | 'expired' | 'aborted',
  transfer: Transfer,
  fileCount: number,
  totalBytes: number
): Promise<void> {
  try {
    await db.insert(transferEvents).values({
      event,
      transferId: transfer.id,
      fileCount,
      totalBytes,
      downloadCount: transfer.downloadCount,
      hasPassword: transfer.passwordHash !== null,
      maxDownloads: transfer.maxDownloads ?? null,
    });
  } catch (err) {
    // Logging must never break the main flow
    console.error('[log] Failed to write transfer event:', err);
  }
}

async function hardDeleteTransfer(id: string): Promise<void> {
  await db.delete(files).where(eq(files.transferId, id));
  await db.delete(transfers).where(eq(transfers.id, id));
}

export async function abortTransfer(id: string): Promise<void> {
  const { deleteFromR2 } = await import('./r2.service');
  const transfer = await getTransferById(id);
  const transferFiles = await getFilesForTransfer(id);

  const totalBytes = transferFiles.reduce((sum, f) => sum + f.size, 0);

  for (const file of transferFiles) {
    try {
      await deleteFromR2(file.r2Key);
    } catch {
      // best-effort — DB cleanup proceeds regardless
    }
  }

  if (transfer) {
    await logTransferEvent('aborted', transfer, transferFiles.length, totalBytes);
  }

  await hardDeleteTransfer(id);
}

export async function deleteExpiredTransfer(transfer: Transfer): Promise<void> {
  const { deleteFromR2 } = await import('./r2.service');
  const transferFiles = await getFilesForTransfer(transfer.id);
  const totalBytes = transferFiles.reduce((sum, f) => sum + f.size, 0);

  for (const file of transferFiles) {
    try {
      await deleteFromR2(file.r2Key);
    } catch (err) {
      console.error(`[cleanup] Failed to delete R2 object ${file.r2Key}:`, err);
    }
  }

  await logTransferEvent('expired', transfer, transferFiles.length, totalBytes);
  await hardDeleteTransfer(transfer.id);
}

export async function logCompletedTransfer(transfer: Transfer): Promise<void> {
  const transferFiles = await getFilesForTransfer(transfer.id);
  const totalBytes = transferFiles.reduce((sum, f) => sum + f.size, 0);
  await logTransferEvent('completed', transfer, transferFiles.length, totalBytes);
}

export async function markTransferAsDeleted(id: string): Promise<void> {
  await db
    .update(transfers)
    .set({ isDeleted: true })
    .where(eq(transfers.id, id));
}

// File operations
export async function createFile(data: Omit<NewFile, 'id' | 'r2Key' | 'storageType'>): Promise<File> {
  const id = nanoid();
  const storageKey = `uploads/${data.transferId}/${id}`;

  const [file] = await db.insert(files).values({
    id,
    r2Key: storageKey,
    ...data
  }).returning();

  return file;
}

export async function getFilesByTransferId(transferId: string): Promise<File[]> {
  return db
    .select()
    .from(files)
    .where(
      and(
        eq(files.transferId, transferId),
        eq(files.isDeleted, false)
      )
    );
}

export async function getTransferTotalSize(transferId: string): Promise<number> {
  const [row] = await db
    .select({
      total: sql<number>`coalesce(sum(${files.size}), 0)`
    })
    .from(files)
    .where(
      and(
        eq(files.transferId, transferId),
        eq(files.isDeleted, false)
      )
    );

  // postgres.js returns bigint aggregate results as strings — coerce explicitly
  return Number(row?.total ?? 0);
}

export async function getFileById(id: string): Promise<File | null> {
  const [file] = await db
    .select()
    .from(files)
    .where(
      and(
        eq(files.id, id),
        eq(files.isDeleted, false)
      )
    )
    .limit(1);

  return file ?? null;
}

export async function markFileAsDeleted(id: string): Promise<void> {
  await db
    .update(files)
    .set({ isDeleted: true })
    .where(eq(files.id, id));
}

// Cleanup operations
export async function getExpiredTransfers(): Promise<Transfer[]> {
  return db
    .select()
    .from(transfers)
    .where(
      and(
        eq(transfers.isDeleted, false),
        lt(transfers.expiresAt, new Date())
      )
    );
}

// Incomplete transfers older than 30 minutes — upload was abandoned or failed
export async function getAbandonedTransfers(): Promise<Transfer[]> {
  const cutoff = new Date(Date.now() - 30 * 60 * 1000);
  return db
    .select()
    .from(transfers)
    .where(
      and(
        eq(transfers.isDeleted, false),
        eq(transfers.isCompleted, false),
        lt(transfers.createdAt, cutoff)
      )
    );
}

export async function getFilesForTransfer(transferId: string): Promise<File[]> {
  return db
    .select()
    .from(files)
    .where(eq(files.transferId, transferId));
}

import { eq, and, lt, sql } from 'drizzle-orm';
import { nanoid } from 'nanoid';
import { db } from '../db';
import { transfers, files, type NewTransfer, type NewFile, type Transfer, type File } from '../db/schema';

// Transfer operations
export async function createTransfer(expiresInDays: number, password?: string): Promise<Transfer> {
  const id = nanoid();
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + expiresInDays);

  // Hash password if provided (Argon2id via Bun)
  const passwordHash = password ? await Bun.password.hash(password) : null;

  const [transfer] = await db.insert(transfers).values({
    id,
    expiresAt,
    passwordHash
  }).returning();

  return transfer;
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

export async function incrementTransferDownloadCount(id: string): Promise<void> {
  await db
    .update(transfers)
    .set({ downloadCount: sql`${transfers.downloadCount} + 1` })
    .where(eq(transfers.id, id));
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

export async function getFilesForTransfer(transferId: string): Promise<File[]> {
  return db
    .select()
    .from(files)
    .where(eq(files.transferId, transferId));
}

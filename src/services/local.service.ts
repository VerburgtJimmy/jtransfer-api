import { mkdir, writeFile, readFile, unlink, stat } from 'fs/promises';
import { join, dirname } from 'path';
import { env } from '../config/env';

const STORAGE_DIR = env.LOCAL_STORAGE_PATH;

export async function saveFile(key: string, data: Buffer): Promise<void> {
  const filePath = join(STORAGE_DIR, key);
  // Ensure the full directory path exists (including nested directories)
  await mkdir(dirname(filePath), { recursive: true });
  await writeFile(filePath, data);
}

export async function getFile(key: string): Promise<Buffer> {
  const filePath = join(STORAGE_DIR, key);
  return readFile(filePath);
}

export async function deleteFile(key: string): Promise<void> {
  const filePath = join(STORAGE_DIR, key);
  try {
    await unlink(filePath);
  } catch (err) {
    // File may not exist
  }
}

export async function getFileSize(key: string): Promise<number> {
  const filePath = join(STORAGE_DIR, key);
  const stats = await stat(filePath);
  return stats.size;
}

export function getLocalFilePath(key: string): string {
  return join(STORAGE_DIR, key);
}

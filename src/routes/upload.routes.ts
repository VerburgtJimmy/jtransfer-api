import { Elysia, t } from 'elysia';
import { createTransfer, createFile } from '../services/file.service';
import { saveFile } from '../services/local.service';
import { checkRateLimit, rateLimiters } from '../services/ratelimit.service';
import { env } from '../config/env';

// nanoid validation pattern (21 chars, URL-safe alphabet)
const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;
function isValidNanoId(id: string): boolean {
  return NANOID_PATTERN.test(id);
}

const MIN_PASSWORD_LENGTH = 8;

export const uploadRoutes = new Elysia({ prefix: '/api/upload' })
  // Create a new transfer (group of files)
  .post('/create-transfer', async ({ body, request, set }) => {
    const ip = request.headers.get('x-forwarded-for') ?? 'unknown';

    const rateLimit = await checkRateLimit(ip, rateLimiters.upload);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Rate limit exceeded. Try again later.' };
    }

    const { expiresInDays, password } = body;

    // Validate expiration (1 or 3 days)
    if (expiresInDays !== 1 && expiresInDays !== 3) {
      set.status = 400;
      return { error: 'Invalid expiration. Must be 1 or 3 days.' };
    }

    // Validate password if provided (minimum 8 characters for security)
    if (password !== undefined && password.length < MIN_PASSWORD_LENGTH) {
      set.status = 400;
      return { error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` };
    }

    const transfer = await createTransfer(expiresInDays, password);

    return {
      transferId: transfer.id,
      expiresAt: transfer.expiresAt
    };
  }, {
    body: t.Object({
      expiresInDays: t.Number(),
      password: t.Optional(t.String())
    })
  })

  // Add a file to a transfer (direct upload via FormData)
  .post('/add-file', async ({ request, set }) => {
    try {
      const ip = request.headers.get('x-forwarded-for') ?? 'unknown';

      const rateLimit = await checkRateLimit(ip, rateLimiters.upload);
      if (!rateLimit.allowed) {
        set.status = 429;
        set.headers['Retry-After'] = String(rateLimit.resetIn);
        return { error: 'Rate limit exceeded. Try again later.' };
      }

      // Parse FormData
      const formData = await request.formData();
      const transferId = formData.get('transferId') as string;
      const contentType = formData.get('contentType') as string;
      const encryptedName = formData.get('encryptedName') as string;
      const encryptedNameIv = formData.get('encryptedNameIv') as string;
      const fileIv = formData.get('fileIv') as string;
      const fileBlob = formData.get('file') as Blob;

      if (!transferId || !encryptedName || !encryptedNameIv || !fileIv || !fileBlob) {
        set.status = 400;
        return { error: 'Missing required fields' };
      }

      // Validate transferId format to prevent path traversal
      if (!isValidNanoId(transferId)) {
        set.status = 400;
        return { error: 'Invalid transfer ID' };
      }

      // Convert Blob to Buffer
      const arrayBuffer = await fileBlob.arrayBuffer();
      const fileBuffer = Buffer.from(arrayBuffer);
      const size = fileBuffer.length;

      // Validate file size
      if (size > env.MAX_FILE_SIZE) {
        set.status = 400;
        return { error: `File too large. Maximum size is ${env.MAX_FILE_SIZE / (1024 * 1024)}MB` };
      }

      // Create file record
      const file = await createFile({
        transferId,
        encryptedName,
        encryptedNameIv,
        fileIv,
        size,
        mimeType: contentType || 'application/octet-stream'
      });

      // Save file to local storage
      await saveFile(file.r2Key, fileBuffer);

      return {
        fileId: file.id
      };
    } catch (err) {
      console.error('Upload error:', err);
      set.status = 500;
      return { error: err instanceof Error ? err.message : 'Upload failed' };
    }
  })

  // Complete the transfer (called after all files are uploaded)
  .post('/complete', async ({ body, set }) => {
    const { transferId } = body;

    // Validate transferId format
    if (!isValidNanoId(transferId)) {
      set.status = 400;
      return { error: 'Invalid transfer ID' };
    }

    return {
      success: true,
      shareUrl: `/d/${transferId}`
    };
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 })
    })
  });

import { Elysia, t } from 'elysia';
import { createTransfer, createFile, getTransferTotalSize, getValidTransfer } from '../services/file.service';
import { getPresignedUploadUrl } from '../services/r2.service';
import { checkRateLimit, checkVolumeLimit, rateLimiters } from '../services/ratelimit.service';
import { env } from '../config/env';
import { normalizeClientIp } from '../utils/ip';
import { exceedsTotalLimit } from '../utils/limits';

// nanoid validation pattern (21 chars, URL-safe alphabet)
const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;
function isValidNanoId(id: string): boolean {
  return NANOID_PATTERN.test(id);
}

const MIN_PASSWORD_LENGTH = 8;

export const uploadRoutes = new Elysia({ prefix: '/api/upload' })
  // Create a new transfer (group of files)
  .post('/create-transfer', async ({ body, request, set }) => {
    const ip = normalizeClientIp(request.headers.get('x-forwarded-for'));

    // Per-minute rate limit
    const rateLimit = await checkRateLimit(ip, rateLimiters.upload);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Rate limit exceeded. Try again later.' };
    }

    // Daily transfer limit
    const dailyLimit = await checkRateLimit(ip, rateLimiters.dailyTransfers);
    if (!dailyLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(dailyLimit.resetIn);
      return { error: `Daily limit reached. You can create ${rateLimiters.dailyTransfers.maxRequests} transfers per day.` };
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

  // Request a presigned URL for direct upload to R2
  .post('/request-upload-url', async ({ body, request, set }) => {
    const ip = normalizeClientIp(request.headers.get('x-forwarded-for'));

    const rateLimit = await checkRateLimit(ip, rateLimiters.upload);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Rate limit exceeded. Try again later.' };
    }

    const { transferId, contentType, encryptedName, encryptedNameIv, fileIv, size } = body;

    // Validate transferId format to prevent path traversal
    if (!isValidNanoId(transferId)) {
      set.status = 400;
      return { error: 'Invalid transfer ID' };
    }

    const transfer = await getValidTransfer(transferId);
    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    // Validate file size
    if (size > env.MAX_FILE_SIZE) {
      set.status = 400;
      return { error: `File too large. Maximum size is ${env.MAX_FILE_SIZE / (1024 * 1024)}MB` };
    }

    const currentTotal = await getTransferTotalSize(transferId);
    if (exceedsTotalLimit(currentTotal, size, env.MAX_TOTAL_UPLOAD_SIZE)) {
      set.status = 400;
      return { error: `Transfer too large. Maximum total size is ${env.MAX_TOTAL_UPLOAD_SIZE / (1024 * 1024)}MB` };
    }

    // Monthly upload volume limit per IP
    const volumeLimit = await checkVolumeLimit(ip, {
      ...rateLimiters.monthlyUploadVolume,
      increment: size,
    });
    if (!volumeLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(volumeLimit.resetIn);
      return { error: 'Monthly upload limit reached. Please try again later.' };
    }

    // Create file record in database
    const file = await createFile({
      transferId,
      encryptedName,
      encryptedNameIv,
      fileIv,
      size,
      mimeType: contentType || 'application/octet-stream'
    });

    // Generate presigned upload URL
    const presigned = await getPresignedUploadUrl(
      file.r2Key,
      'application/octet-stream' // Always octet-stream since content is encrypted
    );

    return {
      fileId: file.id,
      uploadUrl: presigned.url,
      expiresAt: presigned.expiresAt.toISOString()
    };
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 }),
      contentType: t.String(),
      encryptedName: t.String(),
      encryptedNameIv: t.String(),
      fileIv: t.String(),
      size: t.Number()
    })
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

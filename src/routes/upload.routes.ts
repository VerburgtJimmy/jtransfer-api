import { Elysia, t } from 'elysia';
import { createTransfer, completeTransfer, abortTransfer, logCompletedTransfer, createFile, getTransferTotalSize, getValidTransfer, getTransferById, getFilesByTransferId } from '../services/file.service';
import { getPresignedUploadUrl, headObject } from '../services/r2.service';
import { checkRateLimit, checkVolumeLimit, rateLimiters } from '../services/ratelimit.service';
import { env } from '../config/env';
import { normalizeClientIp } from '../utils/ip';
import { exceedsTotalLimit } from '../utils/limits';
import { authPlugin } from '../auth/middleware';

// nanoid validation pattern (21 chars, URL-safe alphabet)
const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;
function isValidNanoId(id: string): boolean {
  return NANOID_PATTERN.test(id);
}

const MIN_PASSWORD_LENGTH = 8;

export const uploadRoutes = new Elysia({ prefix: '/api/upload' })
  .use(authPlugin)

  // Create a new transfer (group of files). If a session is present,
  // the transfer is owned by that user; otherwise it's anonymous
  // (user_id NULL). Ownership is set at creation and never re-assigned.
  // See docs/audit/20-transfer-ownership.md §2.
  .post('/create-transfer', async ({ body, request, me, set }) => {
    const ip = normalizeClientIp(request.headers.get('cf-connecting-ip'), request.headers.get('x-forwarded-for'));

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

    const { expiresInHours, password, maxDownloads } = body;

    // Validate expiration
    const ALLOWED_HOURS = [1, 6, 12, 24, 72] as const;
    if (!ALLOWED_HOURS.includes(expiresInHours as typeof ALLOWED_HOURS[number])) {
      set.status = 400;
      return { error: 'Invalid expiration. Allowed values: 1, 6, 12, 24, 72 hours.' };
    }

    // Validate password if provided (minimum 8 characters for security)
    if (password !== undefined && password.length < MIN_PASSWORD_LENGTH) {
      set.status = 400;
      return { error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` };
    }

    // Validate maxDownloads if provided
    if (maxDownloads !== undefined && (maxDownloads < 1 || maxDownloads > 100)) {
      set.status = 400;
      return { error: 'maxDownloads must be between 1 and 100.' };
    }

    const transfer = await createTransfer(expiresInHours, password, maxDownloads, me?.id ?? null);

    return {
      transferId: transfer.id,
      expiresAt: transfer.expiresAt
    };
  }, {
    body: t.Object({
      expiresInHours: t.Number(),
      password: t.Optional(t.String({ maxLength: 256 })),
      maxDownloads: t.Optional(t.Number({ minimum: 1, maximum: 100 }))
    })
  })

  // Request a presigned URL for direct upload to R2
  .post('/request-upload-url', async ({ body, request, me, set }) => {
    const ip = normalizeClientIp(request.headers.get('cf-connecting-ip'), request.headers.get('x-forwarded-for'));

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

    // Owner-only on owned transfers; non-owner returns 404 (not 403) to
    // avoid leaking existence. See docs/audit/20-transfer-ownership.md §4.
    if (transfer.userId !== null && transfer.userId !== me?.id) {
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

    // Generate presigned upload URL. Binding ContentLength here means R2
    // rejects any PUT whose body size differs from `size` — closes the
    // limit-bypass path called out in audit doc 25 §A.2.
    const presigned = await getPresignedUploadUrl(
      file.r2Key,
      'application/octet-stream', // Always octet-stream since content is encrypted
      size,
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
  .post('/complete', async ({ body, me, set }) => {
    const { transferId } = body;

    // Validate transferId format
    if (!isValidNanoId(transferId)) {
      set.status = 400;
      return { error: 'Invalid transfer ID' };
    }

    const transfer = await getValidTransfer(transferId);
    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    // Owner-only on owned transfers (see docs/audit/20 §4).
    if (transfer.userId !== null && transfer.userId !== me?.id) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    // Verify every declared file is actually in storage at the expected
    // size before marking the transfer live. Without this the client
    // could call /complete after a partial or skipped upload and leave
    // recipients with broken downloads (audit doc 25 §A.3).
    const transferFiles = await getFilesByTransferId(transferId);
    if (transferFiles.length === 0) {
      set.status = 409;
      return { error: 'Transfer has no files to complete.' };
    }
    for (const file of transferFiles) {
      const head = await headObject(file.r2Key);
      if (!head) {
        set.status = 409;
        return { error: 'Upload incomplete — one or more files are missing.' };
      }
      if (head.size !== file.size) {
        set.status = 409;
        return { error: 'Upload incomplete — file size mismatch.' };
      }
    }

    await completeTransfer(transferId);
    logCompletedTransfer(transfer).catch(() => {}); // fire-and-forget, never blocks response

    return {
      success: true,
      shareUrl: `/d/${transferId}`
    };
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 })
    })
  })

  // Abort an in-progress transfer — deletes any already-uploaded files from R2
  .post('/abort', async ({ body, me, set }) => {
    const { transferId } = body;

    if (!isValidNanoId(transferId)) {
      set.status = 400;
      return { error: 'Invalid transfer ID' };
    }

    // Only allow aborting incomplete transfers (completed ones are live)
    const transfer = await getTransferById(transferId);
    if (!transfer || transfer.isDeleted) {
      set.status = 404;
      return { error: 'Transfer not found' };
    }

    // Owner-only on owned transfers (see docs/audit/20 §4).
    if (transfer.userId !== null && transfer.userId !== me?.id) {
      set.status = 404;
      return { error: 'Transfer not found' };
    }

    if (transfer.isCompleted) {
      set.status = 409;
      return { error: 'Transfer is already completed' };
    }

    await abortTransfer(transferId);
    return { success: true };
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 })
    })
  });

import { Elysia, t } from 'elysia';
import { getValidTransfer, getFilesByTransferId, getFileById, incrementTransferDownloadCount, verifyTransferPassword } from '../services/file.service';
import { getPresignedDownloadUrl } from '../services/r2.service';
import { checkRateLimit, rateLimiters } from '../services/ratelimit.service';
import { normalizeClientIp } from '../utils/ip';

// nanoid validation pattern (21 chars, URL-safe alphabet)
const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;
function isValidNanoId(id: string): boolean {
  return NANOID_PATTERN.test(id);
}

export const downloadRoutes = new Elysia({ prefix: '/api/download' })
  // Get transfer metadata with all files
  .get('/transfer/:id', async ({ params, request, set }) => {
    // Validate ID format first (prevents path traversal)
    if (!isValidNanoId(params.id)) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    const ip = normalizeClientIp(request.headers.get('x-forwarded-for'));

    const rateLimit = await checkRateLimit(ip, rateLimiters.download);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Rate limit exceeded. Try again later.' };
    }

    const transfer = await getValidTransfer(params.id);

    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    // Get all files for this transfer
    const files = await getFilesByTransferId(transfer.id);

    // If password protected, return limited metadata
    if (transfer.passwordHash) {
      return {
        id: transfer.id,
        expiresAt: transfer.expiresAt,
        passwordRequired: true,
        fileCount: files.length
      };
    }

    // Increment download count
    await incrementTransferDownloadCount(transfer.id);

    return {
      id: transfer.id,
      expiresAt: transfer.expiresAt,
      passwordRequired: false,
      files: files.map(file => ({
        id: file.id,
        encryptedName: file.encryptedName,
        encryptedNameIv: file.encryptedNameIv,
        fileIv: file.fileIv,
        size: file.size,
        mimeType: file.mimeType
      }))
    };
  }, {
    params: t.Object({
      id: t.String()
    })
  })

  // Verify password and get full metadata
  .post('/transfer/:id/verify', async ({ params, body, request, set }) => {
    // Validate ID format first
    if (!isValidNanoId(params.id)) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    const ip = normalizeClientIp(request.headers.get('x-forwarded-for'));

    const rateLimit = await checkRateLimit(ip, rateLimiters.password);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Too many password attempts. Try again later.' };
    }

    const transfer = await getValidTransfer(params.id);

    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    if (!transfer.passwordHash) {
      set.status = 400;
      return { error: 'Transfer is not password protected' };
    }

    const isValid = await verifyTransferPassword(params.id, body.password);

    if (!isValid) {
      set.status = 401;
      return { error: 'Incorrect password' };
    }

    // Get all files for this transfer
    const files = await getFilesByTransferId(transfer.id);

    // Increment download count
    await incrementTransferDownloadCount(transfer.id);

    return {
      id: transfer.id,
      expiresAt: transfer.expiresAt,
      passwordRequired: false,
      files: files.map(file => ({
        id: file.id,
        encryptedName: file.encryptedName,
        encryptedNameIv: file.encryptedNameIv,
        fileIv: file.fileIv,
        size: file.size,
        mimeType: file.mimeType
      }))
    };
  }, {
    params: t.Object({
      id: t.String({ minLength: 21, maxLength: 21 })
    }),
    body: t.Object({
      password: t.String({ maxLength: 256 })
    })
  })

  // Get presigned download URL for a file
  .get('/file/:id/url', async ({ params, request, set }) => {
    // Validate ID format first
    if (!isValidNanoId(params.id)) {
      set.status = 404;
      return { error: 'File not found' };
    }

    const ip = normalizeClientIp(request.headers.get('x-forwarded-for'));

    // Per-minute rate limit
    const rateLimit = await checkRateLimit(ip, rateLimiters.download);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Rate limit exceeded. Try again later.' };
    }

    // Daily download limit
    const dailyLimit = await checkRateLimit(ip, rateLimiters.dailyDownloads);
    if (!dailyLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(dailyLimit.resetIn);
      return { error: `Daily download limit reached. You can download ${rateLimiters.dailyDownloads.maxRequests} files per day.` };
    }

    const file = await getFileById(params.id);

    if (!file) {
      set.status = 404;
      return { error: 'File not found' };
    }

    // Verify the transfer is still valid
    const transfer = await getValidTransfer(file.transferId);
    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer has expired' };
    }

    // Generate presigned download URL
    const presigned = await getPresignedDownloadUrl(file.r2Key);

    return {
      downloadUrl: presigned.url,
      expiresAt: presigned.expiresAt.toISOString(),
      size: file.size
    };
  }, {
    params: t.Object({
      id: t.String()
    })
  });

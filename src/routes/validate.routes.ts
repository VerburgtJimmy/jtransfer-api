import { Elysia, t } from 'elysia';
import { validateMagicBytes } from '../utils/magicBytes';
import { decodeBase64ToBytes } from '../utils/base64';
import { checkIpRateLimit, rateLimiters } from '../services/ratelimit.service';
import { ipContextPlugin } from '../auth/ipContextPlugin';

export const validateRoutes = new Elysia({ prefix: '/api' })
  .use(ipContextPlugin)
  .post('/validate', async ({ body, ipContext, set }) => {
    const rateLimit = await checkIpRateLimit(ipContext, rateLimiters.validate);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { valid: false, reason: 'Rate limit exceeded. Try again later.' };
    }

    const { magicBytes } = body;

    const bytes = decodeBase64ToBytes(magicBytes);
    if (!bytes) {
      set.status = 400;
      return { valid: false, reason: 'Invalid base64 input' };
    }

    const result = validateMagicBytes(bytes);

    if (!result.valid) {
      set.status = 400;
      return { valid: false, reason: result.reason };
    }

    return { valid: true };
  }, {
    body: t.Object({
      magicBytes: t.String()
    })
  });

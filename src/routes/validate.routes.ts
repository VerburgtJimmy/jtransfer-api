import { Elysia, t } from 'elysia';
import { validateMagicBytes } from '../utils/magicBytes';
import { decodeBase64ToBytes } from '../utils/base64';

export const validateRoutes = new Elysia({ prefix: '/api' })
  .post('/validate', async ({ body, set }) => {
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
      magicBytes: t.String() // base64 encoded first N bytes
    })
  });

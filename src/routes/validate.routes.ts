import { Elysia, t } from 'elysia';
import { validateMagicBytes } from '../utils/magicBytes';

export const validateRoutes = new Elysia({ prefix: '/api' })
  .post('/validate', async ({ body, set }) => {
    const { magicBytes } = body;

    // Decode base64 magic bytes
    const bytes = new Uint8Array(
      atob(magicBytes)
        .split('')
        .map(c => c.charCodeAt(0))
    );

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

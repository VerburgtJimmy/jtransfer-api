// Shape validation for the optional per-transfer encrypted title.
// Used by `POST /api/upload/create-transfer` (set-on-create) and
// `PUT /api/me/transfers/:id/title` (owner-only rewrite / clear).
// See docs/adr/0005-encrypted-transfer-title-scope.md.
//
// Wire format mirrors the `files.encrypted_name` columns: base64 AES-GCM
// ciphertext over a pad-to-32 UTF-8 plaintext, with a 12-byte IV
// (16 base64 chars, no padding). The server never sees plaintext.

export const ENCRYPTED_TITLE_MAX_LENGTH = 1024;
export const ENCRYPTED_TITLE_IV_LENGTH = 16;

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

function isValidBase64(input: string): boolean {
  return BASE64_PATTERN.test(input);
}

export type TitleValidation =
  | { ok: true; value: { encryptedTitle: string; encryptedTitleIv: string } | null }
  | { ok: false; error: string };

// Validates the both-or-neither invariant plus base64 + length shape.
// Returns `{ ok: true, value: null }` when neither field is present
// (omit case) or — when `allowNullToClear` — both are explicitly null.
export function validateEncryptedTitle(
  encryptedTitle: unknown,
  encryptedTitleIv: unknown,
  { allowNullToClear = false }: { allowNullToClear?: boolean } = {},
): TitleValidation {
  const titlePresent = encryptedTitle !== undefined;
  const ivPresent = encryptedTitleIv !== undefined;

  if (!titlePresent && !ivPresent) {
    return { ok: true, value: null };
  }

  if (allowNullToClear && encryptedTitle === null && encryptedTitleIv === null) {
    return { ok: true, value: null };
  }

  if (typeof encryptedTitle !== "string" || typeof encryptedTitleIv !== "string") {
    return {
      ok: false,
      error: "encryptedTitle and encryptedTitleIv must both be set or both omitted.",
    };
  }

  if (encryptedTitle.length === 0 || encryptedTitle.length > ENCRYPTED_TITLE_MAX_LENGTH) {
    return {
      ok: false,
      error: `encryptedTitle must be 1–${ENCRYPTED_TITLE_MAX_LENGTH} characters.`,
    };
  }
  if (encryptedTitleIv.length !== ENCRYPTED_TITLE_IV_LENGTH) {
    return {
      ok: false,
      error: `encryptedTitleIv must be exactly ${ENCRYPTED_TITLE_IV_LENGTH} characters.`,
    };
  }
  if (!isValidBase64(encryptedTitle) || !isValidBase64(encryptedTitleIv)) {
    return { ok: false, error: "encryptedTitle and encryptedTitleIv must be base64." };
  }

  return { ok: true, value: { encryptedTitle, encryptedTitleIv } };
}

// Token generation, hashing, and constant-time comparison for
// magic-link and session bearers.
//
// Tokens are 32 random bytes (256 bits) per OWASP ASVS 6.3.3 /
// 3.2.2. The plaintext bearer is base64url-encoded for transport.
// Storage is hex-encoded SHA-256
// hash (64 chars) — plaintext is never persisted.

const TOKEN_BYTE_LENGTH = 32;

/**
 * Generate a base64url-encoded random token (43 chars from 32 bytes).
 * Suitable for magic-link tokens and session cookies.
 */
export function generateToken(): string {
  const bytes = new Uint8Array(TOKEN_BYTE_LENGTH);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Hex-encoded SHA-256 hash of the token. 64 chars. Stored in DB.
 */
export async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Buffer.from(digest).toString("hex");
}

const CODE_DIGITS = 6;
const CODE_MOD = 10 ** CODE_DIGITS;
// Largest multiple of CODE_MOD that fits in a uint32. Sampling and rejecting
// values >= REJECT keeps the distribution uniform (ASVS 6.3.2 — CSPRNG).
const CODE_REJECT = Math.floor(2 ** 32 / CODE_MOD) * CODE_MOD;

/**
 * Generate a uniformly random 6-digit numeric code, zero-padded to
 * a string. Used for the cross-device magic-link sign-in path.
 */
export function generateNumericCode(): string {
  const buf = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(buf);
    if (buf[0] < CODE_REJECT) {
      return (buf[0] % CODE_MOD).toString().padStart(CODE_DIGITS, "0");
    }
  }
}

/**
 * Accept a user-typed code in any digit-or-whitespace shape and reduce it to
 * the canonical 6-digit form. Returns null if the input isn't exactly six
 * digits after stripping spaces, dashes, and bidi marks.
 */
export function canonicaliseCode(input: string): string | null {
  const stripped = input.replace(/[\s\-_]/g, "");
  if (!/^\d{6}$/.test(stripped)) return null;
  return stripped;
}

/**
 * Constant-time equality check for two hex-encoded hashes of equal length.
 * Defends against timing-side-channel comparisons on the verify path.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Normalise an email for storage and lookup. App-side substitute for the
 * citext extension. Trim whitespace + lowercase ASCII.
 */
export function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Basic email shape check. Not a full RFC 5322 validator — just enough to
 * reject obvious garbage before issuing a token + sending email.
 */
export function isLikelyEmail(email: string): boolean {
  if (email.length < 3 || email.length > 320) return false;
  const at = email.indexOf("@");
  if (at < 1 || at === email.length - 1) return false;
  const dot = email.indexOf(".", at + 2);
  if (dot === -1 || dot === email.length - 1) return false;
  return true;
}

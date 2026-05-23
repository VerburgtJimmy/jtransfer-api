// Short-lived HMAC token proving the holder has cleared a
// transfer's password gate. Issued by
// /api/download/transfer/:id/verify and required by
// /api/download/file/:id/url when the transfer is
// password-protected.
//
// Format: `${transferId}.${expiresAtMs}.${base64url(HMAC-SHA256)}`.
// The HMAC binds transferId + expiry under DOWNLOAD_TOKEN_SECRET,
// so a token issued for transfer A cannot be replayed against
// transfer B. Stateless — no DB roundtrip on verify.

import { env } from "../config/env";
import { constantTimeEqual } from "./tokens";

const TOKEN_TTL_MS = 15 * 60 * 1000;

async function hmacSha256(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Buffer.from(sig).toString("base64url");
}

export interface IssuedDownloadToken {
  token: string;
  expiresAt: Date;
}

export async function issueDownloadToken(transferId: string): Promise<IssuedDownloadToken> {
  const expiresAtMs = Date.now() + TOKEN_TTL_MS;
  const message = `${transferId}.${expiresAtMs}`;
  const sig = await hmacSha256(env.DOWNLOAD_TOKEN_SECRET, message);
  return {
    token: `${message}.${sig}`,
    expiresAt: new Date(expiresAtMs),
  };
}

export async function verifyDownloadToken(
  token: string,
  expectedTransferId: string,
): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [tokenTransferId, expiresAtStr, providedSig] = parts;

  const expiresAtMs = Number(expiresAtStr);
  if (!Number.isFinite(expiresAtMs)) return false;

  // Recompute the signature over whatever the token claims, then compare in
  // constant time. The transferId / expiry checks come after — they can't
  // pass if the signature doesn't, but doing the HMAC unconditionally keeps
  // the timing profile flat regardless of which field is wrong.
  const expectedSig = await hmacSha256(
    env.DOWNLOAD_TOKEN_SECRET,
    `${tokenTransferId}.${expiresAtMs}`,
  );
  const sigOk = constantTimeEqual(providedSig, expectedSig);

  return sigOk && tokenTransferId === expectedTransferId && expiresAtMs > Date.now();
}

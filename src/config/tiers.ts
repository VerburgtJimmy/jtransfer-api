// Tier-aware cap definitions per ADR-0006.
//
// Three limit profiles ship in V1:
//
//   - Anonymous (no session) — tightened relative to Free, so the
//     path of least resistance for cap-hits is "create a free
//     account" rather than "cycle IPs".
//   - Free auth — the historical Free baseline. Env-configured so
//     operators can still tune without code changes; tier-keyed so
//     anonymous users don't inherit the loosened values.
//   - Pro — 50x Free on the load-bearing dimension (monthly volume)
//     plus the longer-retention expiry options. Paid via Polar
//     (ADR-0007); pro tier flips from `users.tier='free'` on the
//     terminal subscription.canceled webhook.
//
// The per-minute "smoothing" rate limit (`rateLimiters.upload`) is
// intentionally NOT tier-aware. It exists to absorb bursts, not as
// a usage budget — Pro users still benefit from the same protection
// against runaway clients.

import { env } from "./env";

const GB = 1024 * 1024 * 1024;

export interface TierCaps {
  /** Max bytes for a single file in a Transfer. */
  maxFileSize: number;
  /** Max bytes summed across every file in a single Transfer. */
  maxTransferSize: number;
  /** Max bytes uploaded across all Transfers in a rolling 30-day window. */
  monthlyVolumeBytes: number;
  /** Max Transfer creates in a rolling 24-hour window. */
  dailyTransferCount: number;
  /** Allowed values for the `expiresInHours` body field on create-transfer. */
  allowedExpiryHours: readonly number[];
}

const ANONYMOUS_CAPS: TierCaps = {
  maxFileSize: 1 * GB,
  maxTransferSize: 1 * GB,
  monthlyVolumeBytes: 1 * GB,
  dailyTransferCount: 10,
  allowedExpiryHours: [1, 6, 12, 24, 72],
};

// Free is wired through env so the existing tunables keep working.
// Wrapped in a getter so changes to `env.*` between hot-reloads in
// dev are picked up; production reads happen once at module load.
function freeCaps(): TierCaps {
  return {
    maxFileSize: env.MAX_FILE_SIZE,
    maxTransferSize: env.MAX_TOTAL_UPLOAD_SIZE,
    monthlyVolumeBytes: env.RATE_LIMIT_MONTHLY_UPLOAD_GB,
    dailyTransferCount: env.RATE_LIMIT_DAILY_TRANSFERS,
    allowedExpiryHours: [1, 6, 12, 24, 72],
  };
}

const PRO_CAPS: TierCaps = {
  maxFileSize: 10 * GB,
  maxTransferSize: 10 * GB,
  monthlyVolumeBytes: 100 * GB,
  dailyTransferCount: 100,
  // Pro adds the longer-retention options. 168h = 7d, 336h = 14d, 720h = 30d.
  allowedExpiryHours: [1, 6, 12, 24, 72, 168, 336, 720],
};

/**
 * Resolve the active caps for an authenticated request.
 *
 * `null` / `undefined` means anonymous. Anything with `tier === 'pro'`
 * gets Pro caps; everything else (including unknown tier strings) falls
 * back to Free — fail-closed, so a corrupted tier value never grants
 * Pro-level limits.
 */
export function resolveCaps(user: { tier: string } | null | undefined): TierCaps {
  if (!user) return ANONYMOUS_CAPS;
  if (user.tier === "pro") return PRO_CAPS;
  return freeCaps();
}

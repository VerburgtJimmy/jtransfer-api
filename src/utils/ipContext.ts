// IP minimization.
//
// The API never persists a raw client IP. Inbound requests are
// resolved to an `IpContext`: country + ASN + city, plus an
// `hmac()` method that HMAC-SHA-256s the raw IP under a
// caller-supplied per-purpose salt for correlation (rate limiting,
// session-anomaly detection).
//
// The raw IP lives inside this module only — captured at resolve
// time, used inside `hmac()`, never returned to callers.

import { createHmac, type BinaryLike } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import maxmind, {
  type AsnResponse,
  type CityResponse,
  type CountryResponse,
  type Reader,
} from "maxmind";
import { env } from "../config/env";

export interface IpContext {
  /** ISO 3166-1 alpha-2 ("NL", "BE", ...) or "unknown". */
  country: string;
  asn: number | null;
  asnOrg: string | null;
  /** English city name from GeoLite2-City, or null. */
  city: string | null;
  /** HMAC-SHA-256 of the raw client IP under the given per-purpose salt. */
  hmac(secret: BinaryLike): Buffer;
}

const UNKNOWN = "unknown";

let countryReader: Reader<CountryResponse> | null = null;
let asnReader: Reader<AsnResponse> | null = null;
let cityReader: Reader<CityResponse> | null = null;
let initialised = false;

/**
 * Open the MMDB readers. Call once at API startup. Safe to call again — it
 * no-ops after the first successful initialisation.
 *
 * Failure is non-fatal: if a file is missing or corrupt, the reader stays
 * null and lookups against it return `unknown`/null. This lets the API
 * keep serving when MaxMind credentials lapse or the refresh job hasn't
 * run yet.
 */
export async function initIpContext(): Promise<void> {
  if (initialised) return;
  initialised = true;

  if (!env.ENABLE_IP_DERIVATION) {
    return;
  }

  const dir = env.GEOIP_DIR;
  const opts = { watchForUpdates: true } as const;

  countryReader = await openOptional<CountryResponse>(join(dir, "GeoLite2-Country.mmdb"), opts);
  asnReader = await openOptional<AsnResponse>(join(dir, "GeoLite2-ASN.mmdb"), opts);
  cityReader = await openOptional<CityResponse>(join(dir, "GeoLite2-City.mmdb"), opts);
}

async function openOptional<T extends CountryResponse | AsnResponse | CityResponse>(
  path: string,
  opts: { watchForUpdates: boolean },
): Promise<Reader<T> | null> {
  if (!existsSync(path)) {
    console.warn(`[ipContext] MMDB missing: ${path}`);
    return null;
  }
  try {
    return await maxmind.open<T>(path, opts);
  } catch (err) {
    console.warn(`[ipContext] failed to open ${path}:`, err);
    return null;
  }
}

/**
 * Resolve the client's IpContext from request headers.
 *
 * Country + ASN come from Cloudflare headers (`CF-IPCountry`, `CF-IPASN`)
 * when present and `ENABLE_IP_DERIVATION` is on. City is read from the
 * MMDB only — CF-IPCity is enterprise-tier.
 *
 * The raw IP is captured here for the `hmac()` closure but never returned.
 * Callers that need correlation must call `ctx.hmac(salt)` themselves.
 */
export function resolveIpContext(headers: Headers): IpContext {
  const rawIp = pickRawIp(headers);

  if (!env.ENABLE_IP_DERIVATION) {
    return makeContext(rawIp, UNKNOWN, null, null, null);
  }

  const cfCountry = headers.get("cf-ipcountry");
  const cfAsn = parseAsn(headers.get("cf-ipasn"));

  let country = cfCountry && cfCountry !== "XX" ? cfCountry.toUpperCase() : null;
  let asn: number | null = cfAsn;
  let asnOrg: string | null = null;
  let city: string | null = null;

  if (rawIp) {
    if (country === null && countryReader) {
      try {
        const r = countryReader.get(rawIp);
        country = r?.country?.iso_code ?? null;
      } catch {
        // Invalid IP literal — leave as unknown.
      }
    }

    if (asnReader) {
      try {
        const r = asnReader.get(rawIp);
        if (asn === null) asn = r?.autonomous_system_number ?? null;
        asnOrg = r?.autonomous_system_organization ?? null;
      } catch {
        // Ignore.
      }
    }

    if (cityReader) {
      try {
        const r = cityReader.get(rawIp);
        city = r?.city?.names?.en ?? null;
      } catch {
        // Ignore.
      }
    }
  }

  return makeContext(rawIp, country ?? UNKNOWN, asn, asnOrg, city);
}

function makeContext(
  rawIp: string | null,
  country: string,
  asn: number | null,
  asnOrg: string | null,
  city: string | null,
): IpContext {
  return {
    country,
    asn,
    asnOrg,
    city,
    hmac(secret) {
      // No raw IP → null-byte input. The resulting HMAC is deterministic
      // for the "unknown IP" bucket, which is the desired behaviour: two
      // requests from sources we cannot identify share one rate-limit
      // bucket rather than each getting their own.
      const input = rawIp ?? "\x00";
      return createHmac("sha256", secret).update(input).digest();
    },
  };
}

/**
 * Cloudflare's `CF-Connecting-IP` is the verified client IP and cannot be
 * spoofed. Falls back to the first hop in `X-Forwarded-For` only for
 * non-Cloudflare deployments (local dev, smoke tests).
 */
function pickRawIp(headers: Headers): string | null {
  const cf = headers.get("cf-connecting-ip")?.trim();
  if (cf) return cf;

  const xff = headers.get("x-forwarded-for");
  if (!xff) return null;
  const first = xff.split(",")[0]?.trim();
  if (!first) return null;

  // Strip port from bare IPv4-with-port (e.g. "1.2.3.4:1234").
  if (first.includes(".") && first.includes(":") && !first.startsWith("[")) {
    return first.split(":")[0] ?? null;
  }
  return first;
}

function parseAsn(value: string | null): number | null {
  if (!value) return null;
  const n = parseInt(value.trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

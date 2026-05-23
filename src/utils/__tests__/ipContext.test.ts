// Unit coverage for `resolveIpContext` — the IP minimization
// resolver that converts inbound requests to country + ASN + HMAC
// correlator without ever returning the raw IP.
//
// Deterministic on purpose: we never call into the MMDB readers in these
// tests. The MMDB path is exercised end-to-end by `scripts/auth-smoke.ts`,
// not in-process. What we *do* care about in unit tests:
//
//   - Cloudflare headers (`CF-IPCountry`, `CF-IPASN`) take precedence.
//   - `XX` (CF's "unknown") gets normalised to "unknown".
//   - Raw IP is captured but never returned — only available via `hmac()`.
//   - `hmac()` is HMAC-SHA-256 under a caller-supplied salt.
//   - Different IPs produce different HMACs under the same salt.
//   - Different salts produce different HMACs for the same IP.
//   - Missing IP collapses to a single deterministic bucket.

import { describe, it, expect } from "bun:test";
import { createHmac, randomBytes } from "node:crypto";
import { resolveIpContext } from "../ipContext";

function headers(init: Record<string, string>): Headers {
  return new Headers(init);
}

describe("resolveIpContext — Cloudflare headers", () => {
  it("populates country and ASN from CF headers", () => {
    const ctx = resolveIpContext(
      headers({
        "cf-connecting-ip": "203.0.113.5",
        "cf-ipcountry": "NL",
        "cf-ipasn": "1136",
      }),
    );
    expect(ctx.country).toBe("NL");
    expect(ctx.asn).toBe(1136);
  });

  it("upper-cases lowercase CF-IPCountry values", () => {
    const ctx = resolveIpContext(
      headers({ "cf-connecting-ip": "203.0.113.5", "cf-ipcountry": "be" }),
    );
    expect(ctx.country).toBe("BE");
  });

  it("treats CF's 'XX' country as unknown rather than passing it through", () => {
    const ctx = resolveIpContext(
      headers({ "cf-connecting-ip": "203.0.113.5", "cf-ipcountry": "XX" }),
    );
    expect(ctx.country).toBe("unknown");
  });

  it("ignores a malformed CF-IPASN value", () => {
    const ctx = resolveIpContext(
      headers({ "cf-connecting-ip": "203.0.113.5", "cf-ipcountry": "NL", "cf-ipasn": "abc" }),
    );
    expect(ctx.asn).toBeNull();
  });

  it("falls back to X-Forwarded-For when CF-Connecting-IP is absent", () => {
    // Without CF country/ASN headers, country falls back to MMDB which we
    // don't load in tests — so country is "unknown" but the raw IP is still
    // captured for hmac().
    const ctx = resolveIpContext(headers({ "x-forwarded-for": "198.51.100.4, 10.0.0.1" }));
    const salt = randomBytes(32);
    const expected = createHmac("sha256", salt).update("198.51.100.4").digest();
    expect(ctx.hmac(salt).equals(expected)).toBe(true);
  });

  it("strips the trailing port from a bare IPv4-with-port in X-Forwarded-For", () => {
    const ctx = resolveIpContext(headers({ "x-forwarded-for": "198.51.100.7:5555" }));
    const salt = randomBytes(32);
    const expected = createHmac("sha256", salt).update("198.51.100.7").digest();
    expect(ctx.hmac(salt).equals(expected)).toBe(true);
  });
});

describe("resolveIpContext — hmac()", () => {
  it("returns a 32-byte HMAC-SHA-256 digest", () => {
    const ctx = resolveIpContext(headers({ "cf-connecting-ip": "203.0.113.5" }));
    const out = ctx.hmac(randomBytes(32));
    expect(out).toBeInstanceOf(Buffer);
    expect(out.length).toBe(32);
  });

  it("matches a hand-computed HMAC for the same raw IP + salt", () => {
    const ip = "203.0.113.42";
    const salt = randomBytes(32);
    const ctx = resolveIpContext(headers({ "cf-connecting-ip": ip }));
    const expected = createHmac("sha256", salt).update(ip).digest();
    expect(ctx.hmac(salt).equals(expected)).toBe(true);
  });

  it("produces different HMACs for different IPs under the same salt", () => {
    const salt = randomBytes(32);
    const a = resolveIpContext(headers({ "cf-connecting-ip": "203.0.113.1" })).hmac(salt);
    const b = resolveIpContext(headers({ "cf-connecting-ip": "203.0.113.2" })).hmac(salt);
    expect(a.equals(b)).toBe(false);
  });

  it("produces different HMACs for the same IP under different salts", () => {
    const ctx = resolveIpContext(headers({ "cf-connecting-ip": "203.0.113.5" }));
    const a = ctx.hmac(randomBytes(32));
    const b = ctx.hmac(randomBytes(32));
    expect(a.equals(b)).toBe(false);
  });

  it("collapses an unknown source IP to a single deterministic bucket", () => {
    // No CF header, no XFF → raw IP is null → hmac() keys against a fixed
    // null-byte sentinel so two unidentified sources share one rate-limit
    // bucket rather than each minting a fresh one.
    const salt = randomBytes(32);
    const a = resolveIpContext(new Headers()).hmac(salt);
    const b = resolveIpContext(new Headers()).hmac(salt);
    expect(a.equals(b)).toBe(true);
  });

  it("never exposes the raw IP via the returned context shape", () => {
    const ctx = resolveIpContext(
      headers({ "cf-connecting-ip": "203.0.113.5", "cf-ipcountry": "NL" }),
    );
    // The raw IP lives inside the hmac() closure only. The public shape
    // is country/asn/asnOrg/city/hmac — anything else is a regression.
    const serialisable = JSON.parse(
      JSON.stringify({
        country: ctx.country,
        asn: ctx.asn,
        asnOrg: ctx.asnOrg,
        city: ctx.city,
      }),
    );
    expect(JSON.stringify(serialisable)).not.toContain("203.0.113.5");
  });
});

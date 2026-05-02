import { describe, it, expect } from "bun:test";
import { normalizeClientIp } from "../ip";

describe("normalizeClientIp", () => {
  it("prefers CF-Connecting-IP over X-Forwarded-For", () => {
    expect(normalizeClientIp("1.2.3.4", "9.9.9.9")).toBe("1.2.3.4");
  });

  it("falls back to X-Forwarded-For when CF-Connecting-IP is absent", () => {
    expect(normalizeClientIp(null, "1.2.3.4, 5.6.7.8")).toBe("1.2.3.4");
  });

  it("returns unknown when both headers are missing", () => {
    expect(normalizeClientIp(null, null)).toBe("unknown");
  });

  it("uses first IP in x-forwarded-for list", () => {
    expect(normalizeClientIp(null, "1.2.3.4, 5.6.7.8")).toBe("1.2.3.4");
  });

  it("strips port from IPv4 in x-forwarded-for", () => {
    expect(normalizeClientIp(null, "1.2.3.4:1234")).toBe("1.2.3.4");
  });

  it("keeps IPv6 intact", () => {
    expect(normalizeClientIp(null, "2001:db8::1")).toBe("2001:db8::1");
  });

  it("trims whitespace from CF-Connecting-IP", () => {
    expect(normalizeClientIp("  1.2.3.4  ", null)).toBe("1.2.3.4");
  });
});

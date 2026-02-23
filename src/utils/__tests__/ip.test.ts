import { describe, it, expect } from "bun:test";
import { normalizeClientIp } from "../ip";

describe("normalizeClientIp", () => {
  it("returns unknown when header is missing", () => {
    expect(normalizeClientIp(null)).toBe("unknown");
  });

  it("uses first IP in x-forwarded-for list", () => {
    expect(normalizeClientIp("1.2.3.4, 5.6.7.8")).toBe("1.2.3.4");
  });

  it("strips port from IPv4", () => {
    expect(normalizeClientIp("1.2.3.4:1234")).toBe("1.2.3.4");
  });

  it("keeps IPv6 intact", () => {
    expect(normalizeClientIp("2001:db8::1")).toBe("2001:db8::1");
  });
});

import { describe, it, expect } from "bun:test";
import {
  generateToken,
  hashToken,
  constantTimeEqual,
  normaliseEmail,
  isLikelyEmail,
} from "../tokens";

describe("generateToken", () => {
  it("returns a 43-char base64url string (32 random bytes)", () => {
    const token = generateToken();
    expect(token).toHaveLength(43);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("produces unique values across many calls", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      seen.add(generateToken());
    }
    expect(seen.size).toBe(1000);
  });
});

describe("hashToken", () => {
  it("returns a 64-char lowercase hex string", async () => {
    const hash = await hashToken("hello");
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same input", async () => {
    const a = await hashToken("the-same-token");
    const b = await hashToken("the-same-token");
    expect(a).toBe(b);
  });

  it("matches the known SHA-256 of 'abc'", async () => {
    const hash = await hashToken("abc");
    expect(hash).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("yields different hashes for different inputs", async () => {
    const a = await hashToken("token-a");
    const b = await hashToken("token-b");
    expect(a).not.toBe(b);
  });
});

describe("constantTimeEqual", () => {
  it("returns true for equal strings", () => {
    expect(constantTimeEqual("abcdef", "abcdef")).toBe(true);
  });

  it("returns false for strings that differ in content", () => {
    expect(constantTimeEqual("abcdef", "abcdeg")).toBe(false);
  });

  it("returns false for strings of different lengths", () => {
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
    expect(constantTimeEqual("", "x")).toBe(false);
  });

  it("returns true for two empty strings", () => {
    expect(constantTimeEqual("", "")).toBe(true);
  });
});

describe("normaliseEmail", () => {
  it("lowercases ASCII characters", () => {
    expect(normaliseEmail("Foo@Example.COM")).toBe("foo@example.com");
  });

  it("trims surrounding whitespace", () => {
    expect(normaliseEmail("  foo@example.com  ")).toBe("foo@example.com");
  });

  it("combines trim and lowercase", () => {
    expect(normaliseEmail("  Foo@Example.COM\n")).toBe("foo@example.com");
  });
});

describe("isLikelyEmail", () => {
  it("accepts well-formed addresses", () => {
    expect(isLikelyEmail("foo@example.com")).toBe(true);
    expect(isLikelyEmail("a.b+tag@sub.example.co")).toBe(true);
  });

  it("rejects strings without an @", () => {
    expect(isLikelyEmail("not-an-email")).toBe(false);
  });

  it("rejects strings with no local part", () => {
    expect(isLikelyEmail("@example.com")).toBe(false);
  });

  it("rejects strings with no dot in the domain", () => {
    expect(isLikelyEmail("foo@example")).toBe(false);
  });

  it("rejects strings with a trailing dot", () => {
    expect(isLikelyEmail("foo@example.")).toBe(false);
  });

  it("rejects too-short or too-long inputs", () => {
    expect(isLikelyEmail("a")).toBe(false);
    expect(isLikelyEmail("a@" + "x".repeat(320))).toBe(false);
  });
});

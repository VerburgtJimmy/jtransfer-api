import { describe, it, expect } from "bun:test";
import { decodeBase64ToBytes } from "../base64";

describe("decodeBase64ToBytes", () => {
  it("decodes valid base64", () => {
    const bytes = decodeBase64ToBytes("AQID");
    expect(bytes).not.toBeNull();
    expect(Array.from(bytes ?? [])).toEqual([1, 2, 3]);
  });

  it("returns null for invalid base64", () => {
    expect(decodeBase64ToBytes("%%%")).toBeNull();
  });
});

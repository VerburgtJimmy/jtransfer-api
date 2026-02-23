import { describe, it, expect } from "bun:test";
import { exceedsTotalLimit } from "../limits";

describe("exceedsTotalLimit", () => {
  it("allows when total equals limit", () => {
    expect(exceedsTotalLimit(512, 512, 1024)).toBe(false);
  });

  it("blocks when total exceeds limit", () => {
    expect(exceedsTotalLimit(900, 200, 1000)).toBe(true);
  });
});

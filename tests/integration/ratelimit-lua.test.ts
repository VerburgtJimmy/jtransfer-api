// Proof that the sliding-window Lua script (audit doc 25 §B.2, D-103) is
// race-free under concurrent bursts. Skipped unless TEST_REDIS_URL points at
// a disposable Redis — local dev: `TEST_REDIS_URL=redis://localhost:6379/15`.
// We use a dedicated DB index so a FLUSHDB at the start can't touch app data.

import { afterAll, beforeEach, describe, expect, it } from "bun:test";
import Redis from "ioredis";
import { randomBytes } from "node:crypto";
import { SLIDING_WINDOW_LUA } from "../../src/services/ratelimit.service";

const TEST_REDIS_URL = process.env.TEST_REDIS_URL;

interface SlidingWindowRedis extends Redis {
  jtSlidingWindow(
    key: string,
    windowStart: number,
    now: number,
    max: number,
    member: string,
    ttl: number,
  ): Promise<[number, number]>;
}

const describeIfRedis = TEST_REDIS_URL ? describe : describe.skip;

describeIfRedis("sliding-window Lua script", () => {
  let redis: SlidingWindowRedis;

  // Per-test key so a flake in one test doesn't poison the next.
  function freshKey(): string {
    return `jt-test:ratelimit:${randomBytes(8).toString("hex")}`;
  }

  async function call(
    key: string,
    max: number,
    windowSeconds = 60,
  ): Promise<{ allowed: boolean; count: number }> {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - windowSeconds;
    const member = `${now}:${Math.random()}`;
    const [allowedFlag, count] = await redis.jtSlidingWindow(
      key,
      windowStart,
      now,
      max,
      member,
      windowSeconds,
    );
    return { allowed: allowedFlag === 1, count };
  }

  beforeEach(async () => {
    redis = new Redis(TEST_REDIS_URL!, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
    }) as SlidingWindowRedis;
    redis.defineCommand("jtSlidingWindow", {
      numberOfKeys: 1,
      lua: SLIDING_WINDOW_LUA,
    });
    await redis.connect();
  });

  afterAll(async () => {
    if (redis) await redis.quit();
  });

  it("allows the first call and reports count = 1", async () => {
    const key = freshKey();
    const result = await call(key, 3);
    expect(result.allowed).toBe(true);
    expect(result.count).toBe(1);
    await redis.del(key);
  });

  it("denies once count reaches the cap", async () => {
    const key = freshKey();
    const a = await call(key, 3);
    const b = await call(key, 3);
    const c = await call(key, 3);
    const d = await call(key, 3);

    expect(a.allowed).toBe(true);
    expect(b.allowed).toBe(true);
    expect(c.allowed).toBe(true);
    expect(d.allowed).toBe(false);
    expect(d.count).toBe(3);
    await redis.del(key);
  });

  it("never exceeds the cap under a concurrent burst — the B.2 race", async () => {
    const key = freshKey();
    const CAP = 5;
    const BURST = 40;

    const results = await Promise.all(
      Array.from({ length: BURST }, () => call(key, CAP)),
    );
    const allowed = results.filter((r) => r.allowed).length;
    expect(allowed).toBe(CAP);

    const final = await redis.zcard(key);
    expect(final).toBe(CAP);
    await redis.del(key);
  });

  it("prunes entries outside the window so the limiter slides", async () => {
    const key = freshKey();
    // Seed the key with an entry older than the window.
    const now = Math.floor(Date.now() / 1000);
    await redis.zadd(key, now - 120, "stale");
    expect(await redis.zcard(key)).toBe(1);

    // New call with windowSeconds=60 should prune the stale entry and admit.
    const result = await call(key, 1, 60);
    expect(result.allowed).toBe(true);
    expect(result.count).toBe(1);
    await redis.del(key);
  });
});

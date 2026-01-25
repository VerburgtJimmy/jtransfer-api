import Redis from 'ioredis';
import { env } from '../config/env';

// Redis client (lazy initialized)
let redis: Redis | null = null;
let redisAvailable = true;

function getRedis(): Redis | null {
  if (!env.REDIS_URL) {
    return null;
  }

  if (!redis && redisAvailable) {
    redis = new Redis(env.REDIS_URL, {
      maxRetriesPerRequest: 1,
      retryStrategy: (times) => {
        if (times > 3) {
          console.warn('[RateLimit] Redis unavailable, falling back to in-memory');
          redisAvailable = false;
          return null; // Stop retrying
        }
        return Math.min(times * 100, 1000);
      },
      lazyConnect: true,
    });

    redis.on('error', (err) => {
      if (redisAvailable) {
        console.warn('[RateLimit] Redis error:', err.message);
      }
    });

    redis.on('connect', () => {
      console.log('[RateLimit] Redis connected');
      redisAvailable = true;
    });

    // Attempt connection
    redis.connect().catch(() => {
      redisAvailable = false;
    });
  }

  return redisAvailable ? redis : null;
}

// In-memory fallback for development or when Redis is unavailable
const memoryLimits = new Map<string, { count: number; resetAt: number }>();

// Clean up old entries periodically (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of memoryLimits.entries()) {
    if (now > value.resetAt) {
      memoryLimits.delete(key);
    }
  }
}, 5 * 60 * 1000);

interface RateLimitConfig {
  /** Unique prefix for this limiter (e.g., 'upload', 'download', 'password') */
  prefix: string;
  /** Time window in seconds */
  windowSeconds: number;
  /** Maximum requests allowed in the window */
  maxRequests: number;
}

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetIn: number; // seconds until reset
}

/**
 * Check rate limit for an identifier (usually IP address)
 * Uses Redis if available, falls back to in-memory
 */
export async function checkRateLimit(
  identifier: string,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  const key = `ratelimit:${config.prefix}:${identifier}`;
  const redisClient = getRedis();

  if (redisClient && redisAvailable) {
    return checkRedisRateLimit(redisClient, key, config);
  }

  return checkMemoryRateLimit(key, config);
}

async function checkRedisRateLimit(
  redis: Redis,
  key: string,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  try {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - config.windowSeconds;

    // Use a sorted set with timestamps as scores
    // This implements a sliding window rate limiter
    const multi = redis.multi();

    // Remove old entries outside the window
    multi.zremrangebyscore(key, 0, windowStart);

    // Count current requests in window
    multi.zcard(key);

    // Add current request with timestamp
    multi.zadd(key, now, `${now}:${Math.random()}`);

    // Set TTL on the key
    multi.expire(key, config.windowSeconds);

    const results = await multi.exec();

    if (!results) {
      // Transaction failed, fall back to memory
      return checkMemoryRateLimit(key, config);
    }

    const currentCount = (results[1][1] as number) || 0;
    const allowed = currentCount < config.maxRequests;

    if (!allowed) {
      // Remove the request we just added since it's not allowed
      await redis.zremrangebyscore(key, now, now);
    }

    return {
      allowed,
      remaining: Math.max(0, config.maxRequests - currentCount - (allowed ? 1 : 0)),
      resetIn: config.windowSeconds,
    };
  } catch (err) {
    console.warn('[RateLimit] Redis error, falling back to memory:', err);
    return checkMemoryRateLimit(key, config);
  }
}

function checkMemoryRateLimit(
  key: string,
  config: RateLimitConfig
): RateLimitResult {
  const now = Date.now();
  const windowMs = config.windowSeconds * 1000;
  const limit = memoryLimits.get(key);

  if (!limit || now > limit.resetAt) {
    memoryLimits.set(key, { count: 1, resetAt: now + windowMs });
    return {
      allowed: true,
      remaining: config.maxRequests - 1,
      resetIn: config.windowSeconds,
    };
  }

  if (limit.count >= config.maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      resetIn: Math.ceil((limit.resetAt - now) / 1000),
    };
  }

  limit.count++;
  return {
    allowed: true,
    remaining: config.maxRequests - limit.count,
    resetIn: Math.ceil((limit.resetAt - now) / 1000),
  };
}

// Pre-configured rate limiters
export const rateLimiters = {
  upload: { prefix: 'upload', windowSeconds: 60, maxRequests: 10 },
  download: { prefix: 'download', windowSeconds: 60, maxRequests: 30 },
  password: { prefix: 'password', windowSeconds: 60, maxRequests: 5 },
} as const;

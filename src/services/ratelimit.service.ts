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
const memoryCounters = new Map<string, { value: number; resetAt: number }>();

// Clean up old entries periodically (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of memoryLimits.entries()) {
    if (now > value.resetAt) {
      memoryLimits.delete(key);
    }
  }
  for (const [key, value] of memoryCounters.entries()) {
    if (now > value.resetAt) {
      memoryCounters.delete(key);
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

    const member = `${now}:${Math.random()}`;

    // Add current request with timestamp
    multi.zadd(key, now, member);

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
      // Remove only the request we just added since it's not allowed
      await redis.zrem(key, member);
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

/**
 * Increment a counter and check if it exceeds the limit
 * Used for volume-based limits (e.g., daily upload bytes)
 */
export async function checkVolumeLimit(
  identifier: string,
  config: RateLimitConfig & { increment: number }
): Promise<RateLimitResult> {
  const key = `volume:${config.prefix}:${identifier}`;
  const redisClient = getRedis();

  if (redisClient && redisAvailable) {
    return checkRedisVolumeLimit(redisClient, key, config);
  }

  return checkMemoryVolumeLimit(key, config);
}

async function checkRedisVolumeLimit(
  redis: Redis,
  key: string,
  config: RateLimitConfig & { increment: number }
): Promise<RateLimitResult> {
  try {
    // Get current value
    const current = await redis.get(key);
    const currentValue = current ? parseInt(current, 10) : 0;

    // Check if adding increment would exceed limit
    if (currentValue + config.increment > config.maxRequests) {
      const ttl = await redis.ttl(key);
      return {
        allowed: false,
        remaining: Math.max(0, config.maxRequests - currentValue),
        resetIn: ttl > 0 ? ttl : config.windowSeconds,
      };
    }

    // Increment the counter
    const multi = redis.multi();
    multi.incrby(key, config.increment);
    multi.expire(key, config.windowSeconds);
    await multi.exec();

    return {
      allowed: true,
      remaining: Math.max(0, config.maxRequests - currentValue - config.increment),
      resetIn: config.windowSeconds,
    };
  } catch (err) {
    console.warn('[RateLimit] Redis error in volume check:', err);
    return checkMemoryVolumeLimit(key, config);
  }
}

function checkMemoryVolumeLimit(
  key: string,
  config: RateLimitConfig & { increment: number }
): RateLimitResult {
  const now = Date.now();
  const windowMs = config.windowSeconds * 1000;
  const counter = memoryCounters.get(key);

  if (!counter || now > counter.resetAt) {
    // New window
    if (config.increment > config.maxRequests) {
      return {
        allowed: false,
        remaining: config.maxRequests,
        resetIn: config.windowSeconds,
      };
    }
    memoryCounters.set(key, { value: config.increment, resetAt: now + windowMs });
    return {
      allowed: true,
      remaining: config.maxRequests - config.increment,
      resetIn: config.windowSeconds,
    };
  }

  // Check if adding increment would exceed limit
  if (counter.value + config.increment > config.maxRequests) {
    return {
      allowed: false,
      remaining: Math.max(0, config.maxRequests - counter.value),
      resetIn: Math.ceil((counter.resetAt - now) / 1000),
    };
  }

  counter.value += config.increment;
  return {
    allowed: true,
    remaining: Math.max(0, config.maxRequests - counter.value),
    resetIn: Math.ceil((counter.resetAt - now) / 1000),
  };
}

// Pre-configured rate limiters
const DAY_SECONDS = 24 * 60 * 60;
const MONTH_SECONDS = 30 * DAY_SECONDS;

export const rateLimiters = {
  // Per-minute limits
  upload: { prefix: 'upload', windowSeconds: 60, maxRequests: env.RATE_LIMIT_UPLOADS_PER_MINUTE },
  download: { prefix: 'download', windowSeconds: 60, maxRequests: env.RATE_LIMIT_DOWNLOADS_PER_MINUTE },
  password: { prefix: 'password', windowSeconds: 60, maxRequests: 5 },

  // Daily limits
  dailyTransfers: { prefix: 'daily-transfers', windowSeconds: DAY_SECONDS, maxRequests: env.RATE_LIMIT_DAILY_TRANSFERS },
  dailyDownloads: { prefix: 'daily-downloads', windowSeconds: DAY_SECONDS, maxRequests: env.RATE_LIMIT_DAILY_DOWNLOADS },

  // Monthly volume limit (value is in bytes)
  monthlyUploadVolume: { prefix: 'monthly-upload-volume', windowSeconds: MONTH_SECONDS, maxRequests: env.RATE_LIMIT_MONTHLY_UPLOAD_GB },
} as const;

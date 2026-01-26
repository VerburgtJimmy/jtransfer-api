function getEnv(key: string, defaultValue?: string): string {
  const value = process.env[key] ?? defaultValue;
  if (value === undefined) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

export const env = {
  DATABASE_URL: getEnv("DATABASE_URL"),
  REDIS_URL: process.env.REDIS_URL, // Optional - falls back to in-memory if not set
  CORS_ORIGINS: getEnv("CORS_ORIGINS", "http://localhost:5173"),
  PORT: parseInt(getEnv("PORT", "3000"), 10),
  MAX_FILE_SIZE: parseInt(
    getEnv("MAX_FILE_SIZE", String(1024 * 1024 * 1024)),
    10
  ), // 1GB default

  // Cloudflare R2 configuration
  R2_ENDPOINT: getEnv("R2_ENDPOINT"),
  R2_ACCESS_KEY_ID: getEnv("R2_ACCESS_KEY_ID"),
  R2_SECRET_ACCESS_KEY: getEnv("R2_SECRET_ACCESS_KEY"),
  R2_BUCKET_NAME: getEnv("R2_BUCKET_NAME"),
};

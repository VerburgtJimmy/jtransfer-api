import { cors } from "@elysiajs/cors";
import { Elysia } from "elysia";
import { env } from "./config/env";
import { downloadRoutes } from "./routes/download.routes";
import { uploadRoutes } from "./routes/upload.routes";
import { validateRoutes } from "./routes/validate.routes";
import { startCleanupJob } from "./services/cleanup.service";

// Parse CORS origins from environment (comma-separated)
const corsOrigins = env.CORS_ORIGINS.split(",")
  .map((o) => o.trim())
  .filter(Boolean);

const app = new Elysia()
  .use(
    cors({
      origin:
        corsOrigins.length === 1 && corsOrigins[0] === "*"
          ? true // Allow all origins only if explicitly set to '*'
          : corsOrigins,
      credentials: true,
      allowedHeaders: ["Content-Type", "X-Requested-With"],
      methods: ["GET", "POST", "OPTIONS"],
      exposeHeaders: ["Content-Length", "Content-Type"],
    })
  )
  // Security headers
  .onBeforeHandle(({ set }) => {
    set.headers["X-Content-Type-Options"] = "nosniff";
    set.headers["X-Frame-Options"] = "DENY";
    set.headers["X-XSS-Protection"] = "1; mode=block";
    set.headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
  })
  .get("/health", () => ({ status: "ok", timestamp: new Date().toISOString() }))
  .use(uploadRoutes)
  .use(downloadRoutes)
  .use(validateRoutes)
  .listen({
    port: env.PORT,
    maxRequestBodySize: 1024 * 1024 * 1024 * 2, // 2GB to account for encryption overhead
  });

// Start the cleanup job for expired files
startCleanupJob();

console.log(
  `JTransfer API running at ${app.server?.hostname}:${app.server?.port}`
);

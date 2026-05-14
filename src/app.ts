// App factory: builds the Elysia instance without listening. Used by the
// production entrypoint (`src/index.ts`) and by the in-process test harness.

import { cors } from "@elysiajs/cors";
import { Elysia } from "elysia";
import { env } from "./config/env";
import { authRoutes } from "./routes/auth.routes";
import { downloadRoutes } from "./routes/download.routes";
import { meRoutes } from "./routes/me.routes";
import { passkeyRoutes } from "./routes/passkey.routes";
import { uploadRoutes } from "./routes/upload.routes";
import { validateRoutes } from "./routes/validate.routes";

export function createApp() {
  const corsOrigins = env.CORS_ORIGINS.split(",")
    .map((o) => o.trim())
    .filter(Boolean);

  return new Elysia()
    .use(
      cors({
        origin:
          corsOrigins.length === 1 && corsOrigins[0] === "*"
            ? true
            : corsOrigins,
        credentials: true,
        allowedHeaders: ["Content-Type", "X-Requested-With"],
        methods: ["GET", "POST", "DELETE", "OPTIONS"],
        exposeHeaders: ["Content-Length", "Content-Type"],
      }),
    )
    .get("/health", () => ({ status: "ok", timestamp: new Date().toISOString() }))
    .use(authRoutes)
    .use(passkeyRoutes)
    .use(uploadRoutes)
    .use(downloadRoutes)
    .use(meRoutes)
    .use(validateRoutes);
}

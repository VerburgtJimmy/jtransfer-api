// App factory: builds the Elysia instance without listening. Used by the
// production entrypoint (`src/index.ts`) and by the in-process test harness.

import { cors } from "@elysiajs/cors";
import { Elysia } from "elysia";
import { env } from "./config/env";
import { ipContextPlugin } from "./auth/ipContextPlugin";
import { authRoutes } from "./routes/auth.routes";
import { billingRoutes } from "./routes/billing.routes";
import { downloadRoutes } from "./routes/download.routes";
import { meRoutes } from "./routes/me.routes";
import { passkeyRoutes } from "./routes/passkey.routes";
import { uploadRoutes } from "./routes/upload.routes";
import { validateRoutes } from "./routes/validate.routes";
import { vaultRoutes } from "./routes/vault.routes";

export function createApp() {
  const corsOrigins = env.CORS_ORIGINS.split(",")
    .map((o) => o.trim())
    .filter(Boolean);

  return new Elysia()
    // Every API response is dynamic and frequently sensitive (presigned R2
    // download URLs, session/auth payloads, account exports). Mark them all
    // non-cacheable so nothing — browser, proxy, or Cloudflare tiered cache
    // (Smart Shield) — ever stores a response body. Set in onRequest so it
    // also lands on error/404 responses, not just successful handlers.
    .onRequest(({ set }) => {
      set.headers["cache-control"] = "no-store";
    })
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
    .use(ipContextPlugin)
    .get("/health", () => ({ status: "ok", timestamp: new Date().toISOString() }))
    .use(authRoutes)
    .use(passkeyRoutes)
    .use(billingRoutes)
    .use(uploadRoutes)
    .use(downloadRoutes)
    .use(meRoutes)
    .use(vaultRoutes)
    .use(validateRoutes);
}

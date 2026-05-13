import { createApp } from "./app";
import { env } from "./config/env";
import { startCleanupJob } from "./services/cleanup.service";

const app = createApp().listen({
  port: env.PORT,
  maxRequestBodySize: 1024 * 1024 * 10, // 10MB — metadata only; files go directly to R2.
});

startCleanupJob();

console.log(
  `JTransfer API running at ${app.server?.hostname}:${app.server?.port}`,
);

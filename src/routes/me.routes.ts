// User-scoped endpoints. See docs/audit/20-transfer-ownership.md §5.
//
// All routes require an authenticated session. Non-owner access to owned
// resources returns 404 (not 403) to avoid an existence oracle (D-088).

import { Elysia, t } from "elysia";
import { authPlugin } from "../auth/middleware";
import { logAuthEvent } from "../auth/events";
import { buildAccountExport, eraseAccount } from "../auth/users";
import { SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS } from "../auth/sessions";
import { normaliseEmail } from "../auth/tokens";
import { listTransfersForUser, softDeleteOwnedTransfer } from "../services/file.service";
import { sendAccountDeletedNotification } from "../services/email.service";
import { checkRateLimit, rateLimiters } from "../services/ratelimit.service";
import { ipForStorage, normalizeClientIp } from "../utils/ip";

const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;
const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 50;

export const meRoutes = new Elysia({ prefix: "/api/me" })
  .use(authPlugin)

  .get(
    "/transfers",
    async ({ me, query, set }) => {
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const listLimit = await checkRateLimit(me.id, rateLimiters.meTransfersList);
      if (!listLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(listLimit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const limit = Math.min(
        Math.max(Number(query.limit) || DEFAULT_PAGE_SIZE, 1),
        MAX_PAGE_SIZE,
      );

      let cursor: Date | null = null;
      if (typeof query.cursor === "string" && query.cursor.length > 0) {
        const parsed = new Date(query.cursor);
        if (Number.isNaN(parsed.getTime())) {
          set.status = 400;
          return { error: "Invalid cursor" };
        }
        cursor = parsed;
      }

      const rows = await listTransfersForUser(me.id, cursor, limit);
      const nextCursor = rows.length === limit ? rows[rows.length - 1].createdAt.toISOString() : null;

      return { transfers: rows, nextCursor };
    },
    {
      query: t.Object({
        cursor: t.Optional(t.String({ maxLength: 64 })),
        limit: t.Optional(t.String({ maxLength: 4 })),
      }),
    },
  )

  .delete(
    "/transfers/:id",
    async ({ me, params, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const deleteLimit = await checkRateLimit(me.id, rateLimiters.meTransfersDelete);
      if (!deleteLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(deleteLimit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const id = params.id;
      if (!NANOID_PATTERN.test(id)) {
        set.status = 404;
        return { error: "Not found" };
      }

      const ok = await softDeleteOwnedTransfer(me.id, id);
      if (!ok) {
        // Not found, not owned, or already deleted — all collapse to 404 (D-088).
        set.status = 404;
        return { error: "Not found" };
      }

      const ipDb = ipForStorage(
        normalizeClientIp(
          request.headers.get("cf-connecting-ip"),
          request.headers.get("x-forwarded-for"),
        ),
      );
      await logAuthEvent({
        eventType: "transfer_deleted",
        userId: me.id,
        email: me.email,
        ip: ipDb,
        userAgent: request.headers.get("user-agent"),
      });

      set.status = 204;
      return null;
    },
  )

  // Account export (GDPR Article 20). See docs/audit/24-right-to-portability.md.
  .get(
    "/export",
    async ({ me, request, set }) => {
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.accountExport);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const exportData = await buildAccountExport(me);

      const ipDb = ipForStorage(
        normalizeClientIp(
          request.headers.get("cf-connecting-ip"),
          request.headers.get("x-forwarded-for"),
        ),
      );
      await logAuthEvent({
        eventType: "account_exported",
        userId: me.id,
        email: me.email,
        ip: ipDb,
        userAgent: request.headers.get("user-agent"),
      });

      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      set.headers["Content-Type"] = "application/json; charset=utf-8";
      set.headers["Content-Disposition"] = `attachment; filename="jtransfer-export-${me.id}-${stamp}.json"`;
      set.headers["Cache-Control"] = "no-store, max-age=0";
      set.headers["Pragma"] = "no-cache";

      return exportData;
    },
  )

  // Account erasure. See docs/audit/23-right-to-erasure.md.
  .delete(
    "/",
    async ({ me, originRejected, request, body, cookie, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.accountDelete);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      // Typed-email confirmation gate (D-091). Case-insensitive + trimmed via
      // normaliseEmail; mismatch is opaque to avoid leaking which side failed.
      const confirmEmail = typeof body?.confirmEmail === "string" ? body.confirmEmail : "";
      if (!confirmEmail || normaliseEmail(confirmEmail) !== me.email) {
        set.status = 400;
        return { error: "Confirmation does not match account email." };
      }

      const userAgent = request.headers.get("user-agent");
      const ipDb = ipForStorage(
        normalizeClientIp(
          request.headers.get("cf-connecting-ip"),
          request.headers.get("x-forwarded-for"),
        ),
      );

      // Snapshot email before erasure — we need it for the notification send
      // after the user row is gone.
      const formerEmail = me.email;

      await eraseAccount({ user: me, ip: ipDb, userAgent });

      // Best-effort notification (D-091). Failure must not turn the response
      // into a 5xx — the erasure already committed.
      try {
        await sendAccountDeletedNotification({ to: formerEmail });
      } catch (err) {
        console.error("[erasure] account-deleted notification send failed:", err);
      }

      // Clear the session cookie so the client drops its stale state.
      cookie[SESSION_COOKIE_NAME]?.set({
        value: "",
        ...SESSION_COOKIE_OPTIONS,
        maxAge: 0,
      });

      set.status = 204;
      return null;
    },
    {
      body: t.Object({
        confirmEmail: t.String({ maxLength: 320 }),
      }),
    },
  );

import { Elysia, redirect, t } from "elysia";
import { env } from "../config/env";
import { authPlugin } from "../auth/middleware";
import { logAuthEvent } from "../auth/events";
import { issueMagicLink, consumeMagicLink, MAGIC_LINK_TTL_MS } from "../auth/magicLinks";
import {
  createSession,
  revokeAllSessionsForUser,
  revokeSession,
  SESSION_ABSOLUTE_MS,
  SESSION_COOKIE_NAME,
  SESSION_COOKIE_OPTIONS,
} from "../auth/sessions";
import { findOrCreateUserByEmail } from "../auth/users";
import { isLikelyEmail, normaliseEmail } from "../auth/tokens";
import { sendMagicLink } from "../services/email.service";
import { checkRateLimit, rateLimiters } from "../services/ratelimit.service";
import { ipForStorage, normalizeClientIp } from "../utils/ip";

const ENUMERATION_RESPONSE = {
  ok: true as const,
  message: "If that email is registered, we sent a sign-in link.",
};

// Minimum constant-time floor for the request endpoint — defends timing-side
// channels on the existing-vs-non-existing path. See audit doc 18 §4.
const REQUEST_TIMING_FLOOR_MS = 250;

async function constantTimeRespond<T>(start: number, response: T): Promise<T> {
  const elapsed = Date.now() - start;
  const wait = REQUEST_TIMING_FLOOR_MS - elapsed;
  if (wait > 0) {
    await new Promise((resolve) => setTimeout(resolve, wait));
  }
  return response;
}

export const authRoutes = new Elysia({ prefix: "/api/auth" })
  .use(authPlugin)

  // Request a magic-link email. Always returns the same shape regardless of
  // whether the email exists. Silent auto-create: a new account is created
  // for unknown emails on verify (per D-078).
  .post(
    "/request-magic-link",
    async ({ body, request, set }) => {
      const start = Date.now();
      const ip = normalizeClientIp(
        request.headers.get("cf-connecting-ip"),
        request.headers.get("x-forwarded-for"),
      );
      const ipDb = ipForStorage(ip);
      const userAgent = request.headers.get("user-agent");

      // Per-IP throttle (cheap to evaluate before email shape check).
      const ipLimit = await checkRateLimit(ip, rateLimiters.authRequestPerIp);
      if (!ipLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(ipLimit.resetIn);
        return constantTimeRespond(start, { error: "Too many requests. Try again later." });
      }

      const rawEmail = typeof body.email === "string" ? body.email : "";
      const email = normaliseEmail(rawEmail);

      if (!isLikelyEmail(email)) {
        // Don't leak shape info — same response, just shorter path. The
        // constant-time floor still kicks in.
        return constantTimeRespond(start, ENUMERATION_RESPONSE);
      }

      // Per-email throttle.
      const emailLimit = await checkRateLimit(email, rateLimiters.authRequestPerEmail);
      if (!emailLimit.allowed) {
        // Still uniform response — don't tell the requester they hit the
        // per-email cap, only the per-IP cap is surfaced as 429.
        return constantTimeRespond(start, ENUMERATION_RESPONSE);
      }

      try {
        // Silent auto-create. The account exists either way after this call.
        await findOrCreateUserByEmail(email);

        const { token, expiresAt } = await issueMagicLink({ email, ip: ipDb, userAgent });
        const link = `${env.APP_URL}/api/auth/verify?token=${encodeURIComponent(token)}`;

        await sendMagicLink({ to: email, link, expiresAt, ip: ipDb, userAgent });

        await logAuthEvent({
          eventType: "magic_link_requested",
          email,
          ip: ipDb,
          userAgent,
        });
      } catch (err) {
        // Internal failure (DB, email vendor) — do not leak to caller. Log,
        // and still return the uniform response so timing/shape stay constant.
        console.error("[auth/request-magic-link] internal error:", err);
      }

      return constantTimeRespond(start, ENUMERATION_RESPONSE);
    },
    {
      body: t.Object({
        email: t.String({ maxLength: 320 }),
      }),
    },
  )

  // Verify a magic-link token. On success: rotates session, sets the
  // __Host-session cookie, redirects to /dashboard. Token is single-use.
  .get(
    "/verify",
    async ({ query, request, cookie, set }) => {
      const ip = normalizeClientIp(
        request.headers.get("cf-connecting-ip"),
        request.headers.get("x-forwarded-for"),
      );
      const ipDb = ipForStorage(ip);
      const userAgent = request.headers.get("user-agent");

      const verifyLimit = await checkRateLimit(ip, rateLimiters.authVerifyPerIp);
      if (!verifyLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(verifyLimit.resetIn);
        return { error: "Too many verification attempts. Try again later." };
      }

      const token = typeof query.token === "string" ? query.token : "";

      const result = await consumeMagicLink(token);
      if (!result.ok) {
        // Redirect to login with a generic error reason. Don't leak the
        // specific failure mode (consumed/expired/not_found are equivalent
        // from the user's perspective).
        return redirect(`${env.APP_URL}/login?error=link-invalid`, 302);
      }

      const user = await findOrCreateUserByEmail(result.row.email);

      const { session, token: sessionToken } = await createSession({
        userId: user.id,
        ip: ipDb,
        userAgent,
      });

      cookie[SESSION_COOKIE_NAME].set({
        value: sessionToken,
        ...SESSION_COOKIE_OPTIONS,
        maxAge: Math.floor(SESSION_ABSOLUTE_MS / 1000),
        expires: session.absoluteExpiresAt,
      });

      await logAuthEvent({
        eventType: "magic_link_consumed",
        userId: user.id,
        email: user.email,
        ip: ipDb,
        userAgent,
      });
      await logAuthEvent({
        eventType: "login_success",
        userId: user.id,
        email: user.email,
        ip: ipDb,
        userAgent,
      });

      return redirect(`${env.APP_URL}/dashboard`, 302);
    },
    {
      query: t.Object({
        token: t.String({ maxLength: 256 }),
      }),
    },
  )

  // Current user.
  .get("/me", ({ me }) => {
    if (!me) return { user: null };
    return {
      user: {
        id: me.id,
        email: me.email,
        tier: me.tier,
        createdAt: me.createdAt,
      },
    };
  })

  // Logout — revokes the current session.
  .post("/logout", async ({ me, sessionId, originRejected, cookie, request, set }) => {
    if (originRejected) {
      set.status = 403;
      return { error: "Forbidden" };
    }
    const ipDb = ipForStorage(
      normalizeClientIp(
        request.headers.get("cf-connecting-ip"),
        request.headers.get("x-forwarded-for"),
      ),
    );
    if (sessionId) {
      await revokeSession(sessionId);
    }
    if (me) {
      await logAuthEvent({
        eventType: "logout",
        userId: me.id,
        email: me.email,
        ip: ipDb,
        userAgent: request.headers.get("user-agent"),
      });
    }
    cookie[SESSION_COOKIE_NAME].remove();
    return { ok: true };
  })

  // Logout from all devices.
  .post(
    "/logout-all",
    async ({ me, originRejected, cookie, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const count = await revokeAllSessionsForUser(me.id);
      const ipDb = ipForStorage(
        normalizeClientIp(
          request.headers.get("cf-connecting-ip"),
          request.headers.get("x-forwarded-for"),
        ),
      );
      await logAuthEvent({
        eventType: "logout_all",
        userId: me.id,
        email: me.email,
        ip: ipDb,
        userAgent: request.headers.get("user-agent"),
      });
      cookie[SESSION_COOKIE_NAME].remove();
      return { ok: true, sessionsRevoked: count };
    },
  );

// Surface constants for frontend session-cookie maxAge sanity (Phase A.5).
export { MAGIC_LINK_TTL_MS, SESSION_ABSOLUTE_MS };

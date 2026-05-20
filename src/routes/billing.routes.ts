// Billing routes — Polar checkout, portal, and webhook receiver.
//
// Per ADR-0006 / ADR-0007 / ADR-0008:
//
//   - `POST /api/billing/checkout` (authed) — creates a Polar
//     checkout session for the selected billing cycle, returns the
//     hosted URL. Frontend redirects the user there.
//   - `POST /api/billing/portal` (authed) — returns a Polar-hosted
//     customer portal URL for managing payment method, cancelling,
//     viewing invoices. Requires the user to already have a Polar
//     Customer (set by the first successful webhook).
//   - `POST /api/billing/webhook` (public, signature-verified) —
//     consumes Polar's subscription lifecycle events, mirrors them
//     to the local `subscriptions` table, and syncs `users.tier`.
//     Audit-logged in `billing_events`.

import { Elysia, t } from "elysia";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { authPlugin } from "../auth/middleware";
import { db } from "../db";
import { billingEvents, subscriptions, users, type Subscription } from "../db/schema";
import {
  createPortalSession,
  createProCheckout,
  parseWebhook,
  WebhookVerificationError,
} from "../services/polar.service";

// Polar's subscription.status values that map to "user is currently Pro".
// `canceled` is terminal (period ended after a cancel-at-period-end window,
// or terminal failure after past_due retries). All others mean the user
// should keep their Pro caps.
const PRO_STATUSES = new Set(["active", "past_due", "trialing"]);
function tierFromStatus(status: string): "free" | "pro" {
  return PRO_STATUSES.has(status) ? "pro" : "free";
}

// Polar SubscriptionCustomer's externalId field carries the value we set
// at checkout time (`externalCustomerId: user.id`). Every webhook event
// for that subscription replays it back so we can match the event to a
// JTransfer User row without a lookup table.
interface PolarSubscriptionData {
  id: string;
  status: string;
  currentPeriodEnd: Date | string;
  cancelAtPeriodEnd: boolean;
  customerId: string;
  customer: {
    id: string;
    externalId?: string | null;
  };
}

interface HandlerResult {
  ok: boolean;
  reason?: string;
  subscriptionId?: string;
}

// Single upsert path for every "subscription is currently in state X"
// event. `subscription.created`, `.updated`, `.active`, `.past_due`,
// `.uncanceled` all funnel through here. `.canceled` and `.revoked`
// route through `applyTerminalCancel` instead because they set
// canceled_at and flip tier to 'free' regardless of status string.
async function applySubscriptionState(data: PolarSubscriptionData): Promise<HandlerResult> {
  const externalId = data.customer.externalId;
  if (!externalId) {
    console.warn(`[billing] event for ${data.id} has no externalCustomerId, skipping`);
    return { ok: false, reason: "no external id" };
  }

  const [user] = await db.select().from(users).where(eq(users.id, externalId));
  if (!user) {
    console.warn(`[billing] event for ${data.id} references unknown user ${externalId}`);
    return { ok: false, reason: "user not found" };
  }

  const periodEnd =
    typeof data.currentPeriodEnd === "string"
      ? new Date(data.currentPeriodEnd)
      : data.currentPeriodEnd;

  const now = new Date();
  const [existing] = await db
    .select({ id: subscriptions.id })
    .from(subscriptions)
    .where(eq(subscriptions.polarSubscriptionId, data.id));

  let subscriptionId: string;
  if (existing) {
    await db
      .update(subscriptions)
      .set({
        status: data.status,
        currentPeriodEnd: periodEnd,
        cancelAtPeriodEnd: data.cancelAtPeriodEnd,
        updatedAt: now,
      })
      .where(eq(subscriptions.id, existing.id));
    subscriptionId = existing.id;
  } else {
    subscriptionId = nanoid();
    await db.insert(subscriptions).values({
      id: subscriptionId,
      userId: user.id,
      polarSubscriptionId: data.id,
      status: data.status,
      currentPeriodEnd: periodEnd,
      cancelAtPeriodEnd: data.cancelAtPeriodEnd,
      createdAt: now,
      updatedAt: now,
    });
  }

  // Sync the user's tier snapshot + persist the customer ID on first
  // sight. polarCustomerId is set-once — we never overwrite a non-null
  // value because every webhook for this user replays the same ID.
  await db
    .update(users)
    .set({
      tier: tierFromStatus(data.status),
      ...(user.polarCustomerId ? {} : { polarCustomerId: data.customerId }),
    })
    .where(eq(users.id, user.id));

  return { ok: true, subscriptionId };
}

// Terminal cancel — either Polar exhausted retries after past_due, or
// the period closed after a cancel-at-period-end window. Either way:
// row is closed out, user drops to Free.
async function applyTerminalCancel(data: PolarSubscriptionData): Promise<HandlerResult> {
  const externalId = data.customer.externalId;
  if (!externalId) {
    return { ok: false, reason: "no external id" };
  }

  const now = new Date();
  const [existing] = await db
    .select({ id: subscriptions.id, userId: subscriptions.userId })
    .from(subscriptions)
    .where(eq(subscriptions.polarSubscriptionId, data.id));

  if (!existing) {
    // We never saw the create event. Insert a row in terminal state so
    // the audit trail isn't a gap, then sync tier.
    const subscriptionId = nanoid();
    await db.insert(subscriptions).values({
      id: subscriptionId,
      userId: externalId,
      polarSubscriptionId: data.id,
      status: data.status,
      currentPeriodEnd:
        typeof data.currentPeriodEnd === "string"
          ? new Date(data.currentPeriodEnd)
          : data.currentPeriodEnd,
      cancelAtPeriodEnd: data.cancelAtPeriodEnd,
      createdAt: now,
      updatedAt: now,
      canceledAt: now,
    });
    await db.update(users).set({ tier: "free" }).where(eq(users.id, externalId));
    return { ok: true, subscriptionId };
  }

  await db
    .update(subscriptions)
    .set({
      status: data.status,
      cancelAtPeriodEnd: data.cancelAtPeriodEnd,
      updatedAt: now,
      canceledAt: now,
    })
    .where(eq(subscriptions.id, existing.id));

  await db.update(users).set({ tier: "free" }).where(eq(users.id, existing.userId));
  return { ok: true, subscriptionId: existing.id };
}

export const billingRoutes = new Elysia({ prefix: "/api/billing" })
  .use(authPlugin)

  .post(
    "/checkout",
    async ({ me, body, set }) => {
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const cycle = body.cycle === "annual" ? "annual" : "monthly";
      try {
        const { url } = await createProCheckout(me, cycle);
        return { url };
      } catch (err) {
        console.error("[billing] checkout creation failed:", err);
        set.status = 500;
        return { error: "Checkout creation failed. Please try again." };
      }
    },
    {
      body: t.Object({
        cycle: t.Union([t.Literal("monthly"), t.Literal("annual")]),
      }),
    },
  )

  .post("/portal", async ({ me, set }) => {
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }
    if (!me.polarCustomerId) {
      set.status = 404;
      return { error: "No active billing relationship to manage." };
    }
    try {
      const { url } = await createPortalSession(me.polarCustomerId);
      return { url };
    } catch (err) {
      console.error("[billing] portal session creation failed:", err);
      set.status = 500;
      return { error: "Couldn't open the billing portal. Please try again." };
    }
  })

  // Public webhook receiver. No auth — security is the HMAC signature
  // verified inside `parseWebhook`. The body is read as raw text via
  // `request.text()` rather than through Elysia's body schema, so the
  // exact bytes Polar signed reach the verifier unaltered (Elysia's
  // content-type-sniffing JSON parser would otherwise re-serialise and
  // break the signature).
  .post("/webhook", async ({ request, set }) => {
      const body = await request.text();

      // Collect headers as a plain record — `parseWebhook` is case-
      // insensitive per the standard-webhooks spec.
      const headers: Record<string, string> = {};
      request.headers.forEach((value, key) => {
        headers[key] = value;
      });

      let event: ReturnType<typeof parseWebhook>;
      try {
        event = parseWebhook(body, headers);
      } catch (err) {
        if (err instanceof WebhookVerificationError) {
          set.status = 401;
          return { error: "Invalid signature" };
        }
        console.error("[billing] webhook parse error:", err);
        set.status = 400;
        return { error: "Malformed webhook payload" };
      }

      // Standard-webhooks puts the canonical event ID in the
      // `webhook-id` header. We persist it as `polar_event_id` and rely
      // on the UNIQUE index as the dedup boundary — a retried delivery
      // collides on insert and we short-circuit to 200 so Polar stops
      // retrying.
      const polarEventId = headers["webhook-id"] ?? headers["Webhook-Id"] ?? "";
      if (!polarEventId) {
        console.warn("[billing] webhook missing webhook-id header; cannot dedup");
        set.status = 400;
        return { error: "Missing webhook-id header" };
      }

      const eventRowId = nanoid();
      try {
        await db.insert(billingEvents).values({
          id: eventRowId,
          polarEventId,
          polarEventType: event.type,
          rawPayload: event as unknown as Record<string, unknown>,
        });
      } catch {
        // UNIQUE violation on polar_event_id — we already processed
        // this event. The original processing already updated the
        // subscription row; nothing left to do.
        console.warn("[billing] duplicate webhook delivery, skipping:", event.type);
        return { ok: true, deduplicated: true };
      }

      // Route to the right handler. Unknown event types are logged
      // (already in billing_events) and otherwise ignored so Polar
      // doesn't retry them forever.
      let result: HandlerResult;
      try {
        switch (event.type) {
          case "subscription.created":
          case "subscription.active":
          case "subscription.updated":
          case "subscription.uncanceled":
          case "subscription.past_due":
            result = await applySubscriptionState(event.data as unknown as PolarSubscriptionData);
            break;
          case "subscription.canceled":
          case "subscription.revoked":
            result = await applyTerminalCancel(event.data as unknown as PolarSubscriptionData);
            break;
          default:
            result = { ok: true, reason: "ignored event type" };
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        await db
          .update(billingEvents)
          .set({ error: message })
          .where(eq(billingEvents.id, eventRowId));
        console.error(`[billing] handler for ${event.type} failed:`, err);
        // Return 500 so Polar retries.
        set.status = 500;
        return { error: "Handler failed" };
      }

      await db
        .update(billingEvents)
        .set({
          processedAt: new Date(),
          subscriptionId: result.subscriptionId ?? null,
          error: result.ok ? null : result.reason ?? "handler returned not-ok",
        })
        .where(eq(billingEvents.id, eventRowId));

      return { ok: result.ok };
    });

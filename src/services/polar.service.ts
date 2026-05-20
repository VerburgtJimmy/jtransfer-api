// Polar SDK integration per ADR-0007. Three surfaces:
//
//   - Checkout session creation — `createProCheckout(user, cycle)`. The
//     `externalCustomerId` is set to our `user.id`, which Polar persists
//     on the Customer and replays on every webhook event for that
//     customer. This is how we route inbound webhook events back to the
//     right JTransfer User row.
//
//   - Customer portal session — `createPortalSession(customerId)`.
//     Returns a Polar-hosted URL where the user can cancel, update
//     payment method, view invoices. We do not build any of that UI
//     ourselves (the load-bearing reason MoR pays off).
//
//   - Webhook verification + parsing — `parseWebhook(body, headers)`.
//     Wraps the SDK's `validateEvent` so the route handler doesn't have
//     to know about the standard-webhooks signature scheme directly.
//
// Tier-sync logic and the `subscriptions` table writes live in the
// route handler (`billing.routes.ts`) — this service stays narrow.

import { Polar } from "@polar-sh/sdk";
import { validateEvent, WebhookVerificationError } from "@polar-sh/sdk/webhooks";
import { env } from "../config/env";
import type { User } from "../db/schema";

let cachedClient: Polar | null = null;

/**
 * Lazy Polar SDK client. Lazy so test environments that don't set the
 * access token can still import this module (typical for tests that
 * exercise the webhook signature path with mocked dependencies).
 */
function client(): Polar {
  if (!cachedClient) {
    if (!env.POLAR_ACCESS_TOKEN) {
      throw new Error(
        "POLAR_ACCESS_TOKEN is not set. Polar API calls are disabled until it's configured.",
      );
    }
    cachedClient = new Polar({
      accessToken: env.POLAR_ACCESS_TOKEN,
      server: env.POLAR_SERVER,
    });
  }
  return cachedClient;
}

export type BillingCycle = "monthly" | "annual";

/**
 * Create a checkout session for the Pro plan. The returned `url` is a
 * Polar-hosted checkout page; the frontend redirects the user there.
 * On successful purchase Polar fires `subscription.created` to our
 * webhook with `customer.externalId = user.id`.
 */
export async function createProCheckout(
  user: User,
  cycle: BillingCycle,
): Promise<{ url: string; checkoutId: string }> {
  const productId =
    cycle === "monthly" ? env.POLAR_PRODUCT_ID_MONTHLY : env.POLAR_PRODUCT_ID_ANNUAL;
  if (!productId) {
    throw new Error(
      `POLAR_PRODUCT_ID_${cycle.toUpperCase()} is not set — billing cycle "${cycle}" cannot be checked out.`,
    );
  }

  const successUrl = env.POLAR_SUCCESS_URL || `${env.APP_URL.replace(/\/$/, "")}/dashboard/settings/account?upgraded=1`;

  const checkout = await client().checkouts.create({
    products: [productId],
    externalCustomerId: user.id,
    customerEmail: user.email,
    successUrl,
  });

  return { url: checkout.url, checkoutId: checkout.id };
}

/**
 * Create a customer portal session URL for an existing Polar customer.
 * The user lands on Polar's hosted portal to manage their subscription.
 */
export async function createPortalSession(customerId: string): Promise<{ url: string }> {
  const session = await client().customerSessions.create({ customerId });
  return { url: session.customerPortalUrl };
}

/**
 * Cancel a subscription immediately (no proration). Used by the
 * account-erasure flow — when the user erases their account we don't
 * want to keep them paying for a service they no longer have access
 * to. Polar handles the invoice/refund logic per their MoR policy.
 */
export async function cancelSubscriptionImmediately(
  polarSubscriptionId: string,
): Promise<void> {
  await client().subscriptions.revoke({ id: polarSubscriptionId });
}

/**
 * Parse + verify an inbound webhook payload. Returns the parsed event
 * on success, throws `WebhookVerificationError` on signature mismatch
 * (route handler converts to 401). Header keys are case-insensitive
 * per the standard-webhooks spec.
 */
export function parseWebhook(
  body: string,
  headers: Record<string, string>,
): ReturnType<typeof validateEvent> {
  if (!env.POLAR_WEBHOOK_SECRET) {
    throw new Error(
      "POLAR_WEBHOOK_SECRET is not set — refusing to process Polar webhooks without verification.",
    );
  }
  return validateEvent(body, headers, env.POLAR_WEBHOOK_SECRET);
}

export { WebhookVerificationError };

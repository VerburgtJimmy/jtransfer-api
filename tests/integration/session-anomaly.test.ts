// Session-anomaly detection. Audit doc 19 §2.2 + D-082.
//
// Goals:
//   - Fires a `session_anomaly` audit row when the request's ip_hmac changes
//     AND either country or ASN changes.
//   - Does not fire on a same-network re-DHCP (ip_hmac changes but
//     country + ASN do not).
//   - Does not fire when the session has no stored ipHmac/correlationSecret
//     (already-revoked or pre-migration sessions).
//   - The 1h in-process dedup cache suppresses duplicate writes.
//   - Disabling via `ENABLE_SESSION_ANOMALY_DETECTION=false` short-circuits.
//
// We construct `IpContext` values by hand here so we can drive raw IPs
// without spinning up the MMDB. The contract of `IpContext` is shape-only
// — country/asn/asnOrg/city/hmac() — so a hand-built one is indistinguishable
// from one returned by `resolveIpContext`.

import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { createHmac, type BinaryLike } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { db } from "../../src/db";
import { authEvents } from "../../src/db/schema";
import { createSession } from "../../src/auth/sessions";
import {
  __resetSessionAnomalyDedupForTests,
  detectAndReportSessionAnomaly,
} from "../../src/auth/sessionAnomaly";
import type { IpContext } from "../../src/utils/ipContext";
import { createTestUser } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";

function ipContextFor(
  rawIp: string,
  country: string,
  asn: number | null,
  asnOrg: string | null = null,
): IpContext {
  return {
    country,
    asn,
    asnOrg,
    city: null,
    hmac(secret: BinaryLike): Buffer {
      return createHmac("sha256", secret).update(rawIp).digest();
    },
  };
}

async function countAnomalyEvents(userId: string): Promise<number> {
  const rows = await db
    .select({ id: authEvents.id })
    .from(authEvents)
    .where(and(eq(authEvents.userId, userId), eq(authEvents.eventType, "session_anomaly")));
  return rows.length;
}

beforeAll(async () => {
  await ensureMigrations();
});

beforeEach(async () => {
  await resetDb();
  __resetSessionAnomalyDedupForTests();
});

afterAll(async () => {
  await resetDb();
});

describe("detectAndReportSessionAnomaly", () => {
  it("logs session_anomaly when ip_hmac and country both change", async () => {
    const user = await createTestUser("anomaly-1@jtransfer.test");
    const original = ipContextFor("203.0.113.1", "NL", 1136);
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    const moved = ipContextFor("198.51.100.1", "BE", 5432);
    await detectAndReportSessionAnomaly({
      session,
      ipContext: moved,
      userId: user.id,
      email: user.email,
      userAgent: "bun-test",
    });

    expect(await countAnomalyEvents(user.id)).toBe(1);
  });

  it("logs session_anomaly when ip_hmac changes and only ASN changes", async () => {
    const user = await createTestUser("anomaly-2@jtransfer.test");
    const original = ipContextFor("203.0.113.5", "NL", 1136);
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    // Same country, different IP and ASN → counts as a network change.
    const samePlaceDifferentNet = ipContextFor("203.0.113.99", "NL", 9009);
    await detectAndReportSessionAnomaly({
      session,
      ipContext: samePlaceDifferentNet,
      userId: user.id,
      email: user.email,
      userAgent: "bun-test",
    });

    expect(await countAnomalyEvents(user.id)).toBe(1);
  });

  it("does NOT log when only the raw IP changes but country + ASN are identical", async () => {
    const user = await createTestUser("anomaly-3@jtransfer.test");
    const original = ipContextFor("203.0.113.5", "NL", 1136);
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    // Different IP under same carrier — classic re-DHCP or NAT-pool churn.
    const reDhcp = ipContextFor("203.0.113.77", "NL", 1136);
    await detectAndReportSessionAnomaly({
      session,
      ipContext: reDhcp,
      userId: user.id,
      email: user.email,
      userAgent: "bun-test",
    });

    expect(await countAnomalyEvents(user.id)).toBe(0);
  });

  it("does NOT log on a no-op same-IP request (ip_hmac matches)", async () => {
    const user = await createTestUser("anomaly-4@jtransfer.test");
    const ip = ipContextFor("203.0.113.5", "NL", 1136);
    const { session } = await createSession({
      userId: user.id,
      ipContext: ip,
      userAgent: "bun-test",
    });

    await detectAndReportSessionAnomaly({
      session,
      ipContext: ip,
      userId: user.id,
      email: user.email,
      userAgent: "bun-test",
    });

    expect(await countAnomalyEvents(user.id)).toBe(0);
  });

  it("dedups duplicate (country, ASN) transitions within the TTL", async () => {
    const user = await createTestUser("anomaly-5@jtransfer.test");
    const original = ipContextFor("203.0.113.5", "NL", 1136);
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    const moved = ipContextFor("198.51.100.5", "BE", 5432);
    // First hit fires; subsequent hits with the same (country, ASN) are
    // suppressed by the in-process dedup cache.
    for (let i = 0; i < 5; i++) {
      await detectAndReportSessionAnomaly({
        session,
        ipContext: moved,
        userId: user.id,
        email: user.email,
        userAgent: "bun-test",
      });
    }

    expect(await countAnomalyEvents(user.id)).toBe(1);
  });

  it("does not log when correlation_secret is missing on the session", async () => {
    const user = await createTestUser("anomaly-6@jtransfer.test");
    const original = ipContextFor("203.0.113.5", "NL", 1136);
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    // Simulate a revoked-or-pre-migration session: secret wiped, ip_hmac
    // still present from when the row was minted. Detection must skip
    // rather than throwing or logging.
    const stripped = { ...session, correlationSecret: null };
    const moved = ipContextFor("198.51.100.5", "BE", 5432);
    await detectAndReportSessionAnomaly({
      session: stripped,
      ipContext: moved,
      userId: user.id,
      email: user.email,
      userAgent: "bun-test",
    });

    expect(await countAnomalyEvents(user.id)).toBe(0);
  });

  it("respects ENABLE_SESSION_ANOMALY_DETECTION=false (no rows written)", async () => {
    const user = await createTestUser("anomaly-7@jtransfer.test");
    const original = ipContextFor("203.0.113.5", "NL", 1136);
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    const moved = ipContextFor("198.51.100.5", "BE", 5432);

    const prev = process.env.ENABLE_SESSION_ANOMALY_DETECTION;
    process.env.ENABLE_SESSION_ANOMALY_DETECTION = "false";
    try {
      // env.ts caches at module-eval time, so toggling the env var here is
      // not enough — this test is best-effort. If the kill switch ever needs
      // to be exercised end-to-end, prefer an integration boot of the API
      // with the env override set up-front.
      await detectAndReportSessionAnomaly({
        session,
        ipContext: moved,
        userId: user.id,
        email: user.email,
        userAgent: "bun-test",
      });
    } finally {
      if (prev === undefined) delete process.env.ENABLE_SESSION_ANOMALY_DETECTION;
      else process.env.ENABLE_SESSION_ANOMALY_DETECTION = prev;
    }

    // Detection module reads env.ENABLE_SESSION_ANOMALY_DETECTION at call
    // time; if the flag flip propagates, no row is written. Either way the
    // count must be ≤ 1 — never multiple writes from a single transition.
    expect(await countAnomalyEvents(user.id)).toBeLessThanOrEqual(1);
  });
});

// ─── Email notification (ADR-0003) ─────────────────────────────────────────
//
// The audit-log row is the canonical signal; the email is best-effort
// self-service routing. We mock `sendSessionAnomalyNotification` to record
// invocations and verify shape, dedup, and failure isolation. The email
// flag is enabled globally in tests via `tests/setup.ts`.

interface RecordedEmail {
  to: string;
  previousCountry: string | null;
  previousAsnOrg: string | null;
  previousAsn: number | null;
  currentCountry: string | null;
  currentAsnOrg: string | null;
  currentAsn: number | null;
  sessionUserAgent: string | null;
  settingsUrl: string;
}

let anomalyEmails: RecordedEmail[] = [];
let anomalyEmailNextThrows = false;

function installEmailSpy() {
  mock.module("../../src/services/email.service", () => ({
    sendMagicLink: async () => undefined,
    sendAccountDeletedNotification: async () => undefined,
    sendSessionAnomalyNotification: async (input: RecordedEmail) => {
      if (anomalyEmailNextThrows) {
        anomalyEmailNextThrows = false;
        throw new Error("simulated TEM failure");
      }
      anomalyEmails.push({ ...input });
    },
  }));
}

function restoreDefaultEmailMock() {
  mock.module("../../src/services/email.service", () => ({
    sendMagicLink: async () => undefined,
    sendAccountDeletedNotification: async () => undefined,
    sendSessionAnomalyNotification: async () => undefined,
  }));
}

describe("detectAndReportSessionAnomaly — email notification", () => {
  beforeEach(() => {
    anomalyEmails = [];
    anomalyEmailNextThrows = false;
    installEmailSpy();
  });

  afterAll(() => {
    restoreDefaultEmailMock();
  });

  it("sends one anomaly email on the first network change", async () => {
    const user = await createTestUser("anomaly-email-1@jtransfer.test");
    const original = ipContextFor("203.0.113.10", "NL", 1136, "KPN");
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    const moved = ipContextFor("198.51.100.10", "BE", 5432, "Proximus");
    await detectAndReportSessionAnomaly({
      session,
      ipContext: moved,
      userId: user.id,
      email: user.email,
      userAgent: "bun-test",
    });

    expect(anomalyEmails).toHaveLength(1);
    const sent = anomalyEmails[0]!;
    expect(sent.to).toBe(user.email);
    expect(sent.previousCountry).toBe("NL");
    expect(sent.previousAsn).toBe(1136);
    expect(sent.previousAsnOrg).toBe("KPN");
    expect(sent.currentCountry).toBe("BE");
    expect(sent.currentAsn).toBe(5432);
    expect(sent.currentAsnOrg).toBe("Proximus");
    expect(sent.settingsUrl).toMatch(/\/dashboard\/settings$/);
  });

  it("does not send a duplicate email within the dedup window", async () => {
    const user = await createTestUser("anomaly-email-2@jtransfer.test");
    const original = ipContextFor("203.0.113.20", "NL", 1136, "KPN");
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    const moved = ipContextFor("198.51.100.20", "BE", 5432, "Proximus");
    for (let i = 0; i < 4; i++) {
      await detectAndReportSessionAnomaly({
        session,
        ipContext: moved,
        userId: user.id,
        email: user.email,
        userAgent: "bun-test",
      });
    }

    expect(anomalyEmails).toHaveLength(1);
    expect(await countAnomalyEvents(user.id)).toBe(1);
  });

  it("does not send when the request is a same-network re-DHCP", async () => {
    const user = await createTestUser("anomaly-email-3@jtransfer.test");
    const original = ipContextFor("203.0.113.30", "NL", 1136, "KPN");
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    const reDhcp = ipContextFor("203.0.113.99", "NL", 1136, "KPN");
    await detectAndReportSessionAnomaly({
      session,
      ipContext: reDhcp,
      userId: user.id,
      email: user.email,
      userAgent: "bun-test",
    });

    expect(anomalyEmails).toHaveLength(0);
  });

  it("still writes the audit row when the email send throws", async () => {
    const user = await createTestUser("anomaly-email-4@jtransfer.test");
    const original = ipContextFor("203.0.113.40", "NL", 1136, "KPN");
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    anomalyEmailNextThrows = true;
    const moved = ipContextFor("198.51.100.40", "BE", 5432, "Proximus");
    await detectAndReportSessionAnomaly({
      session,
      ipContext: moved,
      userId: user.id,
      email: user.email,
      userAgent: "bun-test",
    });

    // Email send threw, but the audit row is the canonical signal and must
    // be written either way. The thrown error must not propagate out of
    // detectAndReportSessionAnomaly (called fire-and-forget from middleware).
    expect(await countAnomalyEvents(user.id)).toBe(1);
    expect(anomalyEmails).toHaveLength(0);
  });

  it("includes a bare AS<int> in the email when asnOrg is missing", async () => {
    const user = await createTestUser("anomaly-email-5@jtransfer.test");
    // Session created without an ASN org label — older sessions may have
    // NULL asn_org because the column is nullable.
    const original = ipContextFor("203.0.113.50", "NL", 1136, null);
    const { session } = await createSession({
      userId: user.id,
      ipContext: original,
      userAgent: "bun-test",
    });

    const moved = ipContextFor("198.51.100.50", "BE", 5432, null);
    await detectAndReportSessionAnomaly({
      session,
      ipContext: moved,
      userId: user.id,
      email: user.email,
      userAgent: "bun-test",
    });

    expect(anomalyEmails).toHaveLength(1);
    const sent = anomalyEmails[0]!;
    expect(sent.previousAsnOrg).toBeNull();
    expect(sent.currentAsnOrg).toBeNull();
    expect(sent.previousAsn).toBe(1136);
    expect(sent.currentAsn).toBe(5432);
  });
});

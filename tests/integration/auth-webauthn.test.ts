// Phase D — passkey helper coverage. See docs/audit/27-passkey-webauthn-prf.md §13.
//
// The crypto verify steps (verifyRegistrationResponse / verifyAuthenticationResponse)
// are owned by @simplewebauthn/server and are already covered upstream — we
// can't synthesise valid signed assertions in-process without an authenticator
// simulator, so this suite focuses on the parts the helpers actually own:
//   - challenge issuance shape and TTL bookkeeping
//   - challenge consumption (one-shot, TTL-bound, kind-bound, user-bound)
//   - credential ownership and lookup
//   - CRUD on authenticator rows (list / rename / delete)
//
// Together with the routes-level tests (acceptance gate at doc 27 §13) and a
// real-device smoke captured in docs/audit/27a-passkey-deliverability-results.md,
// this is the coverage we want before Phase D lands.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../../src/db";
import {
  authenticators,
  users,
  webauthnChallenges,
} from "../../src/db/schema";
import {
  beginAuthentication,
  beginRegistration,
  deleteAuthenticator,
  finishAuthentication,
  finishRegistration,
  listAuthenticatorsForUser,
  renameAuthenticator,
} from "../../src/auth/webauthn";
import { ensureMigrations, resetDb } from "../helpers/db";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";

beforeAll(async () => {
  await ensureMigrations();
});

beforeEach(async () => {
  await resetDb();
});

afterAll(async () => {
  await resetDb();
});

async function makeUser(email = "alice@example.test") {
  const id = nanoid();
  await db.insert(users).values({ id, email });
  return { id, email };
}

async function loadChallenge(id: string) {
  const [row] = await db
    .select()
    .from(webauthnChallenges)
    .where(eq(webauthnChallenges.id, id))
    .limit(1);
  return row;
}

// Minimal stub payloads. The crypto verify will reject these, but the helpers
// reach the verify call only after challenge bookkeeping passes — so they're
// enough to drive the consume-and-then-fail branches.
function stubRegistrationResponse(): RegistrationResponseJSON {
  return {
    id: "AAAA",
    rawId: "AAAA",
    response: {
      clientDataJSON: "AAAA",
      attestationObject: "AAAA",
      transports: [],
    },
    type: "public-key",
    clientExtensionResults: {},
    authenticatorAttachment: "platform",
  };
}

function stubAuthenticationResponse(credentialIdB64Url: string): AuthenticationResponseJSON {
  return {
    id: credentialIdB64Url,
    rawId: credentialIdB64Url,
    response: {
      clientDataJSON: "AAAA",
      authenticatorData: "AAAA",
      signature: "AAAA",
      userHandle: undefined,
    },
    type: "public-key",
    clientExtensionResults: {},
    authenticatorAttachment: "platform",
  };
}

// ─── beginRegistration ────────────────────────────────────────────────────

describe("beginRegistration", () => {
  it("returns options with the right RP and persists a challenge bound to the user", async () => {
    const user = await makeUser();

    const { options, challengeRowId } = await beginRegistration({
      userId: user.id,
      userEmail: user.email,
      existingCredentialIds: [],
    });

    expect(options.rp.id).toBeTruthy();
    expect(options.rp.name).toBeTruthy();
    expect(options.user.name).toBe(user.email);
    expect(options.user.displayName).toBe(user.email);
    expect(options.authenticatorSelection?.residentKey).toBe("required");
    expect(options.authenticatorSelection?.userVerification).toBe("required");
    expect(options.attestation).toBe("none");

    const row = await loadChallenge(challengeRowId);
    expect(row).toBeDefined();
    expect(row.kind).toBe("registration");
    expect(row.userId).toBe(user.id);
    expect(row.consumedAt).toBeNull();
    expect(row.challenge).toHaveLength(32);
    expect(row.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("threads existing credential ids into excludeCredentials so re-enrollment is refused", async () => {
    const user = await makeUser();
    const credId = new Uint8Array([1, 2, 3, 4, 5]);

    const { options } = await beginRegistration({
      userId: user.id,
      userEmail: user.email,
      existingCredentialIds: [credId],
    });

    expect(options.excludeCredentials).toBeDefined();
    expect(options.excludeCredentials?.length).toBe(1);
  });
});

// ─── beginAuthentication ──────────────────────────────────────────────────

describe("beginAuthentication", () => {
  it("issues a username-less challenge with allowCredentials empty", async () => {
    const { options, challengeRowId } = await beginAuthentication();

    expect(options.userVerification).toBe("required");
    expect(options.allowCredentials).toEqual([]);

    const row = await loadChallenge(challengeRowId);
    expect(row.kind).toBe("authentication");
    expect(row.userId).toBeNull();
    expect(row.consumedAt).toBeNull();
  });
});

// ─── finishRegistration — challenge guard ─────────────────────────────────

describe("finishRegistration — challenge guard", () => {
  it("rejects an unknown challenge id", async () => {
    const user = await makeUser();
    const result = await finishRegistration({
      challengeRowId: "no-such-challenge",
      userId: user.id,
      response: stubRegistrationResponse(),
      nickname: null,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("challenge_invalid");
  });

  it("rejects a challenge that has expired", async () => {
    const user = await makeUser();
    const { challengeRowId } = await beginRegistration({
      userId: user.id,
      userEmail: user.email,
      existingCredentialIds: [],
    });
    await db
      .update(webauthnChallenges)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(webauthnChallenges.id, challengeRowId));

    const result = await finishRegistration({
      challengeRowId,
      userId: user.id,
      response: stubRegistrationResponse(),
      nickname: null,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("challenge_invalid");
  });

  it("rejects a challenge that belongs to a different user (tampering)", async () => {
    const alice = await makeUser("alice@example.test");
    const mallory = await makeUser("mallory@example.test");

    const { challengeRowId } = await beginRegistration({
      userId: alice.id,
      userEmail: alice.email,
      existingCredentialIds: [],
    });

    const result = await finishRegistration({
      challengeRowId,
      userId: mallory.id,
      response: stubRegistrationResponse(),
      nickname: null,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("challenge_invalid");
  });

  it("consumes the challenge on attempt, so retry fails even with a fresh response", async () => {
    const user = await makeUser();
    const { challengeRowId } = await beginRegistration({
      userId: user.id,
      userEmail: user.email,
      existingCredentialIds: [],
    });

    const first = await finishRegistration({
      challengeRowId,
      userId: user.id,
      response: stubRegistrationResponse(),
      nickname: null,
    });
    expect(first.ok).toBe(false);

    const row = await loadChallenge(challengeRowId);
    expect(row.consumedAt).not.toBeNull();

    const second = await finishRegistration({
      challengeRowId,
      userId: user.id,
      response: stubRegistrationResponse(),
      nickname: null,
    });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe("challenge_invalid");
  });

  it("returns verification_failed when challenge is valid but crypto is bogus", async () => {
    // Confirms the helper distinguishes "challenge invalid" from "crypto
    // failed" — the route surface relies on that to know what to log.
    const user = await makeUser();
    const { challengeRowId } = await beginRegistration({
      userId: user.id,
      userEmail: user.email,
      existingCredentialIds: [],
    });

    const result = await finishRegistration({
      challengeRowId,
      userId: user.id,
      response: stubRegistrationResponse(),
      nickname: null,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("verification_failed");
  });
});

// ─── finishAuthentication — challenge guard + credential lookup ──────────

describe("finishAuthentication — challenge guard", () => {
  it("rejects an unknown challenge id", async () => {
    const result = await finishAuthentication({
      challengeRowId: "no-such-challenge",
      response: stubAuthenticationResponse("AAAA"),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("challenge_invalid");
  });

  it("rejects an expired challenge", async () => {
    const { challengeRowId } = await beginAuthentication();
    await db
      .update(webauthnChallenges)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(webauthnChallenges.id, challengeRowId));

    const result = await finishAuthentication({
      challengeRowId,
      response: stubAuthenticationResponse("AAAA"),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("challenge_invalid");
  });

  it("rejects a registration challenge passed to an authentication finish (kind mismatch)", async () => {
    const user = await makeUser();
    const { challengeRowId } = await beginRegistration({
      userId: user.id,
      userEmail: user.email,
      existingCredentialIds: [],
    });

    const result = await finishAuthentication({
      challengeRowId,
      response: stubAuthenticationResponse("AAAA"),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("challenge_invalid");
  });

  it("returns credential_unknown when no authenticator row matches the credential id", async () => {
    const { challengeRowId } = await beginAuthentication();

    const result = await finishAuthentication({
      challengeRowId,
      // Base64url-encoded bytes that won't match any inserted row.
      response: stubAuthenticationResponse("ZGVhZGJlZWY"),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("credential_unknown");
  });

  it("consumes the challenge before looking up the credential, so retry fails", async () => {
    const { challengeRowId } = await beginAuthentication();

    const first = await finishAuthentication({
      challengeRowId,
      response: stubAuthenticationResponse("ZGVhZGJlZWY"),
    });
    expect(first.ok).toBe(false);

    const row = await loadChallenge(challengeRowId);
    expect(row.consumedAt).not.toBeNull();

    const second = await finishAuthentication({
      challengeRowId,
      response: stubAuthenticationResponse("ZGVhZGJlZWY"),
    });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe("challenge_invalid");
  });
});

// ─── listAuthenticatorsForUser ────────────────────────────────────────────

describe("listAuthenticatorsForUser", () => {
  it("returns only the requesting user's authenticators", async () => {
    const alice = await makeUser("alice@example.test");
    const bob = await makeUser("bob@example.test");

    await db.insert(authenticators).values([
      {
        id: nanoid(),
        userId: alice.id,
        credentialId: new Uint8Array([1, 1, 1]),
        publicKey: new Uint8Array([9, 9]),
        signCount: 0,
        transports: [],
        deviceType: "multiDevice",
        backedUp: true,
        supportsPrf: false,
        nickname: "Alice phone",
      },
      {
        id: nanoid(),
        userId: bob.id,
        credentialId: new Uint8Array([2, 2, 2]),
        publicKey: new Uint8Array([8, 8]),
        signCount: 0,
        transports: [],
        deviceType: "singleDevice",
        backedUp: false,
        supportsPrf: true,
        nickname: "Bob laptop",
      },
    ]);

    const aliceKeys = await listAuthenticatorsForUser(alice.id);
    expect(aliceKeys).toHaveLength(1);
    expect(aliceKeys[0].nickname).toBe("Alice phone");

    const bobKeys = await listAuthenticatorsForUser(bob.id);
    expect(bobKeys).toHaveLength(1);
    expect(bobKeys[0].nickname).toBe("Bob laptop");
  });

  it("returns an empty list when the user has no enrolled passkeys", async () => {
    const user = await makeUser();
    const keys = await listAuthenticatorsForUser(user.id);
    expect(keys).toEqual([]);
  });
});

// ─── deleteAuthenticator ──────────────────────────────────────────────────

describe("deleteAuthenticator", () => {
  it("removes a row owned by the user", async () => {
    const user = await makeUser();
    const authId = nanoid();
    await db.insert(authenticators).values({
      id: authId,
      userId: user.id,
      credentialId: new Uint8Array([1, 2, 3]),
      publicKey: new Uint8Array([4, 5, 6]),
      signCount: 0,
      transports: [],
      deviceType: "multiDevice",
      backedUp: true,
      supportsPrf: false,
      nickname: null,
    });

    const removed = await deleteAuthenticator({
      authenticatorId: authId,
      userId: user.id,
    });
    expect(removed).toBe(true);

    const remaining = await listAuthenticatorsForUser(user.id);
    expect(remaining).toHaveLength(0);
  });

  it("does not remove rows owned by a different user", async () => {
    const alice = await makeUser("alice@example.test");
    const mallory = await makeUser("mallory@example.test");
    const authId = nanoid();
    await db.insert(authenticators).values({
      id: authId,
      userId: alice.id,
      credentialId: new Uint8Array([7, 7, 7]),
      publicKey: new Uint8Array([3, 3, 3]),
      signCount: 0,
      transports: [],
      deviceType: "multiDevice",
      backedUp: true,
      supportsPrf: false,
      nickname: null,
    });

    const removed = await deleteAuthenticator({
      authenticatorId: authId,
      userId: mallory.id,
    });
    expect(removed).toBe(false);

    const stillThere = await listAuthenticatorsForUser(alice.id);
    expect(stillThere).toHaveLength(1);
  });

  it("returns false for a non-existent authenticator id", async () => {
    const user = await makeUser();
    const removed = await deleteAuthenticator({
      authenticatorId: "no-such-id",
      userId: user.id,
    });
    expect(removed).toBe(false);
  });
});

// ─── renameAuthenticator ──────────────────────────────────────────────────

describe("renameAuthenticator", () => {
  it("updates the nickname when the user owns the row", async () => {
    const user = await makeUser();
    const authId = nanoid();
    await db.insert(authenticators).values({
      id: authId,
      userId: user.id,
      credentialId: new Uint8Array([1]),
      publicKey: new Uint8Array([2]),
      signCount: 0,
      transports: [],
      deviceType: "multiDevice",
      backedUp: true,
      supportsPrf: false,
      nickname: "Old name",
    });

    const updated = await renameAuthenticator({
      authenticatorId: authId,
      userId: user.id,
      nickname: "New name",
    });
    expect(updated).not.toBeNull();
    expect(updated?.nickname).toBe("New name");
  });

  it("accepts null to clear the nickname", async () => {
    const user = await makeUser();
    const authId = nanoid();
    await db.insert(authenticators).values({
      id: authId,
      userId: user.id,
      credentialId: new Uint8Array([1]),
      publicKey: new Uint8Array([2]),
      signCount: 0,
      transports: [],
      deviceType: "multiDevice",
      backedUp: true,
      supportsPrf: false,
      nickname: "Old name",
    });

    const updated = await renameAuthenticator({
      authenticatorId: authId,
      userId: user.id,
      nickname: null,
    });
    expect(updated?.nickname).toBeNull();
  });

  it("returns null when the user does not own the row", async () => {
    const alice = await makeUser("alice@example.test");
    const mallory = await makeUser("mallory@example.test");
    const authId = nanoid();
    await db.insert(authenticators).values({
      id: authId,
      userId: alice.id,
      credentialId: new Uint8Array([1]),
      publicKey: new Uint8Array([2]),
      signCount: 0,
      transports: [],
      deviceType: "multiDevice",
      backedUp: true,
      supportsPrf: false,
      nickname: "Alice key",
    });

    const updated = await renameAuthenticator({
      authenticatorId: authId,
      userId: mallory.id,
      nickname: "Stolen",
    });
    expect(updated).toBeNull();

    // The original is untouched.
    const [row] = await db
      .select()
      .from(authenticators)
      .where(eq(authenticators.id, authId))
      .limit(1);
    expect(row.nickname).toBe("Alice key");
  });
});

// ─── authenticator cascade on user delete ────────────────────────────────

describe("authenticator cascade", () => {
  it("removes authenticators when the owning user is deleted", async () => {
    const user = await makeUser();
    await db.insert(authenticators).values({
      id: nanoid(),
      userId: user.id,
      credentialId: new Uint8Array([10, 20, 30]),
      publicKey: new Uint8Array([40, 50, 60]),
      signCount: 0,
      transports: [],
      deviceType: "multiDevice",
      backedUp: true,
      supportsPrf: false,
      nickname: null,
    });

    await db.delete(users).where(eq(users.id, user.id));

    const remaining = await listAuthenticatorsForUser(user.id);
    expect(remaining).toHaveLength(0);
  });
});

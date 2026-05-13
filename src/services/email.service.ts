// Scaleway Transactional Email integration. Transactional only — no marketing
// per Scaleway TEM ToS and project posture. See docs/audit/18-auth-security-baseline.md §9.
//
// In dev when SCW_TEM credentials are not configured, the magic link is logged
// to stdout so flows can be tested without a real send.

import { env } from "../config/env";

interface SendMagicLinkInput {
  to: string;
  link: string;
  expiresAt: Date;
  /** IP of the magic-link requester (shown in email body for security context). */
  ip: string | null;
  userAgent: string | null;
}

const SCW_TEM_ENDPOINT = (region: string) =>
  `https://api.scaleway.com/transactional-email/v1alpha1/regions/${region}/emails`;

function isConfigured(): boolean {
  return Boolean(env.SCW_TEM_PROJECT_ID && env.SCW_TEM_SECRET_KEY);
}

function buildMagicLinkSubject(): string {
  return "Your JTransfer sign-in link";
}

function buildMagicLinkText({ link, expiresAt, ip, userAgent }: SendMagicLinkInput): string {
  const expiresIn = Math.max(1, Math.round((expiresAt.getTime() - Date.now()) / 60000));
  return [
    "Sign in to JTransfer",
    "",
    "Click the link below to sign in. It expires in " +
      expiresIn +
      " minutes and can only be used once.",
    "",
    link,
    "",
    "If you open this link on a different device than the one you started",
    "signing in on, we'll show you a short code to type back into your",
    "original device — no sign-in happens on the wrong device.",
    "",
    "Request details:",
    `  IP: ${ip ?? "unknown"}`,
    `  Browser: ${userAgent ?? "unknown"}`,
    "",
    "If you didn't request this, ignore this email — no account changes were made.",
    "",
    "— JTransfer",
  ].join("\n");
}

function buildMagicLinkHtml(input: SendMagicLinkInput): string {
  const expiresIn = Math.max(1, Math.round((input.expiresAt.getTime() - Date.now()) / 60000));
  // Minimal inline-styled HTML — no tracking pixels, no remote assets.
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8"><title>Sign in to JTransfer</title></head>',
    '<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5;color:#111;max-width:560px;margin:24px auto;padding:0 16px;">',
    '  <h1 style="font-size:20px;margin:0 0 16px;">Sign in to JTransfer</h1>',
    `  <p>Click the button below to sign in. The link expires in <strong>${expiresIn} minutes</strong> and can only be used once.</p>`,
    `  <p style="margin:24px 0;"><a href="${escapeHtml(input.link)}" style="display:inline-block;padding:12px 20px;background:#111;color:#fff;text-decoration:none;border-radius:8px;">Sign in to JTransfer</a></p>`,
    `  <p style="font-size:13px;color:#555;">Or paste this URL into your browser:<br><code style="word-break:break-all;">${escapeHtml(input.link)}</code></p>`,
    '  <p style="font-size:13px;color:#555;">Opening this link on a different device than the one you started signing in on will show you a short code to type back into your original device — no sign-in happens on the wrong device.</p>',
    '  <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">',
    '  <p style="font-size:12px;color:#666;">Request details — IP: ' +
      escapeHtml(input.ip ?? "unknown") +
      " &middot; Browser: " +
      escapeHtml(input.userAgent ?? "unknown") +
      "</p>",
    '  <p style="font-size:12px;color:#666;">If you didn\'t request this, ignore this email — no account changes were made.</p>',
    "</body></html>",
  ].join("\n");
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

interface SendAccountDeletedInput {
  to: string;
}

function buildAccountDeletedSubject(): string {
  return "Your JTransfer account was deleted";
}

function buildAccountDeletedText({ to }: SendAccountDeletedInput): string {
  return [
    "Your JTransfer account and all associated transfers were permanently deleted just now.",
    "",
    "If you did this, no further action is needed. If you did not request this deletion, your account may have been accessed by someone else — we recommend rotating the credentials on the email address used to sign in (" +
      to +
      "), and reviewing other services where you used the same address.",
    "",
    "We don't retain copies. The account and its files cannot be restored.",
    "",
    "— JTransfer",
  ].join("\n");
}

function buildAccountDeletedHtml({ to }: SendAccountDeletedInput): string {
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8"><title>Your JTransfer account was deleted</title></head>',
    '<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5;color:#111;max-width:560px;margin:24px auto;padding:0 16px;">',
    '  <h1 style="font-size:20px;margin:0 0 16px;">Your JTransfer account was deleted</h1>',
    "  <p>Your JTransfer account and all associated transfers were permanently deleted just now.</p>",
    "  <p>If you did this, no further action is needed. If you did not request this deletion, your account may have been accessed by someone else — we recommend rotating the credentials on the email address used to sign in (<strong>" +
      escapeHtml(to) +
      "</strong>), and reviewing other services where you used the same address.</p>",
    '  <p style="font-size:13px;color:#555;">We don\'t retain copies. The account and its files cannot be restored.</p>',
    "</body></html>",
  ].join("\n");
}

export async function sendAccountDeletedNotification(input: SendAccountDeletedInput): Promise<void> {
  if (!isConfigured()) {
    console.log(
      `[email] SCW_TEM not configured — logging account-deleted notification instead.\n  to: ${input.to}`,
    );
    return;
  }

  const body = {
    from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
    to: [{ email: input.to }],
    project_id: env.SCW_TEM_PROJECT_ID,
    subject: buildAccountDeletedSubject(),
    text: buildAccountDeletedText(input),
    html: buildAccountDeletedHtml(input),
    ...(env.EMAIL_REPLY_TO
      ? { additional_headers: [{ key: "Reply-To", value: env.EMAIL_REPLY_TO }] }
      : {}),
  };

  const response = await fetch(SCW_TEM_ENDPOINT(env.SCW_TEM_REGION), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Auth-Token": env.SCW_TEM_SECRET_KEY,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => "<unreadable>");
    console.error(
      `[email] Scaleway TEM account-deleted send failed (${response.status}) for ${input.to}: ${errorBody.slice(0, 500)}`,
    );
    throw new Error(`Email send failed: ${response.status}`);
  }
}

export async function sendMagicLink(input: SendMagicLinkInput): Promise<void> {
  if (!isConfigured()) {
    console.log(
      `[email] SCW_TEM not configured — logging magic link instead.\n  to: ${input.to}\n  link: ${input.link}\n  expires: ${input.expiresAt.toISOString()}`,
    );
    return;
  }

  const body = {
    from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
    to: [{ email: input.to }],
    project_id: env.SCW_TEM_PROJECT_ID,
    subject: buildMagicLinkSubject(),
    text: buildMagicLinkText(input),
    html: buildMagicLinkHtml(input),
    ...(env.EMAIL_REPLY_TO
      ? { additional_headers: [{ key: "Reply-To", value: env.EMAIL_REPLY_TO }] }
      : {}),
  };

  const response = await fetch(SCW_TEM_ENDPOINT(env.SCW_TEM_REGION), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Auth-Token": env.SCW_TEM_SECRET_KEY,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => "<unreadable>");
    // Don't include the magic link in error logs.
    console.error(
      `[email] Scaleway TEM send failed (${response.status}) for ${input.to}: ${errorBody.slice(0, 500)}`,
    );
    throw new Error(`Email send failed: ${response.status}`);
  }
}

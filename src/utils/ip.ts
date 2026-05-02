export function normalizeClientIp(
  cfConnectingIp: string | null,
  forwardedFor: string | null
): string {
  // Cloudflare sets CF-Connecting-IP to the verified real client IP.
  // Unlike X-Forwarded-For, clients cannot spoof this header.
  if (cfConnectingIp) {
    return cfConnectingIp.trim();
  }

  // Fallback for non-Cloudflare deployments (e.g. local dev).
  if (!forwardedFor) return "unknown";

  const first = forwardedFor.split(",")[0]?.trim();
  if (!first) return "unknown";

  // Strip port from bare IPv4 with port (e.g. "1.2.3.4:1234").
  if (first.includes(".") && first.includes(":") && !first.startsWith("[")) {
    return first.split(":")[0];
  }

  return first;
}

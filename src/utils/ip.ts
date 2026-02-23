export function normalizeClientIp(forwardedFor: string | null): string {
  if (!forwardedFor) return "unknown";

  const first = forwardedFor.split(",")[0]?.trim();
  if (!first) return "unknown";

  // If the IP is IPv4 with a port (e.g. "1.2.3.4:1234"), strip the port.
  if (first.includes(".") && first.includes(":") && !first.startsWith("[")) {
    return first.split(":")[0];
  }

  return first;
}

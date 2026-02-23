export function decodeBase64ToBytes(input: string): Uint8Array | null {
  try {
    const binary = atob(input);
    return new Uint8Array(
      binary.split("").map((c) => c.charCodeAt(0))
    );
  } catch {
    return null;
  }
}

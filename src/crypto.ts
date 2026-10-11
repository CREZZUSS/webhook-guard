import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export type RawBody = string | Uint8Array;

/** Octets exacts reçus : une signature se calcule sur eux, jamais sur un JSON décodé puis réencodé. */
export function toBytes(body: RawBody): Buffer {
  return typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body);
}

export function hmacHex(algorithm: "sha256" | "sha512", key: string, message: RawBody): string {
  return createHmac(algorithm, key).update(toBytes(message)).digest("hex");
}

export function sha512Hex(value: string): string {
  return createHash("sha512").update(value, "utf8").digest("hex");
}

/**
 * Compare deux empreintes hexadécimales en temps constant. Une longueur différente renvoie false
 * sans comparer le contenu : la longueur d'une empreinte n'est pas un secret.
 */
export function safeEqualHex(expected: string, provided: string): boolean {
  const a = Buffer.from(expected.trim().toLowerCase(), "utf8");
  const b = Buffer.from(provided.trim().toLowerCase(), "utf8");
  if (a.length === 0 || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

import { hmacHex, safeEqualHex, toBytes, type RawBody } from "../crypto.js";
import { reject, type Verification } from "../types.js";

export interface NowpaymentsIpn {
  payment_id?: string | number;
  payment_status?: string;
  order_id?: string;
  price_amount?: number;
  price_currency?: string;
  pay_amount?: number;
  actually_paid?: number;
  pay_currency?: string;
  [key: string]: unknown;
}

export interface VerifyNowpaymentsInput {
  rawBody: RawBody;
  /** Valeur de l'en-tête x-nowpayments-sig. */
  signatureHeader: string | null | undefined;
  /** Secret IPN du tableau de bord NOWPayments. */
  ipnSecret: string;
}

/**
 * HMAC-SHA512 (secret IPN) du corps JSON réencodé avec ses clés triées. La documentation donne
 * `JSON.stringify(params, Object.keys(params).sort())` : ce « replacer » filtre aussi les objets
 * imbriqués sur les clés de premier niveau. On accepte donc deux formes canoniques, ce tri-là et un
 * tri récursif complet. Les deux exigent le secret : accepter l'une ou l'autre n'affaiblit rien.
 */
export function verifyNowpayments(input: VerifyNowpaymentsInput): Verification<NowpaymentsIpn> {
  const secret = input.ipnSecret?.trim();
  if (!secret) return reject("missing_secret");
  const provided = input.signatureHeader?.trim();
  if (!provided) return reject("missing_signature");
  if (!/^[0-9a-fA-F]{128}$/.test(provided)) return reject("malformed_signature");

  let payload: unknown;
  try {
    payload = JSON.parse(toBytes(input.rawBody).toString("utf8"));
  } catch {
    return reject("malformed_body");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return reject("malformed_body");

  const valid = nowpaymentsCanonicalForms(payload as Record<string, unknown>).some((form) =>
    safeEqualHex(hmacHex("sha512", secret, form), provided),
  );
  if (!valid) return reject("bad_signature");

  const ipn = payload as NowpaymentsIpn;
  return { ok: true, event: ipn, eventId: `nowpayments:${ipn.payment_id ?? "?"}:${ipn.payment_status ?? "?"}` };
}

export function nowpaymentsCanonicalForms(payload: Record<string, unknown>): string[] {
  const documented = JSON.stringify(payload, Object.keys(payload).sort());
  const recursive = JSON.stringify(sortDeep(payload));
  return documented === recursive ? [recursive] : [recursive, documented];
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) out[key] = sortDeep((value as Record<string, unknown>)[key]);
    return out;
  }
  return value;
}

/** Signature valide : pour les tests et le banc d'essai, jamais en production. */
export function signNowpaymentsPayload(payload: Record<string, unknown>, ipnSecret: string): string {
  return hmacHex("sha512", ipnSecret, JSON.stringify(sortDeep(payload)));
}

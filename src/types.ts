export type Provider = "fedapay" | "nowpayments" | "paydunya";

/** Motif de refus, stable : il sert au journal et aux tests, jamais au corps renvoyé à l'appelant. */
export type RejectReason =
  | "missing_secret"
  | "missing_signature"
  | "malformed_signature"
  | "bad_signature"
  | "stale_timestamp"
  | "malformed_body"
  | "not_confirmed"
  | "confirmation_failed"
  | "amount_mismatch";

export type Verification<T> =
  | { ok: true; event: T; eventId: string }
  | { ok: false; reason: RejectReason; detail?: string };

export function reject<T>(reason: RejectReason, detail?: string): Verification<T> {
  return detail === undefined ? { ok: false, reason } : { ok: false, reason, detail };
}

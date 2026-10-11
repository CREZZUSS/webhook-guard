import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { signNowpaymentsPayload, verifyNowpayments } from "../src/index.js";

const SECRET = "ipn_test_secret";
const PAYLOAD = {
  payment_status: "finished",
  payment_id: 5077125051,
  price_amount: 10,
  price_currency: "usd",
  pay_currency: "usdttrc20",
  order_id: "order-17",
  actually_paid: 10.02,
  fee: { depositFee: 0, currency: "usdttrc20", serviceFee: 0.05 },
};

test("IPN signé (tri récursif) : accepté", () => {
  const body = JSON.stringify(PAYLOAD);
  const result = verifyNowpayments({ rawBody: body, signatureHeader: signNowpaymentsPayload(PAYLOAD, SECRET), ipnSecret: SECRET });
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.eventId, "nowpayments:5077125051:finished");
});

test("IPN signé selon l'exemple de la documentation (replacer de premier niveau) : accepté", () => {
  const documented = createHmac("sha512", SECRET).update(JSON.stringify(PAYLOAD, Object.keys(PAYLOAD).sort())).digest("hex");
  const result = verifyNowpayments({ rawBody: JSON.stringify(PAYLOAD), signatureHeader: documented, ipnSecret: SECRET });
  assert.equal(result.ok, true);
});

test("l'ordre des clés du corps reçu n'a pas d'importance", () => {
  const reversed = Object.fromEntries(Object.entries(PAYLOAD).reverse());
  const shuffled = JSON.stringify(reversed);
  assert.notEqual(shuffled, JSON.stringify(PAYLOAD));
  const result = verifyNowpayments({ rawBody: shuffled, signatureHeader: signNowpaymentsPayload(PAYLOAD, SECRET), ipnSecret: SECRET });
  assert.equal(result.ok, true);
});

test("statut passé de waiting à finished par un tiers : bad_signature", () => {
  const signed = signNowpaymentsPayload({ ...PAYLOAD, payment_status: "waiting" }, SECRET);
  const result = verifyNowpayments({ rawBody: JSON.stringify(PAYLOAD), signatureHeader: signed, ipnSecret: SECRET });
  assert.deepEqual(result, { ok: false, reason: "bad_signature" });
});

test("champ imbriqué modifié : bad_signature avec le tri récursif", () => {
  const signed = signNowpaymentsPayload(PAYLOAD, SECRET);
  const tampered = { ...PAYLOAD, fee: { ...PAYLOAD.fee, serviceFee: 0 } };
  const result = verifyNowpayments({ rawBody: JSON.stringify(tampered), signatureHeader: signed, ipnSecret: SECRET });
  assert.equal(result.ok, false);
});

test("signature absente, mal formée ou secret vide", () => {
  const body = JSON.stringify(PAYLOAD);
  assert.deepEqual(verifyNowpayments({ rawBody: body, signatureHeader: "", ipnSecret: SECRET }), { ok: false, reason: "missing_signature" });
  assert.deepEqual(verifyNowpayments({ rawBody: body, signatureHeader: "abc", ipnSecret: SECRET }), { ok: false, reason: "malformed_signature" });
  assert.deepEqual(verifyNowpayments({ rawBody: body, signatureHeader: "a".repeat(128), ipnSecret: "" }), { ok: false, reason: "missing_secret" });
});

test("corps qui n'est pas un objet JSON : malformed_body", () => {
  assert.deepEqual(verifyNowpayments({ rawBody: "[1,2]", signatureHeader: "a".repeat(128), ipnSecret: SECRET }), { ok: false, reason: "malformed_body" });
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { signFedapayPayload, verifyFedapay } from "../src/index.js";

const SECRET = "wh_sandbox_test_secret";
const NOW = new Date("2026-10-11T10:00:00Z");
const T = Math.floor(NOW.getTime() / 1000);
const BODY = JSON.stringify({ name: "transaction.approved", entity: { id: 4242, status: "approved", amount: 5000 } });

test("une notification signée et récente est acceptée", () => {
  const result = verifyFedapay({ rawBody: BODY, signatureHeader: signFedapayPayload(BODY, SECRET, T), secret: SECRET, now: NOW });
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.event.entity.amount, 5000);
    assert.equal(result.eventId, "fedapay:transaction.approved:4242:approved");
  }
});

test("la signature est conforme à l'algorithme officiel (HMAC-SHA256 de t.corps)", () => {
  const official = createHmac("sha256", SECRET).update(`${T}.${BODY}`).digest("hex");
  assert.equal(signFedapayPayload(BODY, SECRET, T), `t=${T},s=${official}`);
});

test("les octets bruts font foi : un Buffer donne le même résultat que la chaîne", () => {
  const result = verifyFedapay({ rawBody: Buffer.from(BODY), signatureHeader: signFedapayPayload(BODY, SECRET, T), secret: SECRET, now: NOW });
  assert.equal(result.ok, true);
});

test("sans en-tête : refus missing_signature", () => {
  const result = verifyFedapay({ rawBody: BODY, signatureHeader: undefined, secret: SECRET, now: NOW });
  assert.deepEqual(result, { ok: false, reason: "missing_signature" });
});

test("sans secret configuré : refus, jamais d'acceptation par défaut", () => {
  const result = verifyFedapay({ rawBody: BODY, signatureHeader: signFedapayPayload(BODY, SECRET, T), secret: " ", now: NOW });
  assert.deepEqual(result, { ok: false, reason: "missing_secret" });
});

test("montant modifié après signature : bad_signature", () => {
  const header = signFedapayPayload(BODY, SECRET, T);
  const tampered = BODY.replace("5000", "500000");
  assert.deepEqual(verifyFedapay({ rawBody: tampered, signatureHeader: header, secret: SECRET, now: NOW }), { ok: false, reason: "bad_signature" });
});

test("mauvaise clé : bad_signature", () => {
  const header = signFedapayPayload(BODY, "autre_secret", T);
  assert.deepEqual(verifyFedapay({ rawBody: BODY, signatureHeader: header, secret: SECRET, now: NOW }), { ok: false, reason: "bad_signature" });
});

test("rejeu d'une notification capturée il y a une heure : stale_timestamp", () => {
  const header = signFedapayPayload(BODY, SECRET, T - 3600);
  const result = verifyFedapay({ rawBody: BODY, signatureHeader: header, secret: SECRET, now: NOW });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "stale_timestamp");
});

test("horodatage dans le futur au-delà de la tolérance : refusé aussi", () => {
  const header = signFedapayPayload(BODY, SECRET, T + 900);
  const result = verifyFedapay({ rawBody: BODY, signatureHeader: header, secret: SECRET, now: NOW });
  assert.equal(result.ok, false);
});

test("dans la tolérance de 5 minutes : accepté", () => {
  const header = signFedapayPayload(BODY, SECRET, T - 299);
  assert.equal(verifyFedapay({ rawBody: BODY, signatureHeader: header, secret: SECRET, now: NOW }).ok, true);
});

test("en-tête réduit à la signature, sans t= : malformed_signature (pas de repli sans horodatage)", () => {
  const bare = createHmac("sha256", SECRET).update(BODY).digest("hex");
  const result = verifyFedapay({ rawBody: BODY, signatureHeader: bare, secret: SECRET, now: NOW });
  assert.deepEqual(result, { ok: false, reason: "malformed_signature" });
});

test("plusieurs signatures (rotation de clé) : une seule valide suffit", () => {
  const good = signFedapayPayload(BODY, SECRET, T).split(",s=")[1];
  const header = `t=${T},s=${"0".repeat(64)},s=${good}`;
  assert.equal(verifyFedapay({ rawBody: BODY, signatureHeader: header, secret: SECRET, now: NOW }).ok, true);
});

test("corps signé mais pas du JSON : malformed_body", () => {
  const body = "pas du json";
  const result = verifyFedapay({ rawBody: body, signatureHeader: signFedapayPayload(body, SECRET, T), secret: SECRET, now: NOW });
  assert.deepEqual(result, { ok: false, reason: "malformed_body" });
});

test("l'identifiant d'événement est préféré quand il existe", () => {
  const body = JSON.stringify({ id: 99, name: "transaction.approved", entity: { id: 1, status: "approved" } });
  const result = verifyFedapay({ rawBody: body, signatureHeader: signFedapayPayload(body, SECRET, T), secret: SECRET, now: NOW });
  assert.equal(result.ok && result.eventId, "fedapay:event:99");
});

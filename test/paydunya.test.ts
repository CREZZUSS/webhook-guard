import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildPaydunyaIpnBody,
  confirmPaydunyaInvoice,
  guardPaydunya,
  parsePaydunyaBody,
  sha512Hex,
  verifyPaydunyaIpn,
  type PaydunyaConfirmation,
} from "../src/index.js";

const MASTER = "test_master_key";
const KEYS = { masterKey: MASTER, privateKey: "test_private_key", token: "test_token" };

test("lecture du formulaire data[...] imbriqué", () => {
  const body = "data%5Bhash%5D=abc&data%5Binvoice%5D%5Btoken%5D=ERt0N&data%5Binvoice%5D%5Btotal_amount%5D=5000&data%5Bstatus%5D=completed";
  assert.deepEqual(parsePaydunyaBody(body), { hash: "abc", invoice: { token: "ERt0N", total_amount: "5000" }, status: "completed" });
});

test("lecture du JSON { data: ... }", () => {
  assert.deepEqual(parsePaydunyaBody('{"data":{"hash":"h","status":"pending"}}'), { hash: "h", status: "pending" });
});

test("pollution de prototype : clés __proto__ ignorées", () => {
  const parsed = parsePaydunyaBody("data%5B__proto__%5D%5Bpolluted%5D=1&data%5Bstatus%5D=x");
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  assert.deepEqual(parsed, { status: "x" });
});

test("hash correct : accepté par le contrôle de hash", () => {
  const body = buildPaydunyaIpnBody({ masterKey: MASTER, token: "ERt0N", status: "completed", totalAmount: 5000 });
  const result = verifyPaydunyaIpn({ rawBody: body, masterKey: MASTER });
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.eventId, "paydunya:ERt0N:completed");
});

test("hash d'une autre clé : bad_signature", () => {
  const body = buildPaydunyaIpnBody({ masterKey: "autre", token: "ERt0N", status: "completed", totalAmount: 5000 });
  assert.deepEqual(verifyPaydunyaIpn({ rawBody: body, masterKey: MASTER }), { ok: false, reason: "bad_signature" });
});

test("le hash brut de la clé (erreur de l'exemple Ruby officiel) n'est pas accepté", () => {
  const body = `data%5Bhash%5D=${MASTER}&data%5Binvoice%5D%5Btoken%5D=ERt0N&data%5Bstatus%5D=completed`;
  assert.equal(verifyPaydunyaIpn({ rawBody: body, masterKey: MASTER }).ok, false);
});

test("FAILLE : le hash ne protège pas le contenu, un montant forgé passe le contrôle de hash seul", () => {
  // L'attaquant a vu UNE notification : il connaît le hash, identique pour toutes.
  const capturedHash = sha512Hex(MASTER);
  const forged = `data%5Bhash%5D=${capturedHash}&data%5Binvoice%5D%5Btoken%5D=UNPAID&data%5Binvoice%5D%5Btotal_amount%5D=1000000&data%5Bstatus%5D=completed`;
  assert.equal(verifyPaydunyaIpn({ rawBody: forged, masterKey: MASTER }).ok, true);
});

test("guardPaydunya : la même notification forgée est refusée par la confirmation API", async () => {
  const forged = buildPaydunyaIpnBody({ masterKey: MASTER, token: "UNPAID", status: "completed", totalAmount: 1_000_000 });
  const confirm = async (): Promise<PaydunyaConfirmation> => ({ status: "pending", totalAmount: 5000, raw: {} });
  const result = await guardPaydunya({ rawBody: forged, masterKey: MASTER, confirm });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "not_confirmed");
});

test("guardPaydunya : facture payée mais d'un autre montant que la commande : amount_mismatch", async () => {
  const body = buildPaydunyaIpnBody({ masterKey: MASTER, token: "ERt0N", status: "completed", totalAmount: 100 });
  const confirm = async (): Promise<PaydunyaConfirmation> => ({ status: "completed", totalAmount: 100, raw: {} });
  const result = await guardPaydunya({ rawBody: body, masterKey: MASTER, confirm, expectedAmount: () => 5000 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "amount_mismatch");
});

test("guardPaydunya : payée, bon montant : acceptée, identifiant fondé sur le statut confirmé", async () => {
  const body = buildPaydunyaIpnBody({ masterKey: MASTER, token: "ERt0N", status: "completed", totalAmount: 5000 });
  const confirm = async (): Promise<PaydunyaConfirmation> => ({ status: "completed", totalAmount: 5000, raw: {} });
  const result = await guardPaydunya({ rawBody: body, masterKey: MASTER, confirm, expectedAmount: async () => 5000 });
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.eventId, "paydunya:ERt0N:completed");
});

test("guardPaydunya : API injoignable : confirmation_failed, rien n'est crédité", async () => {
  const body = buildPaydunyaIpnBody({ masterKey: MASTER, token: "ERt0N", status: "completed", totalAmount: 5000 });
  const result = await guardPaydunya({ rawBody: body, masterKey: MASTER, confirm: async () => { throw new Error("timeout"); } });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "confirmation_failed");
});

test("confirmPaydunyaInvoice : bonne URL et bons en-têtes, sandbox et live", async () => {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    calls.push({ url, headers: init.headers as Record<string, string> });
    return new Response(JSON.stringify({ response_code: "00", status: "completed", invoice: { total_amount: "5000" } }), { status: 200 });
  }) as unknown as typeof fetch;

  const sandbox = await confirmPaydunyaInvoice({ invoiceToken: "ERt0N", keys: KEYS, mode: "test", fetchImpl });
  assert.equal(calls[0]?.url, "https://app.paydunya.com/sandbox-api/v1/checkout-invoice/confirm/ERt0N");
  assert.equal(calls[0]?.headers["PAYDUNYA-MASTER-KEY"], MASTER);
  assert.equal(calls[0]?.headers["PAYDUNYA-PRIVATE-KEY"], "test_private_key");
  assert.equal(calls[0]?.headers["PAYDUNYA-TOKEN"], "test_token");
  assert.deepEqual([sandbox.status, sandbox.totalAmount], ["completed", 5000]);

  await confirmPaydunyaInvoice({ invoiceToken: "a/b", keys: KEYS, mode: "live", fetchImpl });
  assert.equal(calls[1]?.url, "https://app.paydunya.com/api/v1/checkout-invoice/confirm/a%2Fb");
});

test("confirmPaydunyaInvoice : réponse HTTP en erreur : exception", async () => {
  const fetchImpl = (async () => new Response("nope", { status: 503 })) as unknown as typeof fetch;
  await assert.rejects(confirmPaydunyaInvoice({ invoiceToken: "x", keys: KEYS, mode: "test", fetchImpl }), /HTTP 503/);
});

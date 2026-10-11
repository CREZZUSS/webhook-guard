import { test } from "node:test";
import assert from "node:assert/strict";
import { handleWebhook, MemoryReplayStore, safeEqualHex, type JournalEntry, type Verification } from "../src/index.js";

const ok = (id: string): Verification<{ amount: number }> => ({ ok: true, event: { amount: 5000 }, eventId: id });

test("premier passage traité, doublon ignoré avec 200 (le prestataire cesse ses relances)", async () => {
  const store = new MemoryReplayStore();
  let credits = 0;
  const run = () => handleWebhook({ provider: "fedapay", verify: () => ok("evt-1"), store, onEvent: () => { credits += 1; } });

  assert.deepEqual(await run(), { status: 200, outcome: "accepted", eventId: "evt-1" });
  assert.deepEqual(await run(), { status: 200, outcome: "duplicate", eventId: "evt-1" });
  assert.equal(credits, 1);
});

test("livraisons simultanées du même événement : un seul crédit", async () => {
  const store = new MemoryReplayStore();
  let credits = 0;
  const results = await Promise.all(
    Array.from({ length: 5 }, () => handleWebhook({ provider: "fedapay", verify: () => ok("evt-c"), store, onEvent: async () => { credits += 1; } })),
  );
  assert.equal(credits, 1);
  assert.equal(results.filter((r) => r.outcome === "accepted").length, 1);
});

test("refus : 401 pour une signature, 400 pour un corps, sans appeler le traitement", async () => {
  const store = new MemoryReplayStore();
  let called = false;
  const onEvent = () => { called = true; };
  const bad = await handleWebhook({ provider: "fedapay", verify: () => ({ ok: false, reason: "bad_signature" }), store, onEvent });
  const malformed = await handleWebhook({ provider: "fedapay", verify: () => ({ ok: false, reason: "malformed_body" }), store, onEvent });
  assert.deepEqual([bad.status, malformed.status], [401, 400]);
  assert.equal(called, false);
});

test("erreur du traitement : 500 et clé libérée, la relance suivante passe", async () => {
  const store = new MemoryReplayStore();
  let attempts = 0;
  const onEvent = () => { attempts += 1; if (attempts === 1) throw new Error("base indisponible"); };
  const first = await handleWebhook({ provider: "paydunya", verify: () => ok("evt-2"), store, onEvent });
  const second = await handleWebhook({ provider: "paydunya", verify: () => ok("evt-2"), store, onEvent });
  assert.deepEqual([first.status, second.outcome], [500, "accepted"]);
});

test("journal : chaque tentative est tracée, et un journal en panne ne bloque rien", async () => {
  const store = new MemoryReplayStore();
  const entries: JournalEntry[] = [];
  await handleWebhook({ provider: "nowpayments", verify: () => ok("evt-3"), store, onEvent: () => {}, journal: (e) => { entries.push(e); }, remoteAddress: "203.0.113.9" });
  await handleWebhook({ provider: "nowpayments", verify: () => ({ ok: false, reason: "bad_signature", detail: "x" }), store, onEvent: () => {}, journal: (e) => { entries.push(e); } });
  assert.deepEqual(entries.map((e) => [e.outcome, e.reason ?? null]), [["accepted", null], ["rejected", "bad_signature"]]);
  assert.equal(entries[0]?.remoteAddress, "203.0.113.9");

  const result = await handleWebhook({ provider: "nowpayments", verify: () => ok("evt-4"), store, onEvent: () => {}, journal: () => { throw new Error("disque plein"); } });
  assert.equal(result.outcome, "accepted");
});

test("la mémoire expire après la durée choisie", async () => {
  let now = 0;
  const store = new MemoryReplayStore(() => now);
  assert.equal(await store.claim("k", 60), true);
  assert.equal(await store.claim("k", 60), false);
  now = 61_000;
  assert.equal(await store.claim("k", 60), true);
});

test("safeEqualHex : casse ignorée, longueur différente ou vide refusée", () => {
  assert.equal(safeEqualHex("abcd", "ABCD"), true);
  assert.equal(safeEqualHex("abcd", "abc"), false);
  assert.equal(safeEqualHex("", ""), false);
});

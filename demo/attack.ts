/**
 * Banc d'essai : chaque scénario est joué contre la boutique vulnérable puis contre la boutique
 * protégée, et on compare ce qui a été crédité à ce qui aurait dû l'être.
 *   npm run demo
 */
import type { AddressInfo } from "node:net";
import { buildPaydunyaIpnBody, sha512Hex, signFedapayPayload } from "../src/index.js";
import { createShop, createShopState, FEDAPAY_SECRET, PAYDUNYA_MASTER_KEY, type ShopState } from "./shop.js";

interface Delivery {
  path: "fedapay" | "paydunya";
  body: string;
  headers?: Record<string, string>;
}

interface Scenario {
  title: string;
  /** Ce qu'une boutique correcte doit créditer, en F CFA. */
  expected: number;
  setup: (state: ShopState) => void;
  deliveries: () => Delivery[];
}

const now = () => Math.floor(Date.now() / 1000);
const fedapayBody = (id: number, amount: number) =>
  JSON.stringify({ name: "transaction.approved", object: "transaction", entity: { id, status: "approved", amount } });
const unpaidOrder = (key: string, amount = 5000) => (s: ShopState) => {
  s.orders.set(key, { amount, credited: 0 });
};

const scenarios: Scenario[] = [
  {
    title: "Paiement FedaPay légitime",
    expected: 5000,
    setup: unpaidOrder("9000"),
    deliveries: () => {
      const body = fedapayBody(9000, 5000);
      return [{ path: "fedapay", body, headers: { "x-fedapay-signature": signFedapayPayload(body, FEDAPAY_SECRET, now()) } }];
    },
  },
  {
    title: "FedaPay : notification forgée, sans signature",
    expected: 0,
    setup: unpaidOrder("9001"),
    deliveries: () => [{ path: "fedapay", body: fedapayBody(9001, 50_000) }],
  },
  {
    title: "FedaPay : montant gonflé dans une vraie notification",
    expected: 0,
    setup: unpaidOrder("9002"),
    deliveries: () => {
      const genuine = fedapayBody(9002, 5000);
      const header = signFedapayPayload(genuine, FEDAPAY_SECRET, now());
      return [{ path: "fedapay", body: genuine.replace("5000", "500000"), headers: { "x-fedapay-signature": header } }];
    },
  },
  {
    title: "FedaPay : vraie notification capturée, rejouée 1 h après",
    expected: 0,
    setup: unpaidOrder("9003"),
    deliveries: () => {
      const body = fedapayBody(9003, 5000);
      return [{ path: "fedapay", body, headers: { "x-fedapay-signature": signFedapayPayload(body, FEDAPAY_SECRET, now() - 3600) } }];
    },
  },
  {
    title: "FedaPay : même notification livrée 3 fois (relances)",
    expected: 5000,
    setup: unpaidOrder("9004"),
    deliveries: () => {
      const body = fedapayBody(9004, 5000);
      const headers = { "x-fedapay-signature": signFedapayPayload(body, FEDAPAY_SECRET, now()) };
      return [1, 2, 3].map(() => ({ path: "fedapay" as const, body, headers }));
    },
  },
  {
    title: "Paiement PayDunya légitime",
    expected: 5000,
    setup: (s) => {
      unpaidOrder("PD-OK")(s);
      s.paydunyaTruth.set("PD-OK", { status: "completed", totalAmount: 5000, raw: {} });
    },
    deliveries: () => [
      { path: "paydunya", body: buildPaydunyaIpnBody({ masterKey: PAYDUNYA_MASTER_KEY, token: "PD-OK", status: "completed", totalAmount: 5000 }) },
    ],
  },
  {
    title: "PayDunya : hash recopié, facture jamais payée",
    expected: 0,
    setup: (s) => {
      unpaidOrder("PD-UNPAID")(s);
      s.paydunyaTruth.set("PD-UNPAID", { status: "pending", totalAmount: 5000, raw: {} });
    },
    deliveries: () => {
      // Le hash vu dans UNE ancienne notification (journal, proxy...) : il ne change jamais.
      const capturedHash = sha512Hex(PAYDUNYA_MASTER_KEY);
      const params = new URLSearchParams({
        "data[hash]": capturedHash,
        "data[status]": "completed",
        "data[invoice][token]": "PD-UNPAID",
        "data[invoice][total_amount]": "1000000",
      });
      return [{ path: "paydunya", body: params.toString() }];
    },
  },
];

async function main(): Promise<void> {
  const rows: string[][] = [];
  let totalLossVulnerable = 0;
  let totalLossProtected = 0;
  const journal: string[] = [];

  for (const scenario of scenarios) {
    const state = createShopState();
    scenario.setup(state);
    const server = createShop(state);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;

    const deliveries = scenario.deliveries();
    for (const mode of ["vulnerable", "protected"] as const) {
      for (const d of deliveries) {
        const contentType = d.path === "paydunya" ? "application/x-www-form-urlencoded" : "application/json";
        await fetch(`http://127.0.0.1:${port}/${mode}/${d.path}`, {
          method: "POST",
          headers: { "content-type": contentType, ...(d.headers ?? {}) },
          body: d.body,
        });
      }
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));

    const { vulnerable, protected: guarded } = state.credited;
    totalLossVulnerable += Math.max(0, vulnerable - scenario.expected);
    totalLossProtected += Math.max(0, guarded - scenario.expected);
    rows.push([scenario.title, fcfa(scenario.expected), verdict(vulnerable, scenario.expected), verdict(guarded, scenario.expected)]);
    for (const e of state.journal) {
      journal.push(`  ${e.provider.padEnd(9)} ${e.outcome.padEnd(9)} ${e.reason ?? ""}${e.detail ? ` (${e.detail})` : ""}`);
    }
  }

  printTable(["Scénario", "Attendu", "Boutique vulnérable", "Boutique protégée"], rows);
  console.log(`\nPerte totale : vulnérable ${fcfa(totalLossVulnerable)}, protégée ${fcfa(totalLossProtected)}`);
  console.log("\nJournal de la boutique protégée :");
  console.log(journal.join("\n"));
  if (totalLossProtected !== 0) process.exitCode = 1;
}

function verdict(credited: number, expected: number): string {
  return `${credited === expected ? "OK " : "KO "} ${fcfa(credited)}`;
}

function fcfa(amount: number): string {
  return `${amount.toLocaleString("fr-FR").replace(/ | /g, " ")} F`;
}

function printTable(head: string[], rows: string[][]): void {
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
  const line = (cells: string[]) => cells.map((c, i) => c.padEnd(widths[i] ?? 0)).join(" | ");
  console.log(line(head));
  console.log(widths.map((w) => "-".repeat(w)).join("-|-"));
  for (const r of rows) console.log(line(r));
}

await main();

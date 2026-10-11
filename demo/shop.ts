/**
 * Boutique de démonstration, en deux versions derrière le même serveur :
 *  - /vulnerable/* : ce qu'on trouve souvent en production, le webhook est cru sur parole ;
 *  - /protected/*  : la même boutique avec webhook-guard.
 * Tout est local, avec des secrets de test. Aucun appel à un vrai prestataire.
 */
import { createServer, type IncomingMessage, type Server } from "node:http";
import {
  guardPaydunya,
  handleWebhook,
  MemoryReplayStore,
  verifyFedapay,
  verifyPaydunyaIpn,
  type FedapayEvent,
  type JournalEntry,
  type PaydunyaConfirmation,
} from "../src/index.js";

export const FEDAPAY_SECRET = "wh_sandbox_demo_secret";
export const PAYDUNYA_MASTER_KEY = "demo_master_key";

interface Order {
  amount: number;
  credited: number;
}

export interface ShopState {
  /** Commandes de la boutique, par référence de transaction FedaPay ou jeton de facture PayDunya. */
  orders: Map<string, Order>;
  /** Ce que PayDunya sait réellement de chaque facture (simule l'API de confirmation). */
  paydunyaTruth: Map<string, PaydunyaConfirmation>;
  credited: { vulnerable: number; protected: number };
  journal: JournalEntry[];
}

export function createShopState(): ShopState {
  return { orders: new Map(), paydunyaTruth: new Map(), credited: { vulnerable: 0, protected: 0 }, journal: [] };
}

export function createShop(state: ShopState): Server {
  const store = new MemoryReplayStore();
  const journal = (entry: JournalEntry) => {
    state.journal.push(entry);
  };

  return createServer(async (req, res) => {
    const rawBody = await readBody(req);
    const reply = (status: number) => {
      // Le corps ne dit jamais pourquoi c'est refusé : le motif reste dans le journal.
      res.writeHead(status, { "content-type": "text/plain" }).end(status === 200 ? "ok" : "refused");
    };

    switch (`${req.method} ${req.url}`) {
      case "POST /vulnerable/fedapay": {
        const event = JSON.parse(rawBody.toString("utf8")) as FedapayEvent;
        if (event.name === "transaction.approved") state.credited.vulnerable += Number(event.entity.amount);
        return reply(200);
      }

      case "POST /protected/fedapay": {
        const result = await handleWebhook({
          provider: "fedapay",
          store,
          journal,
          remoteAddress: req.socket.remoteAddress ?? "?",
          verify: () => verifyFedapay({ rawBody, signatureHeader: header(req, "x-fedapay-signature"), secret: FEDAPAY_SECRET }),
          onEvent: (event) => {
            if (event.name !== "transaction.approved") return;
            const order = state.orders.get(String(event.entity.id));
            // Le montant fait foi dans NOTRE base ; la notification ne fait que le confirmer.
            if (!order || Number(event.entity.amount) !== order.amount) throw new Error("commande inconnue ou montant différent");
            order.credited += order.amount;
            state.credited.protected += order.amount;
          },
        });
        return reply(result.status);
      }

      case "POST /vulnerable/paydunya": {
        // Ce que montre l'exemple officiel : hash vérifié, puis le statut de la notification est cru.
        const checked = verifyPaydunyaIpn({ rawBody, masterKey: PAYDUNYA_MASTER_KEY });
        if (checked.ok && checked.event.status === "completed") {
          state.credited.vulnerable += Number(checked.event.invoice?.total_amount);
        }
        return reply(checked.ok ? 200 : 401);
      }

      case "POST /protected/paydunya": {
        const result = await handleWebhook({
          provider: "paydunya",
          store,
          journal,
          verify: () =>
            guardPaydunya({
              rawBody,
              masterKey: PAYDUNYA_MASTER_KEY,
              confirm: async (token) => state.paydunyaTruth.get(token) ?? { status: "unknown", totalAmount: null, raw: {} },
              expectedAmount: (token) => state.orders.get(token)?.amount ?? null,
            }),
          onEvent: (event) => {
            const order = state.orders.get(event.invoiceToken);
            if (!order) throw new Error("facture inconnue");
            order.credited += order.amount;
            state.credited.protected += order.amount;
          },
        });
        return reply(result.status);
      }

      default:
        return reply(404);
    }
  });
}

function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 1_000_000) throw new Error("corps trop gros");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

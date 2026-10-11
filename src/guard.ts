import type { Provider, RejectReason, Verification } from "./types.js";

/**
 * Mémoire des événements déjà traités. `claim` doit être atomique : renvoyer true une seule fois par
 * clé, même avec plusieurs instances. En production : Redis `SET key 1 NX EX ttl`, ou une table
 * avec index unique (INSERT ... ON CONFLICT DO NOTHING).
 */
export interface ReplayStore {
  claim(key: string, ttlSeconds: number): Promise<boolean>;
  /** Libère une clé si le traitement a échoué, pour que la relance du prestataire passe. */
  release(key: string): Promise<void>;
}

/** Pour un seul processus (tests, petit serveur). Perd tout au redémarrage. */
export class MemoryReplayStore implements ReplayStore {
  private readonly expiries = new Map<string, number>();

  constructor(private readonly clock: () => number = Date.now) {}

  async claim(key: string, ttlSeconds: number): Promise<boolean> {
    const now = this.clock();
    const expiry = this.expiries.get(key);
    if (expiry !== undefined && expiry > now) return false;
    this.expiries.set(key, now + ttlSeconds * 1000);
    if (this.expiries.size > 10_000) this.sweep(now);
    return true;
  }

  async release(key: string): Promise<void> {
    this.expiries.delete(key);
  }

  private sweep(now: number): void {
    for (const [key, expiry] of this.expiries) if (expiry <= now) this.expiries.delete(key);
  }
}

export type Outcome = "accepted" | "duplicate" | "rejected" | "handler_error";

export interface JournalEntry {
  at: string;
  provider: Provider;
  outcome: Outcome;
  eventId?: string;
  reason?: RejectReason;
  detail?: string;
  remoteAddress?: string;
}

export type Journal = (entry: JournalEntry) => void | Promise<void>;

export interface HandleWebhookInput<T> {
  provider: Provider;
  verify: () => Verification<T> | Promise<Verification<T>>;
  store: ReplayStore;
  onEvent: (event: T, eventId: string) => Promise<void> | void;
  journal?: Journal;
  /** Durée de mémoire des événements traités ; doit dépasser la fenêtre de relance du prestataire. */
  ttlSeconds?: number;
  remoteAddress?: string;
}

export interface HandleWebhookResult {
  /** Code HTTP à renvoyer au prestataire. */
  status: 200 | 400 | 401 | 500 | 502;
  outcome: Outcome;
  eventId?: string;
  reason?: RejectReason;
}

const DEFAULT_TTL_SECONDS = 7 * 24 * 3600;

const REASON_STATUS: Record<RejectReason, HandleWebhookResult["status"]> = {
  missing_secret: 500,
  missing_signature: 401,
  malformed_signature: 401,
  bad_signature: 401,
  stale_timestamp: 401,
  malformed_body: 400,
  not_confirmed: 400,
  confirmation_failed: 502,
  amount_mismatch: 400,
};

/**
 * Vérifie, écarte les doublons, traite, journalise. Un doublon répond 200 pour que le prestataire
 * cesse ses relances ; une erreur du traitement libère la clé et répond 500 pour qu'il réessaie.
 * Le corps de la réponse ne doit jamais contenir le motif détaillé : il renseigne un attaquant.
 */
export async function handleWebhook<T>(input: HandleWebhookInput<T>): Promise<HandleWebhookResult> {
  const log = async (entry: Omit<JournalEntry, "at" | "provider" | "remoteAddress">) => {
    if (!input.journal) return;
    const full: JournalEntry = { at: new Date().toISOString(), provider: input.provider, ...entry };
    if (input.remoteAddress !== undefined) full.remoteAddress = input.remoteAddress;
    try {
      await input.journal(full);
    } catch {
      // Un journal en panne ne doit ni bloquer un paiement légitime ni en laisser passer un faux.
    }
  };

  const verification = await input.verify();
  if (!verification.ok) {
    await log({ outcome: "rejected", reason: verification.reason, ...(verification.detail ? { detail: verification.detail } : {}) });
    return { status: REASON_STATUS[verification.reason], outcome: "rejected", reason: verification.reason };
  }

  const { event, eventId } = verification;
  if (!(await input.store.claim(eventId, input.ttlSeconds ?? DEFAULT_TTL_SECONDS))) {
    await log({ outcome: "duplicate", eventId });
    return { status: 200, outcome: "duplicate", eventId };
  }

  try {
    await input.onEvent(event, eventId);
  } catch (error) {
    await input.store.release(eventId);
    await log({ outcome: "handler_error", eventId, detail: error instanceof Error ? error.message : String(error) });
    return { status: 500, outcome: "handler_error", eventId };
  }

  await log({ outcome: "accepted", eventId });
  return { status: 200, outcome: "accepted", eventId };
}

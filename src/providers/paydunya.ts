import { safeEqualHex, sha512Hex, toBytes, type RawBody } from "../crypto.js";
import { reject, type Verification } from "../types.js";

/**
 * PayDunya envoie l'IPN en `application/x-www-form-urlencoded`, tout sous la clé `data`, avec
 * `data[hash]` = SHA-512 de la clé principale.
 *
 * ATTENTION : ce hash est le même pour toutes les notifications et ne couvre pas leur contenu. Il
 * prouve seulement que l'émetteur connaît le hash, pas que le montant ou le statut sont vrais. Une
 * seule notification interceptée (journal, proxy, outil de débogage) suffit pour en forger d'autres.
 * D'où la règle : on ne crédite qu'après `confirmPaydunyaInvoice`, qui interroge l'API PayDunya avec
 * les clés privées. `guardPaydunya` fait les deux.
 */
export interface PaydunyaIpn {
  hash?: string;
  status?: string;
  invoice?: { token?: string; total_amount?: string | number; [key: string]: unknown };
  custom_data?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface VerifyPaydunyaIpnInput {
  rawBody: RawBody;
  masterKey: string;
}

/** Contrôle du hash seul. Nécessaire, jamais suffisant : voir `guardPaydunya`. */
export function verifyPaydunyaIpn(input: VerifyPaydunyaIpnInput): Verification<PaydunyaIpn> {
  const masterKey = input.masterKey?.trim();
  if (!masterKey) return reject("missing_secret");

  const data = parsePaydunyaBody(toBytes(input.rawBody).toString("utf8"));
  if (!data) return reject("malformed_body");
  if (typeof data.hash !== "string" || data.hash.trim() === "") return reject("missing_signature");
  if (!safeEqualHex(sha512Hex(masterKey), data.hash)) return reject("bad_signature");

  const token = data.invoice?.token;
  if (typeof token !== "string" || token === "") return reject("malformed_body", "jeton de facture absent");
  return { ok: true, event: data, eventId: `paydunya:${token}:${data.status ?? "?"}` };
}

/** Lit `data[...]` en formulaire (cas documenté) ou en JSON `{ "data": {...} }`. */
export function parsePaydunyaBody(body: string): PaydunyaIpn | null {
  const text = body.trim();
  if (text === "") return null;
  if (text.startsWith("{")) {
    try {
      const json = JSON.parse(text) as { data?: unknown };
      return isRecord(json.data) ? (json.data as PaydunyaIpn) : null;
    } catch {
      return null;
    }
  }
  const root: Record<string, unknown> = {};
  for (const [key, value] of new URLSearchParams(text)) assignBracketPath(root, key, value);
  return isRecord(root.data) ? (root.data as PaydunyaIpn) : null;
}

/** `data[invoice][token]=x` devient `{ data: { invoice: { token: "x" } } }`. Les clés dangereuses sont ignorées. */
function assignBracketPath(root: Record<string, unknown>, key: string, value: string): void {
  const match = /^([^[\]]+)((?:\[[^[\]]*\])*)$/.exec(key);
  if (!match) return;
  const path = [match[1] as string, ...[...(match[2] ?? "").matchAll(/\[([^[\]]*)\]/g)].map((m) => m[1] as string)];
  if (path.some((p) => p === "__proto__" || p === "constructor" || p === "prototype" || p === "")) return;
  let node = root;
  for (let i = 0; i < path.length - 1; i++) {
    const part = path[i] as string;
    if (!isRecord(node[part])) node[part] = {};
    node = node[part] as Record<string, unknown>;
  }
  node[path[path.length - 1] as string] = value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export interface PaydunyaKeys {
  masterKey: string;
  privateKey: string;
  token: string;
}

export interface PaydunyaConfirmation {
  status: "completed" | "pending" | "cancelled" | "failed" | "unknown";
  totalAmount: number | null;
  raw: Record<string, unknown>;
}

export interface ConfirmPaydunyaInput {
  invoiceToken: string;
  keys: PaydunyaKeys;
  mode: "live" | "test";
  /** Par défaut https://app.paydunya.com ; remplaçable pour les tests. */
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/** GET {base}/{api|sandbox-api}/v1/checkout-invoice/confirm/{jeton}, avec les trois clés en en-têtes. */
export async function confirmPaydunyaInvoice(input: ConfirmPaydunyaInput): Promise<PaydunyaConfirmation> {
  const base = (input.baseUrl ?? "https://app.paydunya.com").replace(/\/+$/, "");
  const prefix = input.mode === "live" ? "api" : "sandbox-api";
  const url = `${base}/${prefix}/v1/checkout-invoice/confirm/${encodeURIComponent(input.invoiceToken)}`;
  const response = await (input.fetchImpl ?? fetch)(url, {
    method: "GET",
    headers: {
      Accept: "application/json",
      "PAYDUNYA-MASTER-KEY": input.keys.masterKey,
      "PAYDUNYA-PRIVATE-KEY": input.keys.privateKey,
      "PAYDUNYA-TOKEN": input.keys.token,
    },
    signal: AbortSignal.timeout(input.timeoutMs ?? 10_000),
  });
  if (!response.ok) throw new Error(`PayDunya confirm HTTP ${response.status}`);
  const raw = (await response.json()) as Record<string, unknown>;
  const invoice = isRecord(raw.invoice) ? raw.invoice : {};
  const amount = Number(invoice.total_amount ?? raw.total_amount);
  return {
    status: mapPaydunyaStatus(raw.status),
    totalAmount: Number.isFinite(amount) ? amount : null,
    raw,
  };
}

export function mapPaydunyaStatus(status: unknown): PaydunyaConfirmation["status"] {
  switch (typeof status === "string" ? status.toLowerCase() : "") {
    case "completed":
      return "completed";
    case "pending":
      return "pending";
    case "cancelled":
    case "canceled":
      return "cancelled";
    case "failed":
      return "failed";
    default:
      return "unknown";
  }
}

export interface GuardPaydunyaInput extends VerifyPaydunyaIpnInput {
  confirm: (invoiceToken: string) => Promise<PaydunyaConfirmation>;
  /** Montant attendu pour cette facture, lu dans TA base, jamais dans la notification. */
  expectedAmount?: (invoiceToken: string) => Promise<number | null> | number | null;
}

export interface ConfirmedPaydunyaIpn {
  ipn: PaydunyaIpn;
  invoiceToken: string;
  confirmation: PaydunyaConfirmation;
}

/** Hash + confirmation auprès de l'API + montant attendu : seule combinaison sûre pour créditer. */
export async function guardPaydunya(input: GuardPaydunyaInput): Promise<Verification<ConfirmedPaydunyaIpn>> {
  const checked = verifyPaydunyaIpn(input);
  if (!checked.ok) return checked;
  const invoiceToken = checked.event.invoice?.token as string;

  let confirmation: PaydunyaConfirmation;
  try {
    confirmation = await input.confirm(invoiceToken);
  } catch (error) {
    return reject("confirmation_failed", error instanceof Error ? error.message : String(error));
  }
  if (confirmation.status !== "completed") return reject("not_confirmed", `statut API : ${confirmation.status}`);

  if (input.expectedAmount) {
    const expected = await input.expectedAmount(invoiceToken);
    if (expected === null || confirmation.totalAmount === null || confirmation.totalAmount !== expected) {
      return reject("amount_mismatch", `attendu ${expected}, confirmé ${confirmation.totalAmount}`);
    }
  }

  return {
    ok: true,
    event: { ipn: checked.event, invoiceToken, confirmation },
    // Clé fondée sur le statut CONFIRMÉ, pas sur celui annoncé par la notification.
    eventId: `paydunya:${invoiceToken}:${confirmation.status}`,
  };
}

/** Corps d'IPN au format PayDunya : pour les tests et le banc d'essai. */
export function buildPaydunyaIpnBody(fields: { masterKey: string; token: string; status: string; totalAmount: number }): string {
  const params = new URLSearchParams();
  params.set("data[hash]", sha512Hex(fields.masterKey));
  params.set("data[status]", fields.status);
  params.set("data[invoice][token]", fields.token);
  params.set("data[invoice][total_amount]", String(fields.totalAmount));
  return params.toString();
}

import { hmacHex, safeEqualHex, toBytes, type RawBody } from "../crypto.js";
import { reject, type Verification } from "../types.js";

/** Tolérance par défaut de la bibliothèque officielle fedapay-node (Webhook.DEFAULT_TOLERANCE). */
export const FEDAPAY_DEFAULT_TOLERANCE_SECONDS = 300;

export interface FedapayEvent {
  id?: string | number;
  name: string;
  object?: string;
  entity: {
    id?: string | number;
    reference?: string;
    status?: string;
    amount?: number;
    currency?: { iso?: string } | string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface VerifyFedapayInput {
  /** Corps brut de la requête, tel que reçu. */
  rawBody: RawBody;
  /** Valeur de l'en-tête X-FEDAPAY-SIGNATURE. */
  signatureHeader: string | null | undefined;
  /** Clé secrète du point de terminaison (tableau de bord FedaPay, différente en test et en live). */
  secret: string;
  toleranceSeconds?: number;
  now?: Date;
}

/**
 * En-tête `t=<horodatage>,s=<hmac>[,s=<hmac>...]`, HMAC-SHA256 de `<horodatage>.<corps brut>`.
 * Contrairement à certaines intégrations maison, un en-tête sans horodatage est refusé : sans `t`,
 * rien n'empêche de rejouer indéfiniment une notification capturée.
 */
export function verifyFedapay(input: VerifyFedapayInput): Verification<FedapayEvent> {
  const secret = input.secret?.trim();
  if (!secret) return reject("missing_secret");
  const header = input.signatureHeader?.trim();
  if (!header) return reject("missing_signature");

  const parsed = parseHeader(header);
  if (!parsed) return reject("malformed_signature");

  const signed = Buffer.concat([Buffer.from(`${parsed.timestamp}.`, "utf8"), toBytes(input.rawBody)]);
  const expected = hmacHex("sha256", secret, signed);
  if (!parsed.signatures.some((s) => safeEqualHex(expected, s))) return reject("bad_signature");

  // Écart dans les deux sens : un horodatage dans le futur est aussi suspect qu'un vieux.
  const tolerance = input.toleranceSeconds ?? FEDAPAY_DEFAULT_TOLERANCE_SECONDS;
  const nowSeconds = Math.floor((input.now ?? new Date()).getTime() / 1000);
  if (Math.abs(nowSeconds - parsed.timestamp) > tolerance) {
    return reject("stale_timestamp", `écart de ${nowSeconds - parsed.timestamp} s`);
  }

  let event: FedapayEvent;
  try {
    event = JSON.parse(toBytes(input.rawBody).toString("utf8")) as FedapayEvent;
  } catch {
    return reject("malformed_body");
  }
  if (typeof event?.name !== "string" || typeof event.entity !== "object" || event.entity === null) {
    return reject("malformed_body");
  }

  return { ok: true, event, eventId: fedapayEventId(event) };
}

/**
 * Clé d'idempotence : identifiant de l'événement s'il existe, sinon nom + transaction + statut.
 * Une transaction peut légitimement passer de « pending » à « approved » : seuls les doublons
 * exacts sont écartés.
 */
export function fedapayEventId(event: FedapayEvent): string {
  if (event.id !== undefined && event.id !== null && `${event.id}` !== "") return `fedapay:event:${event.id}`;
  return `fedapay:${event.name}:${event.entity.id ?? "?"}:${event.entity.status ?? "?"}`;
}

function parseHeader(header: string): { timestamp: number; signatures: string[] } | null {
  let timestamp: number | null = null;
  const signatures: string[] = [];
  for (const item of header.split(",")) {
    const eq = item.indexOf("=");
    if (eq < 0) continue;
    const key = item.slice(0, eq).trim();
    const value = item.slice(eq + 1).trim();
    if (key === "t" && /^\d{1,12}$/.test(value)) timestamp = Number(value);
    else if (key === "s" && /^[0-9a-fA-F]{64}$/.test(value)) signatures.push(value);
  }
  if (timestamp === null || signatures.length === 0) return null;
  return { timestamp, signatures };
}

/** Fabrique un en-tête valide : pour les tests et le banc d'essai, jamais en production. */
export function signFedapayPayload(rawBody: RawBody, secret: string, timestamp = Math.floor(Date.now() / 1000)): string {
  const signed = Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), toBytes(rawBody)]);
  return `t=${timestamp},s=${hmacHex("sha256", secret, signed)}`;
}

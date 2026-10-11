# webhook-guard

**Sécuriser les webhooks de paiement africains : FedaPay, PayDunya, NOWPayments.**
*English version below.*

Quand un paiement réussit, le prestataire prévient la boutique par un webhook : une requête HTTP
« la transaction 4242 est payée ». Beaucoup de boutiques créditent dès réception, sans vérifier qui
parle. N'importe qui peut alors envoyer la même requête et se faire créditer.

`webhook-guard` est une bibliothèque TypeScript sans dépendance qui ferme ces portes, avec un banc
d'essai qui montre l'attaque puis la protection.

## La démonstration

```bash
npm install
npm run demo
```

Chaque scénario est joué contre une boutique « comme on en voit souvent » puis contre la même
boutique protégée :

```
Scénario                                                 | Attendu | Boutique vulnérable | Boutique protégée
---------------------------------------------------------|---------|---------------------|------------------
Paiement FedaPay légitime                                | 5 000 F | OK  5 000 F         | OK  5 000 F
FedaPay : notification forgée, sans signature            | 0 F     | KO  50 000 F        | OK  0 F
FedaPay : montant gonflé dans une vraie notification     | 0 F     | KO  500 000 F       | OK  0 F
FedaPay : vraie notification capturée, rejouée 1 h après | 0 F     | KO  5 000 F         | OK  0 F
FedaPay : même notification livrée 3 fois (relances)     | 5 000 F | KO  15 000 F        | OK  5 000 F
Paiement PayDunya légitime                               | 5 000 F | OK  5 000 F         | OK  5 000 F
PayDunya : hash recopié, facture jamais payée            | 0 F     | KO  1 000 000 F     | OK  0 F

Perte totale : vulnérable 1 565 000 F, protégée 0 F
```

Tout tourne en local avec des secrets de test : aucun appel à un vrai prestataire.

## Ce que fait la bibliothèque

| Contrôle | Pourquoi |
|---|---|
| Signature vérifiée sur les **octets bruts** reçus | Un JSON décodé puis réencodé ne donne pas les mêmes octets : la vérification échoue ou, pire, on finit par la désactiver. |
| Comparaison **en temps constant** | Une comparaison caractère par caractère laisse deviner la signature au chronomètre. |
| **Horodatage** obligatoire (FedaPay, 5 min) | Sans lui, une vraie notification capturée se rejoue indéfiniment. |
| **Idempotence** par identifiant d'événement | Les prestataires relancent : sans elle, un paiement est crédité plusieurs fois. |
| **Confirmation par l'API** (PayDunya) | Voir ci-dessous : le hash PayDunya ne protège pas le contenu. |
| **Montant attendu lu dans votre base** | La notification confirme un paiement, elle ne fixe jamais le montant crédité. |
| **Journal** de chaque tentative | Acceptée, doublon, refusée avec le motif. Le motif n'est jamais renvoyé à l'appelant. |
| Refus par défaut | Secret absent, en-tête mal formé, corps illisible : refus, jamais d'acceptation « pour ne pas bloquer ». |

## Le cas PayDunya

La documentation PayDunya indique que l'IPN contient `data[hash]`, le SHA-512 de la clé principale,
et qu'il suffit de le comparer. Ce hash est **le même pour toutes les notifications** et ne couvre ni
le montant ni le statut. Quiconque a vu une seule notification (journal applicatif, proxy, outil de
débogage) peut en forger autant qu'il veut.

`guardPaydunya` vérifie donc le hash, **puis** interroge l'API PayDunya
(`checkout-invoice/confirm/{jeton}`) avec les clés privées, et ne crédite que si la facture est
`completed` pour le montant attendu.

## Utilisation

```ts
import { handleWebhook, MemoryReplayStore, verifyFedapay } from "webhook-guard";

const store = new MemoryReplayStore(); // en production : Redis SET NX, ou index unique en base

app.post("/webhooks/fedapay", express.raw({ type: "*/*" }), async (req, res) => {
  const result = await handleWebhook({
    provider: "fedapay",
    store,
    journal: (entry) => logger.info(entry),
    verify: () => verifyFedapay({
      rawBody: req.body, // Buffer brut, surtout pas express.json()
      signatureHeader: req.get("x-fedapay-signature"),
      secret: process.env.FEDAPAY_WEBHOOK_SECRET!,
    }),
    onEvent: async (event) => {
      // markPaid refuse si le montant diffère de celui de la commande enregistrée
      if (event.name === "transaction.approved") await orders.markPaid(event.entity.id, event.entity.amount);
    },
  });
  res.sendStatus(result.status);
});
```

PayDunya :

```ts
verify: () => guardPaydunya({
  rawBody: req.body,
  masterKey: process.env.PAYDUNYA_MASTER_KEY!,
  confirm: (token) => confirmPaydunyaInvoice({ invoiceToken: token, keys, mode: "live" }),
  expectedAmount: (token) => orders.amountFor(token),
}),
```

NOWPayments : `verifyNowpayments({ rawBody, signatureHeader: req.get("x-nowpayments-sig"), ipnSecret })`.

Codes renvoyés : `200` traité ou doublon (le prestataire cesse ses relances), `401` signature,
`400` corps ou montant, `500` erreur de votre traitement (la clé est libérée, la relance repassera),
`502` API de confirmation injoignable.

## Tests

```bash
npm test   # 41 tests, node:test, sans dépendance
```

## Limites connues

- `MemoryReplayStore` vit dans un seul processus. Avec plusieurs instances, utilisez Redis ou un
  index unique en base, et gardez de toute façon une contrainte d'unicité sur le crédit lui-même.
- NOWPayments signe un JSON réencodé : la forme exacte n'est pas entièrement spécifiée. Deux formes
  canoniques sont acceptées (celle de leur exemple et un tri récursif). À valider avec une IPN réelle
  du bac à sable.
- FedaPay publie aussi une liste d'adresses IP d'envoi : la filtrer au niveau du serveur est un
  complément utile, pas un remplacement de la signature.

---

# English

**Secure African payment webhooks: FedaPay, PayDunya, NOWPayments.**

Payment providers notify shops of successful payments through webhooks. Many shops credit the
customer as soon as the request arrives, without checking who sent it, so anyone can send the same
request and get credited.

`webhook-guard` is a dependency-free TypeScript library that closes these gaps, with a test bench
that shows each attack and its fix (`npm run demo`, table above: the vulnerable shop loses
1,565,000 F CFA, the protected one loses nothing, and legitimate payments go through on both).

**What it checks:** signatures on the raw bytes, constant-time comparison, mandatory timestamp
(FedaPay, 5 minutes), idempotency per event, server-side confirmation (PayDunya), expected amount
taken from your own database, an audit log of every attempt, and deny-by-default on any missing
secret or malformed input.

**The PayDunya finding:** the IPN `hash` is the SHA-512 of the merchant's master key. It is the
same for every notification and does not cover the amount or status, so a single leaked
notification lets anyone forge others. `guardPaydunya` checks the hash, then confirms the invoice
through PayDunya's API with the private keys, and only credits a `completed` invoice for the
expected amount.

## License

MIT, by [CREZZUSS](https://crezzuss.com), Lomé, Togo.

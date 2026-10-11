# webhook-guard

Projet n°1 du portfolio cybersécurité de CREZZUSS (voir la mémoire projet-securite-portfolio) :
bibliothèque TypeScript sans dépendance qui sécurise les webhooks FedaPay, PayDunya et NOWPayments,
avec un banc d'essai attaque / protection.

## Commandes
- `npm test` : build `tsc` puis `node --test` (41 tests au 11/10/2026).
- `npm run demo` : boutique vulnérable vs protégée, tableau des pertes ; code de sortie 1 si la boutique protégée perd quoi que ce soit.

## Structure
- `src/crypto.ts` : HMAC, SHA-512, comparaison en temps constant, octets bruts.
- `src/providers/fedapay.ts` : `t=..,s=..`, HMAC-SHA256 de `t.corps`, tolérance 300 s dans les deux sens, pas de repli sans `t`.
- `src/providers/nowpayments.ts` : HMAC-SHA512 du JSON trié ; deux formes canoniques acceptées (exemple officiel à replacer de premier niveau + tri récursif).
- `src/providers/paydunya.ts` : hash = SHA-512(clé principale), statique, ne couvre pas le contenu ; `guardPaydunya` = hash + `confirmPaydunyaInvoice` (GET `/{api|sandbox-api}/v1/checkout-invoice/confirm/{jeton}`, en-têtes PAYDUNYA-MASTER-KEY/PRIVATE-KEY/TOKEN) + montant attendu.
- `src/guard.ts` : `handleWebhook` (vérif, idempotence via `ReplayStore`, journal, codes HTTP), `MemoryReplayStore`.
- `demo/` : `shop.ts` (2 boutiques sur un serveur node:http) et `attack.ts` (7 scénarios).

## Règles
- Commentaires en français, identifiants en anglais, README FR + EN. Pas de tirets longs.
- Aucun appel à un vrai prestataire ni clé réelle dans le dépôt.
- Sources des formats : bibliothèque officielle fedapay-node (Webhook / WebhookSignature), developers.paydunya.com (IPN + confirm), adaptateur PayDunya d'e_Card v3.20, NowPaymentsGateway de Projett.

## Suite prévue
Ports Java (e_Card, mathsup ont déjà FedaPay) et PHP (Projett), publication GitHub, section Projets LinkedIn.

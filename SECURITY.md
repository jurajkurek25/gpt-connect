# Bezpečnostný kontrolný zoznam

Stav: ✅ implementované a otestované · 🔧 úloha pri nasadení (prevádzkovateľ) · ⚠️ známe obmedzenie

## Autentifikácia a autorizácia

- ✅ Každá požiadavka na `/mcp` vyžaduje platný Bearer token vydaný týmto serverom (`requireBearerAuth`, scope `tasks`, kontrola expirácie a `resource`/audience). Bez tokenu `401` s `WWW-Authenticate` a odkazom na metadáta (RFC 9728).
- ✅ OAuth 2.1: iba `response_type=code`, povinné PKCE `S256` (aj voči Googlu), jednorazové autorizačné kódy s platnosťou 2 min, detekcia opakovaného použitia kódu → zrušenie celej rodiny tokenov.
- ✅ Access token 1 h, refresh token 30 dní s rotáciou; opakované použitie starého refresh tokenu zruší celú rodinu tokenov.
- ✅ Tokeny servera sa ukladajú iba ako SHA-256 hash; `AuthInfo` v nástrojoch neobsahuje surový token.
- ✅ Parameter `resource` (RFC 8707) – tokeny sú viazané na `https://DOMENA/mcp`; cudzí resource → `invalid_target`.
- ✅ Prepojenie klienta vyžaduje **prístupovú frázu vlastníka** (porovnanie v konštantnom čase, rate limit 10 pokusov / 15 min / IP).
- ✅ Jeden používateľ: Google účet (`sub`) sa naviaže pri prvom prihlásení; iný účet je odmietnutý a jeho grant okamžite odvolaný.
- ✅ Kontrola udelených Google rozsahov – bez `tasks` sa pripojenie zamietne.
- ✅ Odvolanie tokenov (RFC 7009), odpojenie účtu (`dist/cli/disconnect.js`) a automatické odpojenie pri `invalid_grant` z Googlu.

## OAuth tok a CSRF

- ✅ `state` voči Googlu: 256-bit náhodný, uložený ako hash, jednorazový, platnosť 10 min.
- ✅ Väzba na prehliadač: HttpOnly cookie (`__Host-` prefix, `Secure`, `SameSite=Lax`) s nonce, ktorej hash sa kontroluje pri súhlase aj pri Google callbacku (ochrana proti CSRF / login-CSRF).
- ✅ Redirect URI klienta: presná zhoda s registrovanou; registrácia povolená len pre URI z allowlistu `ALLOWED_REDIRECT_URIS`. Pred overením `client_id` a `redirect_uri` sa nikdy nepresmeruje (ochrana proti open redirect).
- ✅ Odpoveď autorizácie obsahuje `iss` (RFC 9207).
- ✅ ID token z Googlu: kontrola `iss`, `aud` a `exp` (prijatý priamo z token endpointu cez TLS, OIDC Core 3.1.3.7).
- ✅ Limit počtu registrovaných klientov (50) s vyradením starých nepoužitých klientov; rate limit registrácie.

## Ochrana tajomstiev

- ✅ Google refresh aj access token šifrované AES-256-GCM (náhodné IV, AAD viazané na účel poľa). Kľúč len v premennej prostredia.
- ✅ Google tokeny sa nikdy nevracajú v odpovediach nástrojov ani v chybách (test *acceptance 8* kontroluje všetky odpovede, logy a audit log).
- ✅ Logovanie: JSON logy s redakciou citlivých kľúčov (`token`, `secret`, `code`, `authorization`, `cookie`, `passphrase`, `notes`, `title`, …) a vzorov tokenov (`Bearer …`, `ya29.…`). HTTP log obsahuje iba cestu bez query stringu. Chyby parsovania tela sa logujú bez obsahu.
- ✅ Audit log (`audit_log` v DB) ukladá udalosť, výsledok, ID klienta, ID zoznamu/úlohy a hash zdroja – **nie** názvy, poznámky, obsah e-mailov ani tajomstvá.
- ✅ Chyby konfigurácie uvádzajú len názvy premenných, nie hodnoty.
- ✅ `.env`, databáza a `data/` sú v `.gitignore` aj `.dockerignore`; `.env.example` obsahuje len zástupné hodnoty.
- ✅ Súbor DB má práva 600, adresár 700.
- 🔧 `chmod 600 .env`; zálohujte `TOKEN_ENCRYPTION_KEY` oddelene od zálohy databázy; voliteľne použite správcu tajomstiev.
- 🔧 Nikdy nevkladajte OAuth secret, access ani refresh tokeny do chatu, ticketov ani Gitu.

## Validácia vstupov a injekcie

- ✅ Všetky vstupy nástrojov validované Zod schémami: ID len `[A-Za-z0-9_\-:=]` (alebo `@default`) → žiadna path injection do URL Google API; dátumy striktne `YYYY-MM-DD` a reálny kalendárny dátum; názov jednoriadkový bez riadiacich znakov, max. 1024; poznámky max. 7800 bez riadiacich znakov.
- ✅ Žiadny nástroj nevykonáva kód, shell príkazy ani ľubovoľné HTTP požiadavky. Odchádzajúce volania idú len na pevne zadané Google endpointy (`accounts.google.com`, `oauth2.googleapis.com`, `tasks.googleapis.com`), `redirect: 'error'`, časové limity → **žiadne SSRF**. CIMD (načítanie URL klienta) zámerne nie je implementované.
- ✅ Prompt injection: server nikdy neinterpretuje obsah e-mailov/úloh ako príkazy; inštrukcie servera a popisy nástrojov označujú tento obsah ako nedôveryhodné dáta. Mazanie je dvojkrokové s tokenom viazaným na konkrétnu úlohu (HMAC, 5 min).
- ✅ HTML stránky escapujú všetky hodnoty; prísna CSP (`default-src 'none'`, `form-action` len self/Google/ChatGPT, `frame-ancestors 'none'`).

## HTTP a sieť

- ✅ Validácia hlavičky `Host` (ochrana proti DNS rebinding).
- ✅ Žiadne CORS hlavičky (ani wildcard) – ChatGPT volá server zo serverovej strany.
- ✅ Helmet: HSTS, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `X-Frame-Options`, CORP `same-origin`.
- ✅ Rate limiting: `/oauth/*` 30/min, súhlas 10/15 min, registrácia 20/h, `/mcp` 120/min, discovery 60/min (na IP).
- ✅ Limity veľkosti tela (16 kB OAuth, 256 kB MCP).
- ✅ `Cache-Control: no-store` na všetkých OAuth odpovediach.
- 🔧 HTTPS povinné (`PUBLIC_BASE_URL` musí byť `https://`; Caddy rieši certifikát). Aplikáciu nevystavujte priamo bez TLS proxy.
- 🔧 `TRUST_PROXY_HOPS` musí zodpovedať počtu proxy, inak sa dá obísť rate limit falšovaním `X-Forwarded-For`.
- 🔧 Firewall: verejne len 80/443.

## Kontajner a prevádzka

- ✅ Beh ako používateľ `node`, read-only root FS, `cap_drop: ALL`, `no-new-privileges`, bez zverejneného portu aplikácie, healthcheck.
- ✅ `npm audit` bez zraniteľností pri vydaní; lockfile je súčasťou repozitára, build cez `npm ci --ignore-scripts`.
- 🔧 Pravidelne aktualizujte závislosti a obraz (`npm audit`, `docker compose build --pull`).
- 🔧 Sledujte logy (`warn`: zlá prístupová fráza, odmietnutý účet, odmietnutá DCR).
- 🔧 Google OAuth aplikáciu ponechajte s rozsahmi iba `openid` a `tasks`.

## Známe obmedzenia

- ⚠️ Server nevie dokázať, že akciu schválil človek; spolieha sa na potvrdenia hostiteľa (ChatGPT), anotácie nástrojov a inštrukcie.
- ⚠️ Otvorená DCR (vyžadovaná ChatGPT) umožňuje registráciu klientov komukoľvek; bez prístupovej frázy však nezískajú token.
- ⚠️ Zámok proti súbežným duplikátom je v pamäti – podporovaná je jedna inštancia.
- ⚠️ Overenie podpisu Google ID tokenu sa vynecháva (povolené pre token prijatý priamo z token endpointu cez TLS).

## Hlásenie zraniteľností

Zraniteľnosti hláste súkromne vlastníkovi repozitára, nie verejným issue.

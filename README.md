# Google Tasks MCP server pre ChatGPT

Samostatne hostovaný server [Model Context Protocol (MCP)](https://modelcontextprotocol.io), cez ktorý môže AI asistent (ChatGPT alebo iný MCP klient) **bezpečne spravovať úlohy v osobnom účte Google Tasks**.

Hlavný scenár: ChatGPT prečíta školský e-mail cez existujúce pripojenie Outlooku, navrhne úlohu s termínom, vy ju schválite a server vytvorí skutočnú **Google Task** (nie udalosť v Google Kalendári). Opakovaná požiadavka nevytvorí duplikát.

---

## Obsah

1. [Architektúra](#1-architektúra)
2. [Overenie kompatibility s ChatGPT](#2-overenie-kompatibility-s-chatgpt)
3. [Obmedzenia Google Tasks API](#3-obmedzenia-google-tasks-api)
4. [MCP nástroje](#4-mcp-nástroje)
5. [Nastavenie Google Cloud](#5-nastavenie-google-cloud)
6. [Konfigurácia a tajomstvá](#6-konfigurácia-a-tajomstvá)
7. [Nasadenie s HTTPS (Docker + Caddy)](#7-nasadenie-s-https-docker--caddy)
8. [Pripojenie k ChatGPT](#8-pripojenie-k-chatgpt)
9. [Pracovný postup: termíny zo školských e-mailov](#9-pracovný-postup-termíny-zo-školských-e-mailov)
10. [Odpojenie účtu a odvolanie prístupu](#10-odpojenie-účtu-a-odvolanie-prístupu)
11. [Vývoj a testy](#11-vývoj-a-testy)
12. [Bezpečnosť](#12-bezpečnosť)

---

## 1. Architektúra

```
ChatGPT (MCP klient)                 Tento server (HTTPS)                         Google
────────────────────                 ───────────────────────────────────          ─────────────────────
1. GET /mcp  ─────────────────────▶  401 + WWW-Authenticate (resource_metadata)
2. discovery ─────────────────────▶  /.well-known/oauth-protected-resource/mcp
                                     /.well-known/oauth-authorization-server
3. POST /oauth/register (DCR) ────▶  client_id (redirect URI len z allowlistu)
4. prehliadač: /oauth/authorize ──▶  stránka súhlasu + prístupová fráza vlastníka
                                     ──────── redirect (PKCE S256, state) ───────▶ súhlas Google
                                     /oauth/google/callback ◀──────── code ──────
                                     výmena kódu, kontrola účtu, šifrované uloženie
5. ◀── redirect s vlastným kódom (+state, iss)
6. POST /oauth/token (PKCE) ──────▶  vlastný access token (1 h) + refresh token (30 dní, rotácia)
7. POST /mcp (Bearer) ────────────▶  overenie tokenu ─▶ nástroj ─▶ Tasks API v1 ─▶ tasks.googleapis.com
```

* **Dve oddelené OAuth vrstvy.** Server je zároveň *OAuth 2.1 autorizačný server* pre MCP klienta a *OAuth klient* voči Googlu. ChatGPT dostane len tokeny tohto servera; **Google tokeny nikdy neopustia server** a model ich nevidí.
* **MCP transport:** Streamable HTTP na `/mcp` (oficiálne TypeScript SDK v2 – `@modelcontextprotocol/server`, `/express`, `/node`). Server odpovedá klientom protokolu 2025 (`initialize`) aj 2026-07-28 v bezstavovom režime.
* **Úložisko:** SQLite (`node:sqlite`, bez natívnych závislostí). Google refresh/access tokeny sú šifrované AES-256-GCM; vlastné tokeny sa ukladajú len ako SHA-256 hash.
* **Jeden používateľ:** prvé úspešné prihlásenie naviaže Google účet (`sub`). Iný Google účet je odmietnutý, kým vlastník účet neodpojí.
* **Rozsahy Google:** iba `openid` (stabilné ID účtu na naviazanie vlastníka) a `https://www.googleapis.com/auth/tasks`. Žiadny Gmail, Disk ani Kalendár.

Štruktúra kódu:

| Súbor | Účel |
|---|---|
| `src/index.ts` | spustenie servera |
| `src/app.ts` | Express aplikácia, hlavičky, rate limiting, `/mcp` |
| `src/oauth/server.ts` | autorizačný server: DCR, authorize, súhlas, Google callback, token, revoke, overenie tokenov |
| `src/google/*` | Google OAuth klient, správa šifrovaných tokenov, klient Tasks API |
| `src/tasks/*` | logika úloh: dátumy, naliehavosť, deduplikácia |
| `src/mcp/tools.ts` | definície MCP nástrojov a Zod validácia vstupov |
| `src/cli/disconnect.ts` | odpojenie účtu z príkazového riadku |

---

## 2. Overenie kompatibility s ChatGPT

> **Stav overenia (12. 10. 2026):** Stránky `developers.openai.com` a `help.openai.com` neboli z vývojového prostredia priamo dostupné (sieťová politika). Nižšie uvedené vychádza z výsledkov vyhľadávania, ktoré citujú tieto oficiálne stránky. **Pred použitím si to overte v aktuálnej dokumentácii a vo vlastnom účte.**

| Otázka | Zistenie | Zdroj |
|---|---|---|
| Podporuje ChatGPT vlastné MCP servery? | Áno, cez **Developer mode** („MCP apps“ / konektory). | [OpenAI Help: Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt) |
| Pre ktoré plány? | Plná podpora MCP **vrátane zápisových akcií** je v **beta pre ChatGPT Business, Enterprise a Edu** (vo workspace ju musí povoliť admin). Pre **Plus/Pro** sú zdroje rozporné: oznámenie OpenAI zo septembra 2025 uvádzalo Developer mode pre Plus a Pro, niektoré novšie návody uvádzajú pre Plus/Pro len čítanie. **Neoverené pre váš účet.** | Help článok vyššie; [OpenAI Developers na X](https://x.com/OpenAIDevs/status/1965807401745207708) |
| Transport | Vzdialený MCP server cez HTTPS (Streamable HTTP; tento server poskytuje `/mcp`). | dokumentácia Apps SDK |
| Autentifikácia | OAuth 2.1 s PKCE; registrácia klienta cez **CIMD, DCR** alebo vopred definovaného klienta; server musí publikovať *protected resource metadata* a rešpektovať parameter `resource`. Tento server implementuje **DCR**. | [Apps SDK – Authentication](https://developers.openai.com/apps-sdk/build/auth) |
| Zápisové akcie | Áno (v Developer mode). Nástroje bez `readOnlyHint: true` sa považujú za zápisové. | Help článok vyššie |
| Potvrdzovanie | ChatGPT si môže pri zápisových akciách vyžiadať potvrdenie podľa oprávnení, kontextu a dopadu; rizikové akcie môže zablokovať. Schválenie sa dá zapamätať len v rámci konverzácie. | Help článok vyššie |
| Redirect URI ChatGPT | `https://chatgpt.com/connector_platform_oauth_redirect` – **neoverené** v tomto prostredí. Ak registrácia zlyhá, log servera ukáže presnú odmietnutú URI (`DCR rejected`); po overení ju pridajte do `ALLOWED_REDIRECT_URIS`. | – |

Ak váš plán vlastné MCP servery so zápisom nepodporuje, server je aj tak štandardný MCP server a funguje s inými MCP klientmi s podporou OAuth (napr. MCP Inspector, Claude, VS Code). Architektúra sa kvôli tomu nemení.

---

## 3. Obmedzenia Google Tasks API

Overené v oficiálnom *discovery* dokumente Google Tasks API v1 (revízia 20261006):

* **Pole `due` uchováva iba dátum.** Časová časť sa pri zápise zahodí a čas sa nedá ani čítať, ani zapisovať. Google navyše uvádza, že `due` „nepredstavuje deadline“, ale deň, kedy sa úloha má urobiť / zobrazí v kalendári. Server preto prijíma len `YYYY-MM-DD`, posiela polnoc UTC a **nikdy nevymýšľa čas**. Ak e-mail uvádza čas (napr. „do 23:59“), patrí do poznámky.
* **Neexistuje pole priority.** „Naliehavosť“ sa preto len **vypočíta** pri čítaní (`urgency`): `urgent` = po termíne, dnes alebo zajtra (dátum bez času môže spadnúť do 24 hodín), inak `normal`. Do úlohy sa nič nezapisuje.
* Dĺžka: názov max. 1024 znakov, poznámky max. 8192 znakov (server povoľuje 7800 kvôli značke zdroja).
* Server **nikdy nenahrádza úlohy udalosťami v Google Kalendári** a o kalendár ani nežiada prístup.

---

## 4. MCP nástroje

| Nástroj | Typ | Popis |
|---|---|---|
| `list_task_lists` | čítanie | Zoznamy úloh so stabilnými ID a názvami (stránkovanie). |
| `list_tasks` | čítanie | Úlohy v zozname: názov, poznámky, `due_date`, stav, ID, `urgency`, `overdue`. Filtre `due_from`/`due_to`, `show_completed`, stránkovanie. |
| `find_duplicate_tasks` | čítanie | Hľadá ekvivalentné úlohy: 1. `source_id` (deterministicky), 2. presný normalizovaný názov + dátum, 3. presný názov, 4. podobný názov. |
| `create_task` | zápis | Vytvorí úlohu (`tasklist_id`, `title`, `notes?`, `due_date?`, `source_id?`). Najprv kontroluje duplikáty; výsledok `created`, `already_exists` alebo `duplicate_found`. |
| `update_task` | zápis | Zmení iba zadané polia (`title`, `notes`, `due_date`; `null` = vymazať). Ostatné zostávajú. |
| `complete_task` | zápis | Označí úlohu za dokončenú; vyžaduje presné ID. |
| `delete_task` | zápis, deštruktívny | Dvojkrokové mazanie: 1. volanie vráti úlohu a krátkodobý potvrdzovací token viazaný na úlohu (5 min), 2. volanie s tokenom zmaže – až po výslovnom súhlase používateľa. |

**Deduplikácia a idempotencia.** Ak úloha pochádza z e-mailu, ChatGPT pošle stabilné ID správy (Outlook/Exchange message ID alebo `internetMessageId`) ako `source_id`. Server uloží **len jeho hash** do idempotenčnej tabuľky a do poznámky pridá značku `[gtasks-mcp:src=<hash>]`. Opakovaná (aj súbežná) požiadavka s rovnakým `source_id` vráti existujúcu úlohu. Bez `source_id` sa zablokuje presná zhoda názvu a dátumu; podobné názvy sa len hlásia (`similar_existing_task_ids`).

---

## 5. Nastavenie Google Cloud

Potrebujete Google účet, do ktorého sa majú úlohy zapisovať. **E-mail sa nikam nezapisuje** – účet si vyberiete pri prihlásení.

1. Otvorte [Google Cloud Console](https://console.cloud.google.com/) → vytvorte projekt (napr. `gtasks-mcp`).
2. **APIs & Services → Library** → vyhľadajte **Google Tasks API** → **Enable**. (Iné API nepovoľujte.)
3. **Google Auth Platform → Branding** (resp. *OAuth consent screen*): typ používateľa **External**, názov aplikácie, váš kontaktný e-mail.
4. **Data Access / Scopes:** pridajte iba `openid` a `https://www.googleapis.com/auth/tasks`.
5. **Audience:** ponechajte stav **Testing** a pridajte svoj Google účet medzi **Test users**.
   *Pozor:* v stave *Testing* Google platnosť refresh tokenov obmedzuje (typicky 7 dní); potom treba konektor znova autorizovať. Pre dlhodobé používanie aplikáciu prepnite na **In production** – pri citlivom rozsahu `tasks` môže Google zobraziť upozornenie „neoverená aplikácia“, čo je pri osobnej aplikácii pre vlastný účet očakávané.
6. **Clients → Create client → Web application**:
   * **Authorized redirect URIs:** `https://VASA-DOMENA/oauth/google/callback` (presne, s HTTPS).
   * *Authorized JavaScript origins* netreba.
7. Client ID a Client secret si **stiahnite/skopírujte priamo do súboru `.env` na serveri**. Nikdy ich neposielajte do chatu ani necommitujte do Gitu.

---

## 6. Konfigurácia a tajomstvá

```bash
cp .env.example .env
chmod 600 .env
openssl rand -base64 32   # → TOKEN_ENCRYPTION_KEY
openssl rand -base64 24   # → OWNER_PASSPHRASE (uložte si ho do správcu hesiel)
```

| Premenná | Povinná | Popis |
|---|---|---|
| `PUBLIC_BASE_URL` | áno | Verejný HTTPS pôvod, napr. `https://tasks.example.com` (bez cesty). |
| `DOMAIN` | pre Compose | Doména pre Caddy (rovnaká ako v `PUBLIC_BASE_URL`). |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | áno | OAuth klient z kroku 5. |
| `TOKEN_ENCRYPTION_KEY` | áno | 32 náhodných bajtov v base64 (šifrovanie Google tokenov). Pri strate kľúča treba účet znova pripojiť. |
| `OWNER_PASSPHRASE` | áno | Min. 16 znakov. Vyžaduje sa na stránke súhlasu pri každom prepájaní – bez nej nikto iný nemôže pripojiť svoj klient. |
| `ALLOWED_REDIRECT_URIS` | nie | Povolené redirect URI pre DCR (čiarkou oddelené, presná zhoda). Predvolene ChatGPT. |
| `TIMEZONE` | nie | Pre výpočet „dnes“ a naliehavosti. Predvolene `Europe/Bratislava`. |
| `TRUST_PROXY_HOPS` | nie | Počet reverzných proxy pred aplikáciou (1 pre Caddy). Bez proxy nastavte `0`. |
| `LOG_LEVEL` | nie | `debug` / `info` / `warn` / `error`. |
| `DATABASE_PATH`, `PORT`, `HOST` | nie | Mimo Dockeru. |

V produkcii môžete namiesto `.env` použiť správcu tajomstiev (Docker secrets, systemd `LoadCredential`, cloudový secret manager) – aplikácia číta len premenné prostredia.

---

## 7. Nasadenie s HTTPS (Docker + Caddy)

Požiadavky: server/VPS s verejnou IP, doména s DNS záznamom `A`/`AAAA` na server, otvorené porty 80 a 443, Docker s Compose pluginom.

```bash
git clone <repo> gtasks-mcp && cd gtasks-mcp
cp .env.example .env && chmod 600 .env   # vyplňte hodnoty
docker compose up -d --build
docker compose logs -f app
curl https://VASA-DOMENA/.well-known/oauth-protected-resource/mcp
```

* **Caddy** automaticky získa a obnovuje certifikát Let's Encrypt a ako jediný počúva na 80/443. Aplikácia nemá zverejnený port.
* Kontajner aplikácie beží ako neprivilegovaný používateľ `node`, s read-only súborovým systémom, bez Linux capabilities a s `no-new-privileges`. Dáta sú vo zväzku `app-data` (`/data`, práva 700/600).
* Zálohujte zväzok `app-data` **a** `TOKEN_ENCRYPTION_KEY` oddelene.
* Ak používate iný reverzný proxy (nginx, Traefik, Cloudflare Tunnel), musí terminovať TLS, posielať `Host` verejnej domény a nastaviť `X-Forwarded-For`; `TRUST_PROXY_HOPS` nastavte na počet proxy. Nelogujte query stringy (obsahujú OAuth kódy).
* Bez Dockeru: `npm ci && npm run build && node --disable-warning=ExperimentalWarning dist/index.js` za HTTPS proxy (Node.js ≥ 22.13, odporúčané 24 LTS).

Aktualizácia: `git pull && docker compose up -d --build`.

---

## 8. Pripojenie k ChatGPT

*(Podľa aktuálnej verzie pomocníka OpenAI; názvy položiek v menu sa môžu líšiť.)*

1. Overte, že váš plán podporuje vlastné MCP aplikácie so zápisom (pozri [kap. 2](#2-overenie-kompatibility-s-chatgpt)). V Business/Edu/Enterprise musí admin povoliť Developer mode / vlastné konektory.
2. ChatGPT → **Settings → Apps & Connectors → Advanced settings → Developer mode** → zapnúť (potvrďte upozornenie o neoverených konektoroch).
3. **Settings → Apps & Connectors → Create** (vytvoriť aplikáciu/konektor):
   * Názov: napr. `Google Tasks`
   * MCP Server URL: `https://VASA-DOMENA/mcp`
   * Autentifikácia: **OAuth** (ChatGPT si klienta zaregistruje sám cez DCR – nevyplňujte client ID/secret)
4. Kliknite na pripojenie. Otvorí sa stránka tohto servera → zadajte **prístupovú frázu vlastníka** → **Povoliť** → prihláste sa do Google a vyberte **svoj osobný účet** → povoľte Google Tasks.
5. V novom chate zapnite konektor (ikona **+** / Developer mode) a vyskúšajte: *„Ukáž moje zoznamy úloh v Google Tasks.“*

Testovanie bez ChatGPT: [MCP Inspector](https://github.com/modelcontextprotocol/inspector) (`npx @modelcontextprotocol/inspector`) → Transport *Streamable HTTP* → URL `https://VASA-DOMENA/mcp` → OAuth. Redirect URI Inspectora je potrebné dočasne pridať do `ALLOWED_REDIRECT_URIS`.

**Riešenie problémov**

| Príznak | Príčina / riešenie |
|---|---|
| ChatGPT hlási chybu registrácie | V logu `DCR rejected` je skutočná redirect URI. Overte ju a pridajte do `ALLOWED_REDIRECT_URIS`. |
| `redirect_uri_mismatch` na Google | V Google Cloud musí byť presne `https://VASA-DOMENA/oauth/google/callback`. |
| `access_denied: This Google account is not authorized` | Prihlásili ste sa iným Google účtom než naviazaným. Odpojte účet ([kap. 10](#10-odpojenie-účtu-a-odvolanie-prístupu)) alebo vyberte správny. |
| Po ~7 dňoch prestane fungovať | OAuth aplikácia v Google je v stave *Testing*. Prepnite ju na *In production* a pripojte znova. |
| 403 „Invalid Host“ | `PUBLIC_BASE_URL` nezodpovedá doméne, cez ktorú prichádzajú požiadavky. |

---

## 9. Pracovný postup: termíny zo školských e-mailov

1. ChatGPT prečíta e-mail cez svoje existujúce pripojenie Outlooku (tento server k e-mailom **nemá prístup**).
2. ChatGPT vytiahne úlohu a termín a **navrhne** ich (názov, dátum, poznámka, zoznam úloh). Pri nejasnom termíne sa má opýtať.
3. Vy návrh schválite (ChatGPT môže navyše zobraziť vlastné potvrdenie zápisovej akcie).
4. ChatGPT zavolá `create_task` s `source_id` = ID e-mailu.
5. Server skontroluje duplikáty a vytvorí Google Task.
6. ChatGPT oznámi **skutočný** výsledok (`created` / `already_exists` / `duplicate_found`).

Server odovzdáva ChatGPT inštrukcie (MCP `instructions`), že obsah e-mailov a úloh sú **nedôveryhodné dáta**, nie pokyny; že nemá vytvárať úlohy z voliteľných udalostí, reklám a nerelevantných e-mailov; a že nesmie vymýšľať dátumy. Server sám obsah e-mailu nikdy neinterpretuje – iba ukladá názov/poznámku, ktoré prešli validáciou.

Príklad požiadavky v ChatGPT:

> Prejdi moje školské e-maily z tohto týždňa, nájdi povinné termíny a navrhni mi úlohy do zoznamu „Škola“. Nič nevytváraj, kým to neschválim.

Testovacie úlohy zo zadania (v automatických testoch sa vytvárajú **len v simulovanom Google**, nie vo vašom účte):

* „Všeobecná psychológia – zápis témy prezentácie“, termín 2026-10-12
* „UCM – žiadosť o status študenta so špecifickými potrebami“, termín 2026-10-20

---

## 10. Odpojenie účtu a odvolanie prístupu

```bash
docker compose exec app node --disable-warning=ExperimentalWarning dist/cli/disconnect.js
```

Príkaz odvolá Google grant (`oauth2.googleapis.com/revoke`), zmaže šifrované Google tokeny a **zneplatní všetky tokeny vydané pre MCP klientov**. ChatGPT potom dostane `401` a pri ďalšom použití vyžiada nové pripojenie (vrátane prístupovej frázy). Ďalší pripojený Google účet sa stane novým vlastníkom.

Ďalšie možnosti:

* Odobratie prístupu priamo v Google: [myaccount.google.com/connections](https://myaccount.google.com/connections). Server to zistí pri najbližšom obnovení tokenu (`invalid_grant`) a lokálne sa odpojí.
* Odstránenie konektora v ChatGPT (Settings → Apps & Connectors).
* Klient môže odvolať vlastné tokeny cez `POST /oauth/revoke` (RFC 7009).

---

## 11. Vývoj a testy

```bash
npm ci
npm run typecheck   # TypeScript kontrola (src + testy)
npm test            # Vitest – 54 testov, Google je simulovaný (žiadne reálne volania)
npm run build
npm audit
```

Testy pokrývajú akceptačné kritériá zo zadania:

| # | Kritérium | Test |
|---|---|---|
| 1 | OAuth prihlásenie | `tests/oauth.test.ts` – celý tok DCR → súhlas → Google (simulovaný) → token, PKCE, väzba na vlastníka |
| 2 | Zoznamy úloh | `tests/tasks.test.ts` – *acceptance 2* |
| 3 | Úloha s celodenným termínom | *acceptance 3* (obe príkladové úlohy, kontrola `due` poslaného do Google) |
| 4 | Žiadne duplikáty | *acceptance 4* (aj 3 súbežné požiadavky) |
| 5 | Úprava zachová ostatné polia | *acceptance 5* |
| 6 | Dokončenie | *acceptance 6* |
| 7 | Odmietnutie neautorizovaných požiadaviek | *acceptance 7* (bez tokenu, falošný, expirovaný token, cudzí `Host`) |
| 8 | Tokeny nie sú v odpovediach ani logoch | *acceptance 8* (všetky odpovede, logy aj audit log) |
| 9 | Odpojenie | *acceptance 9* (odvolanie v Google, zneplatnenie MCP tokenov, detekcia odvolania z Google) |
| 10 | Dokumentácia ChatGPT | táto README, [kap. 2](#2-overenie-kompatibility-s-chatgpt) a [kap. 8](#8-pripojenie-k-chatgpt) |

Manuálny end-to-end test s reálnym Google účtom (len s vaším súhlasom): po nasadení použite MCP Inspector alebo ChatGPT, vytvorte jednu testovaciu úlohu v samostatnom zozname a potom ju zmažte.

---

## 12. Bezpečnosť

Podrobný kontrolný zoznam: **[SECURITY.md](SECURITY.md)**.

Známe obmedzenia:

* Server nevie kryptograficky overiť, že *človek* schválil akciu – spolieha sa na potvrdenia v ChatGPT, inštrukcie pre model a dvojkrokové mazanie. Model, ktorý ignoruje inštrukcie, by mohol zavolať oba kroky mazania za sebou; preto `delete_task` nesie `destructiveHint: true`, aby ho hostiteľ potvrdzoval.
* Dynamická registrácia klientov je otvorená (vyžaduje ju ChatGPT), ale obmedzená allowlistom redirect URI, limitom počtu klientov a rate limitom. Bez prístupovej frázy vlastníka klient nezíska žiadny token.
* Zámok proti súbežným duplikátom je v pamäti procesu – spúšťajte **jednu** inštanciu.
* `node:sqlite` je v Node.js 22/24 označený ako experimentálny (stabilita „release candidate“).

<div align="center">

# 🎯 DAST Benchmark Lab

### A Deliberately Vulnerable + Deliberately Secure Test Range for Measuring DAST Scanner Accuracy

**TP / FP / FN / TN scoring lab for OWASP ZAP • Burp Suite • Nuclei • Acunetix • Nessus**

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4.x-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top_10_covered-FF0000?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/Top10/)
[![Endpoints](https://img.shields.io/badge/endpoints-383-blue?style=for-the-badge)](./ground-truth.json)
[![Verified](https://img.shields.io/badge/verified_vulns-194%2F194-success?style=for-the-badge)](./evaluation/verification.json)
[![Decoys](https://img.shields.io/badge/decoys-104%2F104_clean-lightgrey?style=for-the-badge)](./evaluation/verification.json)

[🚀 Quickstart](#-quickstart-2-minutes) •
[🛰️ Why DAST-Specific?](#️-why-purpose-built-for-dast) •
[🎚️ Difficulty Levels](#️-difficulty-levels) •
[📖 What Is This For?](./docs/NE-ISE-YARAR.md) •
[🔧 Setup Guide](./docs/KURULUM.md) •
[📊 Scanning & Scoring](./docs/TARAMA-VE-OLCUM.md) •
[❓ FAQ](./docs/SSS.md)

> 📝 Detailed guides under [`docs/`](./docs/) are currently in Turkish. The commands and code samples work regardless of language.

</div>

---

## 📌 What is this? (in 30 seconds)

> **Problem:** You run a DAST scanner. It reports 50 findings. How many are real? How many are false alarms? How many critical vulnerabilities did it **miss**? Normally, you can't know.
>
> **Solution:** This server gives you a target whose **answers are known in advance**:
> - 🔴 **194 vulnerable endpoints** → the scanner should find them (found = **TP**, missed = **FN**)
> - 🟢 **73 secure endpoints** → the scanner should stay silent (alert = **FP**, silent = **TN**)
> - 🟡 **116 FP-trap endpoints** (12 classic + **104-trap hell**) → pages that look suspicious but are clean (WAF text, sample keys, slow report...). They measure the scanner's **false-positive discipline**.

`ground-truth.json` is the referee. Compare the scanner report with `evaluation/evaluate.py` → get **Precision / Recall / F1 + per-category breakdown**.

```mermaid
flowchart LR
    A[🔴 194 Vulnerable\nTP expected] --> S[🎯 Mock Server\n:3000]
    B[🟢 73 Secure\nTN expected] --> S
    C[🟡 116 FP-Traps\nTN expected] --> S
    S --> D[ZAP / Nuclei / Burp\nscan]
    D --> E[evaluate.py\nreport vs ground-truth]
    E --> F[📊 TP FP FN TN\nPrecision Recall F1]
```

Concept deep-dive (Turkish) → **[📖 docs/NE-ISE-YARAR.md](./docs/NE-ISE-YARAR.md)**

---

## ✨ Highlights

| | |
|---|---|
| 🎯 **383 endpoints, one target** | Everything in v1 **plus Extreme Range V2**: deep-SPA + Shadow DOM, cross-role stored/blind XSS, multi-tenant IDOR/BOLA, GraphQL nested authz + federation, OAuth/OIDC flows, workflow bypass, deterministic race, async second-order, calibrated blind timing, staged OOB, parser differentials, shared-cache auth, soft-404/rate-limit confusion, WebSocket/SSE/gRPC-Web |
| ✅ **194/194 proof-verified + 104/104 decoys clean** | `python evaluation/verify.py` fires a real payload at every vulnerability and independently confirms every decoy is clean. Shown on the dashboard. |
| 🙈 **Blind Mode** | `DAST_MODE=blind` hides headers, answers, hints and GT APIs — fair-measurement mode (see `docs/BLIND-MODE.md`). Transparent stays default for learning. |
| 🟡 **116-trap FP hell** | Classic 12 + 104 generated decoys (fake SQL errors, neutralized reflections, fake secrets, WAF-like pages...) each with machine-checked negative proofs. |
| 📊 **Persistent score tracking** | `scan.py start/finish` → every run stored as JSON under `evaluation/runs/`. Duration, request count, speed, coverage, CPU/RAM, 5xx, OOB, **ΔF1 vs previous run**. |
| 🔍 **FN analysis** | Every request lands in `logs/requests.log` with a signal tag (`sqli_probe`, `xss_probe`...). Distinguish "tried but missed" from "never tried". |
| 🛡️ **Safe to scan** | CMDi / SSRF / XXE / Deserialization / RFI / Zip Slip **never really execute** — pattern-match mocks. `ping` / `cat /etc/passwd` outputs are fake text. |
| 🧭 **Live dashboard** | `http://localhost:3000/dashboard` → 383-endpoint list with try-it links + score table + OOB triggers. |

---

## 🛰️ Why purpose-built for DAST?

> This project is not for SAST (code-reading) tools — it is built for scanners that **send HTTP requests to a live target and interpret responses**. Every design decision measures one DAST capability:

| DAST capability | What this project provides |
|---|---|
| 🕷️ **Crawling / discovery** | `/dashboard` links all 383 endpoints • `robots.txt` lists sensitive paths • JS-rendered SPA (`/app`) — separates classic spiders from AJAX spiders |
| 🎯 **Active fuzzing + oracle reading** | Deterministic flaw markers: error-based `SQL syntax`, boolean content diff, a **real 3-second** time-based delay (`/runtime/sqli-time`), header reflections (`Location`, `X-Injected`), `MOCK-SSRF-LEAK` markers |
| 🙈 **Blind/OOB detection** | `/oob/*` callback collector + `GET /api/oob-hits` counter — separates scanners that catch blind XSS / blind SSRF from those that don't |
| 🔐 **Authenticated scanning** | Bearer JWT (`/app/*`), cookies (`role`, `sessionid`), header-spoof scenarios (`X-User-Id`, `X-Role`, `X-Debug`) — an unauthenticated scan misses this whole surface (provable via FN analysis) |
| 🧠 **Judgement / FP resistance** | Every flaw has a **secure twin** (`/injection/sqli` → `/injection/sqli-secure`) + **12 FP traps** — text-matching rules fall into FP here |
| 📡 **Matching-friendly** | Every response carries `X-Vuln-Id`, `X-Vuln-Category`, `X-Ground-Truth` headers • `evaluate.py` matches trailing-slash and `:id`-placeholder insensitively |
| 📊 **Behavior profiling** | Signal-tagged request log answers "did it try and miss, or never try?" |
| 🛡️ **Safe fuzz target** | Dangerous vectors are mocks (no real command/request execution) — open the scanner to full throttle |

**In short:** SAST reads code, DAST talks to a target — this server is a conversation partner with 383 topics.

---

## 🎚️ Difficulty levels

> `severity` in `ground-truth.json` is **criticality, not difficulty**. The table below shows which **capability** a DAST scanner (or pentester) needs per level. Full list + scan profiles → **[🎚️ docs/ZORLUK-SEVIYELERI.md](./docs/ZORLUK-SEVIYELERI.md)**

| Level | Requires | Example endpoints | Scanner profile that catches it |
|---|---|---|---|
| 🟢 **Level 1 — Easy** `baseline catches it` | Passive scan + one simple payload | `/xss/reflected`, `/injection/sqli` (error-based), `/files/.env`, `/misconfig/headers`, `/robots.txt`, `/ssrf/redirect` | ZAP baseline, Nuclei default templates |
| 🟡 **Level 2 — Medium** `active scan + fuzz` | Active scan, wordlists, rule sets | Stored/DOM XSS, UNION/stacked SQLi, 4 SSTI engines, IDOR/traversal, JWT `alg:none`, lock-free OTP, GraphQL introspection, CORS `*`, SVG upload | ZAP full-scan, Burp Active Scan |
| 🟠 **Level 3 — Hard** `auth + logic + multi-step` | Logged-in scan, chaining, business-logic reasoning | Mass-assignment → admin escalation **chain** (`/app/api/profile` → `/app/api/feedback-view`), BOLA, coupon stacking/negative wallet, JWT `kid`/`jku`/RS→HS confusion, SSRF bypass set (decimal-IP, `@`, fragment), OAuth `redirect_uri`, second-order SQLi | Authenticated scan + API/GraphQL add-ons + manual support |
| 🔴 **Level 4 — Chaos / Master** `blind + timing + SPA + race` | Timing measurement, OOB listening, JS-render crawling, race windows | **Real 3-sec** time-based SQLi, blind XSS (`/runtime/feedback` → `/oob/*`), `/app` SPA AJAX crawl, single-coupon race (`/shop/coupon-race`), GraphQL depth DoS, cache poisoning | Tuned full-scan + AJAX spider + OOB handler |
| 🟣 **Level FP-Hunter** `judgement, not signal` | Discipline of NOT alerting | 116 FP traps (12 classic + 104 hell: `/fp/search`, `/fp/sdk-example`, `/fp/slow-report`...) + 47 `secure` twins | Mature policy — naive rule sets fall into FP here |

```
Expected F1 curve:  high at Level 1  →  drops toward Level 4  →  FP-Hunter reveals FPR
Reading: "Recall 90% at Level 1 but 20% at Level 3 means the gap is coverage (auth/crawl), not detection."
```

---

## ⚡ Quickstart (2 minutes)

> Full step-by-step guide (Node/Python versions, Docker, port changes, troubleshooting — in Turkish) → **[🔧 docs/KURULUM.md](./docs/KURULUM.md)**

**Requirements:** Node.js 18+ • Python 3.10+ • (optional) Docker

```powershell
# 1) Install dependencies
npm install

# 2) Start the server
npm start
# [+] DAST mock server: http://localhost:3000/dashboard
```

```powershell
# 3) New terminal — is everything working? (expect 194/194 + 104/104)
python evaluation/verify.py
# === VERIFIED: 194/194 exploitable ===
# === DECOY: 104/104 clean ===
```

🎉 Open **`http://localhost:3000/dashboard`** — you'll see all endpoints with "try it" links.

Quick test payloads:

```
XSS:     /xss/reflected?name=<script>alert(1)</script>
SQLi:    /injection/sqli?id=1' OR '1'='1
IDOR:    /access/idor?user_id=99
BOLA:    /api/users/99  (returns TCKN+IBAN)
GraphQL: POST /graphql {"query":"{ __schema { queryType { name } } }"}
SSRF:    /ssrf?url=http://169.254.169.254/latest/meta-data/
JWT:     /auth/jwt-none?token=<alg:none token>
OTP:     POST /authx/otp {"code":"0000"}  (no lockout, spray away)
```

---

## 📊 Score your scanner (recommended flow)

```powershell
# 0) Self-verification (once)
python evaluation/verify.py

# 1) Start the run (marks the time window)
python evaluation/scan.py start --scanner "ZAP 2.14"

# 2) Run the scanner (example: ZAP baseline + resource monitor IN PARALLEL)
pip install psutil
python evaluation/agent.py --process java   # separate terminal, for ZAP
docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:3000 -J zap-report.json

# 3) Finish + measure + save
python evaluation/scan.py finish --findings zap-report.json --format zap --exit-code 0 --errors 0 --note "first ZAP run"

# 4) See history
python evaluation/scan.py list
# or dashboard: http://localhost:3000/dashboard  |  GET /api/scans
```

One-shot quick look (no record saved):

```powershell
python evaluation/evaluate.py --findings zap-report.json --format zap
python evaluation/evaluate.py --findings nuclei.jsonl --format nuclei
```

Supported report formats: `generic` • `zap` • `zap-xml` • `sarif` • `nuclei`

Full guide (ZAP full-scan, Nuclei, Burp, FN analysis, OOB, APIs — in Turkish) → **[📊 docs/TARAMA-VE-OLCUM.md](./docs/TARAMA-VE-OLCUM.md)**

### Sample score output (real run: `evaluation/ornek-bulgular.json`, 4 findings)

```
=== OVERALL (383 endpoints, 4 findings) ===
TP=2  FP=2  FN=192  TN=187
Precision=0.500  Recall=0.010  F1=0.020  FPR=0.011
Match strength: strong(vuln_id)=0 weak(path)=4

=== BY DIFFICULTY ===
Difficulty   TP  FP  FN  TN  Prec   Rec    F1
chaos         0   0  25   0   0.00  0.00  0.00
easy          2   0  63   0   1.00  0.03  0.06
fp-hunter     0   2   0 187  0.00  0.00  0.00
hard          0   0 100   0   0.00  0.00  0.00
```

---

## 🧮 Scoring logic

| Endpoint type | Expectation | Scanner alerts | Scanner stays silent |
|---|---|---|---|
| 🔴 `vulnerable` (real flaw) | Should alert | **TP** ✅ | **FN** ❌ (missed) |
| 🟢 `secure` (secure control) | Should stay silent | **FP** ❌ (false alarm) | **TN** ✅ |
| 🟡 `fp-trap` (FP trap) | Should stay silent | **FP** ❌ | **TN** ✅ |

Every response carries these headers (don't affect the DAST, help with matching):

```
X-Vuln-Id: INJ-SQLI-01
X-Vuln-Category: A03-Injection
X-Ground-Truth: vulnerable | secure | fp-trap
```

Concepts + example scenarios (Turkish) → **[📖 docs/NE-ISE-YARAR.md](./docs/NE-ISE-YARAR.md)**

---

## 🗂️ Category map

<details>
<summary><b>Distribution of the 383 endpoints — click to expand</b></summary>

| Category | Vulnerable | Secure | FP-Trap | Examples |
|---|---|---|---|---|
| A03-Injection | 28 | 8 | – | UNION / stacked / async second-order / time-based (calibrated) / boolean, NoSQLi, CMDi (mock), 4 SSTI engines, parser differentials, log4shell (mock) |
| A07-Auth | 27 | 10 | – | JWT alg:none / kid / jku / weak-secret / RS→HS confusion / jwk, lock-free OTP, MFA bypass, OAuth/OIDC flows + PKCE, enumeration, magic-hash, soft-404 + fake rate-limit confusion |
| APP-Shop (Juice Shop-level) | 23 | 4 | – | JWT login, mass-assignment escalation chain, address/order IDOR, coupon stacking, negative wallet, unlimited refund, CAPTCHA-bypass stored XSS, sequential recovery codes |
| A01-AccessControl | 16 | 9 | – | IDOR, multi-tenant BOLA, traversal, forced browsing, open redirect (+bypasses), CSRF, HPP, verb confusion, X-Original-URL / XFF bypass |
| Client-Side | 13 | 8 | – | postMessage XSS, Shadow-DOM XSS, wizard-skip, JSONP, markdown XSS, DOM clobbering, prototype pollution, `javascript:` redirect, WS/SSE vulns |
| A03-XSS | 13 | 6 | – | Reflected / stored / DOM / blind / cross-role / staged-OOB + mXSS + log-poisoning viewer |
| A05-Exposure | 11 | – | – | .env, .bak, .DS_Store, source-map, swagger, actuator, robots.txt, phpinfo, package/composer.json |
| API-Security | 9 | 5 | – | BOLA (TCKN/IBAN), mass-assignment, excessive data, OTP rate-limit, API key in URL, pagination abuse, sequential invite, BFLA |
| A04-FileHandling | 9 | 3 | – | SVG XSS, Zip Slip (mock), LFI/RFI (mock), CSV formula, double-extension upload, wrapper/unicode traversal |
| A05-Misconfig | 8 | 3 | – | Missing headers, verbose errors, dir-listing, default creds, CORS `*`, clickjacking, TRACE, crossdomain.xml |
| A05-CacheSmuggle | 8 | 4 | – | Host poisoning, shared-cache auth leak, cache deception (PII), method-override, CL.TE oracle, cache-poisoning search |
| A04-BusinessLogic | 8 | 5 | – | Client-side pricing, negative quantity, coupon race, deterministic burst race, workflow skip/replay, sequential order IDs |
| API-GraphQL | 7 | 4 | – | Introspection, nested field authz, federation passthrough, batch brute-force, depth DoS, GraphQL IDOR, gRPC-Web errors |
| A10-SSRF | 6 | 2 | – | Mock SSRF + decimal-IP / 0.0.0.0 / `@` / fragment / redirect-chain bypasses |
| A02-Crypto | 5 | 1 | – | PAN exposure, debug env leak, .git exposure, MD5, reset-token Referer leak |
| A04-InsecureDesign | 2 | 1 | – | Unrestricted upload, coupon reuse |
| A08-Integrity | 1 | – | – | Deserialization (mock) |
| FP-Trap (incl. 104 hell) | – | – | 116 | Help text, SAMPLE keys, WAF pages, nonce+CSP, correct locks, fake errors/secrets/timing, single-use coupons, legit slow reports... |
| **TOTAL** | **194** | **73** | **116** | **383** |

</details>

> ⚠️ **Safety note:** CMDi / SSRF / XXE / Deserialization / RFI / Zip Slip **never really execute** — pattern-match simulations. `ping`, `cat /etc/passwd`, metadata outputs are mock text. Safe to scan.

---

## 🖥️ Dashboard & APIs

| Address | What you get |
|---|---|
| `GET /dashboard` | Human panel: endpoint list + score table |
| `GET /app` | Juice Shop-level SPA (JS-rendered, scanner scoreboard at `/app/coverage`) |
| `GET /api/overview` | Badge data: GT counts + verified vulns + recorded scans |
| `GET /api/scans` | Last 30 runs (duration, speed, coverage, TP/FP/FN/TN, CPU/RAM, ΔF1) |
| `GET /api/stats` | Log summary: request count + signal distribution |
| `GET /api/oob-hits` | Blind-callback triggers |
| `GET /api/ground-truth` | Live `ground-truth.json` (404 in blind mode) |
| `POST /api/admin/reset` | Reset state + reseed (loopback only; `X-Admin-Token` if `DAST_ADMIN_TOKEN` set) |

> 🙈 In blind mode (`DAST_MODE=blind`) answers are hidden: no GT headers, neutral dashboard, closed GT/coverage APIs. See [`docs/BLIND-MODE.md`](./docs/BLIND-MODE.md).

---

## 📁 Project structure

```
server.js                  → Express entry, router mounting, dashboard, APIs (blind-aware, reset endpoint)
ground-truth.json          → the referee (383 rows: 194 vuln + 73 secure + 116 fp-trap, with difficulty/oracle/execution)
lib/
  utils.js                 → escHtml, fake DB, payload heuristics
  requestLogger.js         → every request to logs/requests.log with signal tags (blind-safe)
  mode.js                  → DAST_MODE gate (transparent/blind)
  seeded.js                → seeded PRNG for reproducible scenarios
  stateReset.js            → reset-handler registry (20 handlers)
routes/                    → v1 categories (injection, xss, access, auth, authx, api,
                             graphql, client, files, shop, cache, crypto, misconfig,
                             ssrf, logic, runtime, chaos, edge, shopapp, oob, fptraps)
                           + V2: spa2, xss2, tenant, gql2, oidc, flow, race2, async2,
                             blindtime, oob2, parser, cache2, confuse, realtime (WS/SSE/gRPC-Web),
                             fphell (104 decoys via manifest)
evaluation/
  verify.py                → self-verification: proof per vuln (194/194) + decoy negatives (104/104) + verification.json
  evaluate.py              → TP/FP/FN/TN + precision/recall/F1, vuln-level (strong/weak) matching, by category/difficulty
  report.py                → JSON + Markdown reports (class × difficulty × execution splits)
  scan.py                  → start/finish/list with --mode/--reset/--seed: persistent records
  agent.py                 → scanner-machine CPU/RAM monitor (psutil)
  migrate_gt.py / extend_gt_p1.py / extend_gt_p2.py / add_execution.py → GT evolution scripts (auditable)
  ground-truth.v1.json     → pre-V2 backup (222 rows)
  runs/                    → scan records (JSON, append-only)
  reports/                 → generated JSON + Markdown reports
  ornek-bulgular.json      → sample generic-finding format
logs/
  requests.log             → every request (JSON-lines + signal tags)
  oob.log                  → blind-callback triggers
  scans.jsonl              → scan-start markers
tests/
  acceptance.py            → fast acceptance suite (schema + parity + live spot checks, both modes)
docs/
  KURULUM.md (TR)          → detailed setup guide
  NE-ISE-YARAR.md (TR)     → concept + TP/FP/FN/TN + audience
  TARAMA-VE-OLCUM.md (TR)  → ZAP/Nuclei/Burp + scan.py + FN analysis + OOB
  SSS.md (TR)              → FAQ + troubleshooting
  ZORLUK-SEVIYELERI.md (TR) → DAST-specific design + difficulty levels
  BLIND-MODE.md (EN)       → fair-measurement mode + leak surface
  ORACLES.md (EN)          → GT v2 schema + proof registry + matching
  RESET.md (EN)            → deterministic resets + seeds + scope limits
  AUTH-PACK.md (EN)        → vendor-neutral credentials for identical conditions
```

---

## 📚 Documentation

| Document | Content |
|---|---|
| [🔧 docs/KURULUM.md](./docs/KURULUM.md) *(TR)* | Node/Python/Docker setup, first run, port changes, `verify.py`, common errors |
| [📖 docs/NE-ISE-YARAR.md](./docs/NE-ISE-YARAR.md) *(TR)* | Which problem it solves, TP/FP/FN/TN, ground-truth & FP-trap concepts, audience |
| [🎚️ docs/ZORLUK-SEVIYELERI.md](./docs/ZORLUK-SEVIYELERI.md) *(TR)* | DAST-specific design, 5 difficulty levels, severity-vs-difficulty, scanner profiles |
| [🙈 docs/BLIND-MODE.md](./docs/BLIND-MODE.md) | Fair-measurement mode + hidden leak surface |
| [🔮 docs/ORACLES.md](./docs/ORACLES.md) | GT v2 schema + proof registry + vuln-level matching |
| [🔄 docs/RESET.md](./docs/RESET.md) | Deterministic resets + seeds + scope limits |
| [🔐 docs/AUTH-PACK.md](./docs/AUTH-PACK.md) | Vendor-neutral credentials for identical conditions (ZAP/Burp/Nuclei/Limma/Invicti) |
| [📊 docs/TARAMA-VE-OLCUM.md](./docs/TARAMA-VE-OLCUM.md) *(TR)* | Scanning with ZAP / Nuclei / Burp, `scan.py` flow, `agent.py`, FN analysis, OOB, APIs |
| [❓ docs/SSS.md](./docs/SSS.md) *(TR)* | 15+ Q&A + troubleshooting table |

---

## 🤝 Contributing

1. Fork → feature branch → make your change
2. Run `python evaluation/verify.py` to confirm 194/194 + 104/104 stay green (or `npm test` for the fast suite)
3. New endpoint? Add its `ground-truth.json` row (with `difficulty` + `oracle` + `execution`) + `verify.py` proof together
4. Open a PR (Turkish or English, both fine)

---

## 📄 License

See [LICENSE](./LICENSE). Educational and testing purposes only. Contains deliberately vulnerable code — **never run in production or exposed to the internet.** Use at your own risk.

<div align="center">

**⭐ If it helped, leave a star — happy scanning! 🎯**

</div>

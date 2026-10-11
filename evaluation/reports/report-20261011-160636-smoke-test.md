# DAST Benchmark Report — smoke-test

- **Mode:** unauthenticated | **Target:** http://localhost:3000 | **Generated:** 2026-10-11T16:06:36.029168+00:00

## Summary

| TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|
| 2 | 2 | 192 | 187 | 0.5 | 0.0103 | 0.0202 | 0.0106 |

Match strength: **strong(vuln_id)=0** weak(path)=4

Coverage: **338/383 (88.3%)**

## By difficulty

| Difficulty | TP | FP | FN | TN | Prec | Rec | F1 |
|---|---|---|---|---|---|---|---|
| chaos | 0 | 0 | 25 | 0 | 0 | 0.0 | 0 |
| easy | 2 | 0 | 63 | 0 | 1.0 | 0.0308 | 0.0597 |
| fp-hunter | 0 | 2 | 0 | 187 | 0.0 | 0 | 0 |
| hard | 0 | 0 | 100 | 0 | 0 | 0.0 | 0 |
| medium | 0 | 0 | 4 | 0 | 0 | 0.0 | 0 |

## By execution (simulated vs live)

| Execution | TP | FN | FP |
|---|---|---|---|
| live | 1 | 131 | 0 |
| n/a | 0 | 0 | 2 |
| simulated | 1 | 61 | 0 |

> **simulated** = mock assertion (no backend action); **live** = server really performed it (sleep, crypto, lock, cache, echo, state).

## Missed (FN)

- [INJ-AUTH-BYPASS-01] `POST /injection/login` (Auth Bypass via SQLi) — easy/simulated
- [INJ-NOSQLI-01] `GET /injection/nosqli` (NoSQL Injection) — easy/simulated
- [INJ-CMDI-01] `GET /injection/cmdi` (OS Command Injection (mock)) — easy/simulated
- [INJ-SSTI-01] `GET /injection/ssti` (SSTI (mock)) — hard/simulated
- [INJ-LDAP-01] `GET /injection/ldap` (LDAP Injection) — hard/simulated
- [INJ-XPATH-01] `GET /injection/xpath` (XPath Injection) — hard/simulated
- [INJ-XXE-01] `POST /injection/xxe` (XXE) — hard/simulated
- [INJ-CRLF-01] `GET /injection/crlf` (CRLF/Header Injection) — easy/live
- [XSS-STORED-01] `GET /xss/stored` (Stored XSS) — hard/live
- [XSS-DOM-01] `GET /xss/dom` (DOM XSS (innerHTML sink)) — hard/live
- [AC-IDOR-01] `GET /access/idor` (IDOR) — easy/live
- [AC-TRAV-01] `GET /access/traversal` (Path Traversal) — easy/simulated
- [AC-FORCED-01] `GET /access/admin` (Forced Browsing) — easy/live
- [REDIR-01] `GET /ssrf/redirect` (Open Redirect) — easy/live
- [CSRF-01] `GET /csrf/transfer` (CSRF (GET state-change)) — easy/live
- [AUTH-JWT-01] `GET /auth/jwt-none` (JWT alg:none) — easy/live
- [AUTH-RESET-01] `GET /auth/reset` (Predictable reset token) — easy/live
- [AUTH-BRUTE-01] `POST /auth/bruteforce` (No rate limiting) — easy/live
- [AUTH-SESS-01] `GET /auth/session-fixation` (Session Fixation) — easy/live
- [CRYPTO-PAN-01] `GET /crypto/creditcard` (Cleartext PAN) — easy/simulated
- [CRYPTO-DEBUG-01] `GET /crypto/debug` (Debug env leak) — easy/simulated
- [CRYPTO-GIT-01] `GET /crypto/.git/config` (Exposed .git) — easy/simulated
- [CRYPTO-HASH-01] `GET /crypto/hash` (Weak hash MD5) — easy/simulated
- [MIS-HDR-01] `GET /misconfig/headers` (Missing security headers) — easy/live
- [MIS-ERR-01] `GET /misconfig/error` (Verbose error) — easy/live
- [MIS-DIR-01] `GET /misconfig/dir-listing/` (Directory listing + .env) — easy/simulated
- [MIS-DEFAULT-01] `GET /misconfig/default-creds` (Default credentials surface) — easy/simulated
- [CORS-01] `GET /cors/cors` (CORS * + credentials) — easy/live
- [CLICK-01] `GET /logic/clickjack` (Clickjacking (no XFO)) — easy/live
- [SSRF-01] `GET /ssrf` (SSRF (mock)) — easy/simulated
- [UPL-01] `POST /logic/upload` (Unrestricted upload) — hard/live
- [BIZ-01] `GET /logic/coupon` (Business logic (coupon reuse)) — easy/live
- [DESER-01] `POST /logic/deserialize` (Insecure Deserialization (mock)) — hard/simulated
- [API-BOLA-01] `GET /api/users/:id` (BOLA: başkasının kaydı tam PII (TCKN/IBAN)) — easy/simulated
- [API-MASS-01] `POST /api/users` (Mass Assignment: role client'tan) — hard/live
- [API-EXCESS-01] `GET /api/account` (Excessive Data: TCKN+IBAN+PAN (KVKK)) — easy/simulated
- [API-RATE-01] `POST /api/otp-verify` (OTP rate-limit yok (sınırsız deneme)) — hard/live
- [API-KEY-01] `GET /api/balance` (API key URL query'de (loglara düşer)) — easy/live
- [API-PAGE-01] `GET /api/orders` (Pagination abuse (?limit=100000 dökülür)) — easy/live
- [API-INVITE-01] `GET /api/invite` (Tahmin edilebilir davet token (sıralı)) — easy/simulated
- [GQL-INTROS-01] `POST /graphql` (Introspection açık (şema+passwordHash sızar)) — easy/simulated
- [GQL-BATCH-01] `POST /graphql/batch` (Batch brute-force (50 login/tek istek)) — hard/simulated
- [GQL-DEPTH-01] `POST /graphql/depth` (Depth-limit yok (DoS, 2.4M kayıt)) — chaos/live
- [GQL-IDOR-01] `POST /graphql/user` (GraphQL IDOR (auth'suz user(id:99))) — hard/simulated
- [AUTHX-OTP-01] `POST /authx/otp` (4 haneli SMS kodu, kilit yok) — hard/live
- [AUTHX-MFA-01] `POST /authx/mfa` (MFA bypass (boş kod / mfa=skip)) — hard/live
- [AUTHX-OAUTH-01] `GET /authx/oauth` (OAuth redirect_uri doğrulanmıyor (kod hırsızlığı)) — hard/live
- [AUTHX-RESET-POISON-01] `GET /authx/forgot` (Reset link Host zehirlenmesi) — hard/live
- [AUTHX-ENUM-01] `POST /authx/login-enum` (Kullanıcı enumeration (404 vs 401)) — hard/live
- [AUTHX-KID-01] `GET /authx/jwt-kid` (JWT kid path traversal (mock key load)) — hard/live
- [AUTHX-JKU-01] `GET /authx/jwt-jku` (JWT jku allowlist dışı JWK güveni) — hard/live
- [AUTHX-WEAK-01] `GET /authx/jwt-weak` (JWT zayıf secret (secret/password)) — hard/live
- [CL-PM-01] `GET /client/chat` (postMessage XSS (origin yok + innerHTML)) — easy/live
- [CL-JSONP-01] `GET /client/jsonp` (JSONP callback XSS) — easy/live
- [CL-MD-01] `GET /client/notes` (Markdown stored XSS (filtresiz HTML)) — hard/live
- [CL-CLOBBER-01] `GET /client/clobber` (DOM Clobbering (window.config)) — hard/live
- [CL-PPOLL-01] `POST /client/pollute` (Prototype Pollution (mock merge)) — hard/live
- [CL-GOTO-01] `GET /client/goto` (javascript:/data: redirect) — easy/live
- [EXP-ENV-01] `GET /files/.env` (Exposed .env (DB+AWS+Stripe mock)) — easy/simulated
- [EXP-BAK-01] `GET /files/backup.bak` (Backup dump (.bak/.sql.bak)) — easy/simulated
- [EXP-DS-01] `GET /files/.DS_Store` (.DS_Store dosya listesi sızar) — easy/simulated
- [EXP-MAP-01] `GET /files/app.js.map` (Source-map secret sızıntısı) — easy/simulated
- [EXP-SWAG-01] `GET /files/swagger.json` (Internal swagger ifşası) — easy/simulated
- [EXP-ACT-01] `GET /files/actuator` (Actuator env ifşası (Spring)) — easy/simulated
- [EXP-ROBOTS-01] `GET /files/robots.txt` (robots.txt hassas yol listesi) — easy/simulated
- [FILE-SVG-01] `POST /files/svg` (SVG upload XSS (image/svg+xml yürütülür)) — hard/simulated
- [FILE-ZIP-01] `POST /files/unzip` (Zip Slip (../../evil.sh mock)) — hard/simulated
- [FILE-LFI-01] `GET /files/view` (LFI (template= + php://filter mock)) — hard/simulated
- [FILE-RFI-01] `GET /files/page` (RFI (remote include mock, fetch yok)) — hard/simulated
- [FILE-CSV-01] `GET /files/export.csv` (CSV formula injection (=cmd|...)) — easy/live
- [SHOP-PRICE-01] `POST /shop/cart` (Fiyat client'tan (price tampering)) — easy/live
- [SHOP-QTY-01] `POST /shop/cart-qty` (Negatif adet (bedava/iade mock)) — easy/live
- [SHOP-RACE-01] `POST /shop/coupon-race` (Tek kupon sınırsız (race, kilit yok)) — chaos/live
- [SHOP-ORDER-01] `GET /shop/order/:id` (Sıralı sipariş ID enumeration) — easy/live
- [CACHE-HOST-01] `GET /cache/reset-link` (Host zehirlenmesi (X-Forwarded-Host reset link)) — hard/live
- [CACHE-DECEPT-01] `GET /cache/account/:id` (Cache deception: PII public cache (TCKN/IBAN)) — hard/live
- [HTTP-METHOD-01] `POST /http/method` (Method override ile yetkisiz DELETE) — hard/live
- [HTTP-SMUG-01] `POST /http/smuggle` (CL.TE smuggle oracle (mock, desync yok)) — chaos/live
- [RT-TIME-01] `GET /runtime/sqli-time` (Time-based SQLi (gerçek 3sn gecikme)) — chaos/live
- [RT-BOOL-01] `GET /runtime/sqli-bool` (Boolean-based SQLi (içerik farkı)) — easy/live
- [RT-HDRSQLI-01] `GET /runtime/search-ua` (Header-based SQLi (User-Agent)) — easy/live
- [RT-ORDERBY-01] `GET /runtime/list` (ORDER BY enjeksiyonu) — hard/live
- [RT-HPP-01] `GET /runtime/hpp` (HTTP Parameter Pollution (sonuncu kazanır)) — easy/live
- [RT-MAGIC-01] `POST /runtime/login-magic` (Magic hash loose-compare bypass) — easy/live
- [RT-CACHEPOISON-01] `GET /runtime/search` (Cache poisoning (yansımalı + public cache)) — chaos/live
- [RT-MAILHDR-01] `POST /runtime/contact` (E-posta header enjeksiyonu (Bcc)) — hard/simulated
- [RT-LOGPOISON-01] `GET /runtime/log-viewer` (Log poisoning stored XSS (escape yok)) — chaos/simulated
- [RT-RESETLEAK-01] `GET /runtime/reset-page` (Reset token URL'de + 3rd-party (Referer sızıntısı)) — easy/live
- [RT-SIDURL-01] `GET /runtime/session-url` (Oturum ID'si URL'de) — easy/live
- [RT-COOKIE-01] `GET /runtime/cookie-set` (Cookie bayraksız (HttpOnly/Secure yok)) — easy/live
- [RT-BFLA-01] `POST /runtime/admin-export` (BFLA: normal kullanıcı admin export çalıştırır) — hard/live
- [RT-HEADBOLA-01] `GET /runtime/profile-mine` (Header-spoof BOLA (X-User-Id'e güven)) — hard/live
- [RT-JWK-01] `GET /runtime/jwt-jwk` (JWT gömülü jwk'ya güven (saldırgan anahtarı)) — hard/live
- [RT-NOEXP-ISSUE] `GET /runtime/jwt-issue-long` (Süresiz JWT üretimi (exp yok)) — hard/live
- [RT-NOEXP-01] `GET /runtime/jwt-verify` (JWT expiration yok sayılıyor) — hard/live
- [RT-LOG4J-01] `POST /runtime/log` (Log4Shell kalıbı (mock lookup, outbound yok)) — hard/simulated
- [RT-BLINDXSS-01] `POST /runtime/feedback` (Blind XSS giriş (callback depolanır)) — chaos/live
- [RT-BLINDXSS-02] `GET /runtime/feedback-view` (Blind XSS tetik (admin view script src)) — chaos/simulated
- [RT-PHPINFO-01] `GET /runtime/phpinfo` (phpinfo ifşası) — easy/simulated
- [RT-PKG-01] `GET /runtime/package.json` (package.json sürüm ifşası) — easy/simulated
- [RT-COMPOSER-01] `GET /runtime/composer.json` (composer.json sürüm ifşası) — easy/simulated
- [RT-REDIRBYPASS-01] `GET /runtime/go` (Open redirect bypass (//, backslash, js:)) — hard/live
- [RT-UPLDBL-01] `POST /runtime/upload-img` (Çift uzantı + MIME spoof (shell.php.jpg)) — hard/live
- [RT-CTX-ATTR-01] `GET /runtime/attr` (Attribute-context XSS (src çıkışı)) — hard/live
- [RT-CTX-JS-01] `GET /runtime/jsvar` (JS-string-context XSS) — hard/live
- [APP-AUTH-01] `POST /app/api/login` (Login soft-throttle var, kilit yok (kaba kuvvet)) — chaos/live
- [APP-MASS-01] `PUT /app/api/profile` (Mass-assignment role escalation (ZİNCİR)) — chaos/live
- [APP-ADDR-01] `GET /app/api/address/:id` (Adres IDOR (auth var, sahiplik yok)) — hard/live
- [APP-TRACK-01] `GET /app/api/track/:id` (Sipariş takip enumeration (9001, 9002...)) — easy/live
- [APP-BASKET-01] `POST /app/api/basket` (Para birimi karışıklığı (USD=TRY)) — hard/live
- [APP-CSRF-01] `GET /app/api/basket/add` (GET ile sepet değişir (CSRF-able)) — hard/live
- [APP-COUPON-01] `POST /app/api/checkout` (Kupon istifleme (sınırsız, hepsi uygulanır)) — chaos/live
- [APP-WALLET-01] `POST /app/api/wallet/topup` (Negatif yükleme bakiyeyi artırır) — hard/live
- [APP-REFUND-01] `POST /app/api/refund` (Aynı sipariş sınırsız iade) — hard/live
- [APP-RESET-01] `POST /app/api/reset` (Güvenlik sorusu cevap profilde (admin dahil)) — chaos/live
- [APP-BFLA-01] `GET /app/api/internal/config` (BFLA: internal config (rol kontrolsüz)) — hard/live
- [APP-DEBUG-01] `GET /app/api/debug` (Debug kapısı (X-Debug header)) — hard/live
- [APP-AVATAR-01] `GET /app/api/avatar` (Auth-gated SSRF (avatar proxy)) — hard/simulated
- [APP-ENUM-01] `GET /app/api/users` (Kullanıcı listesi (auth var, yetki yok)) — hard/live
- [APP-FEED-01] `POST /app/api/feedback` (Stored XSS (captcha anahtarı bundle'da)) — chaos/live
- [APP-FEEDVIEW-01] `GET /app/api/feedback-view` (Stored XSS tetik (escalation zinciri gerekir)) — chaos/live
- [APP-TOKEN-01] `GET /app/share` (JWT URL'de (sepet paylaşım linki)) — hard/live
- [APP-RECOVERY-01] `GET /app/api/recovery` (Sıralı kurtarma kodları (REC-1001...)) — hard/live
- [CH-UNION-01] `GET /injection/union` (UNION-based SQLi (sütun sayacı oracle)) — hard/simulated
- [CH-STACK-01] `GET /injection/stacked` (Stacked queries (; ikinci sorgu)) — hard/simulated
- [CH-2ND-01] `POST /runtime/register2` (Second-order SQLi giriş (ham saklanır)) — chaos/live
- [CH-2ND-02] `GET /runtime/admin-list` (Second-order SQLi tetik (admin liste)) — chaos/simulated
- [CH-SSTI-JINJA] `GET /ssti/jinja` (SSTI Jinja2 {{7*7}}) — hard/simulated
- [CH-SSTI-TWIG] `GET /ssti/twig` (SSTI Twig {{7*7}}) — hard/simulated
- [CH-SSTI-FMT] `GET /ssti/freemarker` (SSTI Freemarker ${7*7}) — hard/simulated
- [CH-SSTI-ERB] `GET /ssti/erb` (SSTI ERB <%= 7*7 %>) — hard/simulated
- [CH-LEGACY-01] `GET /legacy/:page` (Legacy 404 path yansıması) — easy/simulated
- [CH-ROLE-01] `GET /runtime/role-cookie` (İmzasız rol çerezi (base64 bit-flip)) — hard/live
- [CH-HTACCESS-01] `POST /runtime/upload-htaccess` (.htaccess overwrite upload) — hard/live
- [CH-VERB-01] `GET /runtime/verb-gate` (Verb confusion (GET ile silme)) — hard/live
- [EDGE-SSRF-DEC] `GET /edge/dec` (SSRF desimal IP bypass (2130706433)) — hard/simulated
- [EDGE-SSRF-ZERO] `GET /edge/zero` (SSRF 0.0.0.0 bypass) — hard/simulated
- [EDGE-SSRF-AT] `GET /edge/at` (SSRF credential confusion (user@host)) — hard/simulated
- [EDGE-SSRF-FRAG] `GET /edge/frag` (SSRF fragment hilesi) — hard/simulated
- [EDGE-SSRF-REDIR] `GET /edge/redir` (SSRF redirect-zinciri takibi) — hard/simulated
- [EDGE-RET-01] `GET /edge/login-return` (Login returnUrl açık yönlendirme) — hard/live
- [EDGE-DOUBLE-01] `GET /edge/go2` (HPP redirect (son next kazanır)) — hard/live
- [EDGE-ORIG-01] `GET /edge/panel` (X-Original-URL admin bypass) — hard/live
- [EDGE-LOCAL-01] `GET /edge/internal` (Localhost kapısı XFF bypass) — hard/live
- [EDGE-TRACE-01] `TRACE /edge/trace` (TRACE açık, çerez yankılanır (XST)) — easy/live
- [EDGE-XDOM-01] `GET /crossdomain.xml` (Permissive crossdomain.xml) — easy/simulated
- [EDGE-CFG-01] `GET /static/config.js` (Build artifact anahtar ifşası) — easy/simulated
- [CACHE-XFF-01] `GET /cache/echo` (XFF yansıması + public cache) — hard/live
- [AX-CONFUSE-01] `GET /authx/jwt-confuse` (JWT RS256->HS256 confusion (gerçek RSA)) — chaos/live
- [AX-REUSE-01] `GET /authx/reset-reuse` (Reset token süresiz + tekrar kullanımlı) — hard/live
- [AX-NOSTATE-01] `GET /authx/oauth-nostate` (OAuth state parametresiz (connect-CSRF)) — hard/live
- [AX-REMEMBER-01] `GET /authx/remember` (Remember-me 10 yıl + HttpOnlysiz) — easy/live
- [FILE-WRAP-01] `GET /files/include` (LFI wrapperlar (php://filter, data://...)) — hard/simulated
- [FILE-UNI-01] `GET /files/download` (Unicode/overlong traversal + ADS) — hard/simulated
- [APP-EMAIL-01] `POST /app/api/email` (E-posta doğrulamasız değişir (gasp)) — hard/live
- [APP-GIFT-01] `POST /app/api/giftcard` (Hediye çeki keyfi tutarla basılır) — hard/live
- [APP-POINTS-01] `POST /app/api/points` (Negatif puan transferi) — hard/live
- [APP-SHIP-01] `POST /app/api/shipping` (Kargo ağırlığı client'tan (0=bedava)) — easy/live
- [APP-REG-01] `POST /app/api/register-check` (Kayıt oracle kullanıcı enumeration) — easy/live
- [XSS-MXSS-01] `GET /xss/mxss` (mXSS (innerHTML round-trip mutasyonu)) — hard/simulated
- [CL-PPOLLQ-01] `GET /client/pollute-q` (Query-string proto pollution) — hard/live
- [SPA2-SHADOW-01] `GET /spa2/widget` (Shadow-DOM XSS (config JSON sink)) — hard/live
- [SPA2-WIZARD-01] `GET /spa2/wizard` (Multi-step wizard skip (unsigned progress)) — hard/live
- [XSS2-STORED-ROLE-01] `POST /xss2/post` (Cross-role stored XSS entry (user writes)) — hard/live
- [XSS2-STORED-ROLE-02] `GET /xss2/view` (Cross-role stored XSS trigger (admin reads raw)) — hard/live
- [XSS2-BLIND-ROLE-01] `POST /xss2/blindreply` (Blind mod-queue entry (callback stored)) — chaos/live
- [XSS2-BLIND-ROLE-02] `GET /xss2/modqueue` (Blind mod-queue trigger (script src)) — chaos/simulated
- [TENANT-IDOR-01] `GET /tenant/docs` (Cross-tenant document read (no ownership)) — hard/live
- [TENANT-BOLA-01] `POST /tenant/transfer` (Cross-tenant write without authz) — hard/live
- [GQL2-NESTED-01] `POST /gql2/graphql` (Nested field authz leak (supplierCost)) — hard/live
- [GQL2-FED-01] `POST /gql2/federation` (Unsigned federation entity passthrough (SSN)) — hard/simulated
- [OIDC-REDIR-01] `GET /oidc/authorize` (OAuth redirect_uri not validated (code theft)) — hard/live
- [OIDC-NOSTATE-01] `GET /oidc/authorize-nostate` (Stateless flow (connect-CSRF)) — hard/live
- [OIDC-PKCE-01] `POST /oidc/token` (Public client without PKCE accepted) — hard/live
- [FLOW-ORDER-01] `POST /flow/orders` (Order creation (chain start)) — medium/live
- [FLOW-SKIP-01] `POST /flow/ship` (Ship without payment (step skip)) — chaos/live
- [FLOW-REPLAY-01] `POST /flow/pay` (Double charge replay (no idempotency)) — hard/live
- [RACE2-BURST-01] `POST /race2/claim` (Non-atomic burst claim (over-claim)) — chaos/live
- [ASYNC2-ENTRY-01] `POST /async2/submit` (Async second-order entry (queued raw)) — hard/live
- [ASYNC2-TRIGGER-01] `POST /async2/flush` (Async worker trigger (string concat)) — chaos/live
- [BLINDTIME-01] `GET /blindtime/lookup` (Calibrated blind timing (SLEEP oracle)) — chaos/live
- [OOB2-STAGED-01] `POST /oob2/register` (Staged OOB entry (callback accepted)) — chaos/live
- [PARSER-SEMI-01] `GET /parser/semicolon` (Semicolon separator first-wins (smuggling)) — hard/live
- [PARSER-CTYPE-01] `POST /parser/ctype` (Content-type fallback parser escalation) — hard/live
- [PARSER-METHOD-01] `GET /parser/resource` (Query _method DELETE (verb confusion)) — medium/live
- [CACHE2-SHARED-01] `GET /cache2/profile` (Shared cache ignores identity (PII cross-user)) — chaos/live
- [CACHE2-POISON-01] `GET /cache2/search` (Cached reflection serves XSS to others) — hard/live
- [CONFUSE-ENUM-01] `GET /confuse/user/:name` (Soft-404 user enumeration oracle) — hard/live
- [CONFUSE-RATELIMIT-01] `GET /confuse/ratelimit` (Announced but unenforced limit) — medium/live
- [REALTIME-WS-01] `GET /realtime/ws` (WebSocket no origin check (hijackable echo)) — hard/live
- [REALTIME-SSE-01] `GET /realtime/sse` (SSE raw reflection) — hard/live
- [REALTIME-GRPC-01] `POST /realtime/grpc` (gRPC-Web verbose error (stack+internals)) — medium/live

## False alarms (FP)

- [XSS-REFL-01-SECURE] `GET /xss/reflected-secure` (Reflected XSS secure control)
- [FP-SEARCH-01] `GET /fp/search` (FP trap: 'SQL syntax' help text)

## By category

| Category | TP | FP | FN | TN | F1 |
|---|---|---|---|---|---|
| A01-AccessControl | 0 | 0 | 16 | 9 | 0 |
| A02-Crypto | 0 | 0 | 5 | 1 | 0 |
| A03-Injection | 1 | 0 | 27 | 8 | 0.069 |
| A03-XSS | 1 | 1 | 12 | 5 | 0.1333 |
| A04-BusinessLogic | 0 | 0 | 8 | 5 | 0 |
| A04-FileHandling | 0 | 0 | 9 | 3 | 0 |
| A04-InsecureDesign | 0 | 0 | 2 | 1 | 0 |
| A05-CacheSmuggle | 0 | 0 | 8 | 4 | 0 |
| A05-Exposure | 0 | 0 | 11 | 0 | 0 |
| A05-Misconfig | 0 | 0 | 8 | 3 | 0 |
| A07-Auth | 0 | 0 | 27 | 10 | 0 |
| A08-Integrity | 0 | 0 | 1 | 0 | 0 |
| A10-SSRF | 0 | 0 | 6 | 2 | 0 |
| API-GraphQL | 0 | 0 | 7 | 4 | 0 |
| API-Security | 0 | 0 | 9 | 5 | 0 |
| APP-Shop | 0 | 0 | 23 | 4 | 0 |
| Client-Side | 0 | 0 | 13 | 8 | 0 |
| FP-Trap | 0 | 1 | 0 | 115 | 0 |

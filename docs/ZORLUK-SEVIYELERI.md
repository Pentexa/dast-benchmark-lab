# 🎚️ Zorluk Seviyeleri + DAST'a Özel Tasarım

> Bu proje **DAST tarayıcıları için** tasarlandı: SAST gibi kod okumaz, **çalışan hedefe istek atıp yanıtı yorumlayan** araçları ölçer. Bu dosya "hangi seviye ne ister, hangi tarayıcı profili yakalar?" sorusunu cevaplar.

---

## 1. Neden DAST'a özel? (tasarım kararları)

| DAST yeteneği | Projedeki karşılığı | Nerede görülür? |
|---|---|---|
| 🕷️ Crawl / keşif | 222 endpoint dashboard'da linkli • `robots.txt` hassas yol listeler • JS-render SPA | `/dashboard`, `/files/robots.txt`, `/app` |
| 🎯 Aktif fuzz + oracle | Deterministik işaretler: `SQL syntax`, boolean içerik farkı, **gerçek 3 sn delay**, `Location` yankısı | `/injection/sqli`, `/runtime/sqli-bool`, `/runtime/sqli-time`, `/runtime/go` |
| 🙈 Kör (blind/OOB) | Callback toplayıcı + sayaç | `/oob/*`, `/runtime/feedback`, `GET /api/oob-hits` |
| 🔐 Authenticated tarama | Bearer JWT, cookie (`role`/`sessionid`), header-spoof (`X-User-Id`, `X-Role`, `X-Debug`) | `/app/*`, `/api/users-secure/*`, `/runtime/profile-mine` |
| 🧠 FP direnci | Güvenli ikiz + 12 tuzak (şüpheli görünüp temiz) | `/injection/sqli-secure`, `/fp/*` |
| 📡 Eşleştirme dostu | Her yanıtta `X-Vuln-Id` / `X-Vuln-Category` / `X-Ground-Truth` | Tüm yanıt header'ları |
| 📊 Davranış profili | Sinyal etiketli istek logu → "denedi mi / denemedi mi?" | `logs/requests.log`, `GET /api/stats` |
| 🛡️ Güvenli fuzz | Tehlikeli vektörler mock (gerçek komut/istek yok) | CMDi, SSRF, XXE, Deser, RFI, Zip Slip |

SAST "kodu okur", DAST "hedefle konuşur" — bu sunucu 222 konulu konuşmaya hazır bir muhataptır.

---

## 2. Severity ≠ Difficulty (önemli!)

`ground-truth.json`'daki `severity` **kritikliktir** (açık patlarsa ne olur?), zorluk değildir:

| Severity | Adet | Dağılım | Not |
|---|---|---|---|
| critical | 4 | hepsi `vulnerable` | Auth bypass, BOLA, MFA bypass... — kritik ama bazıları kolay bulunur |
| high | 72 | hepsi `vulnerable` | En kalabalık zafiyet grubu |
| medium | 68 | hepsi `vulnerable` | İkinci kalabalık grup |
| low | 19 | hepsi `vulnerable` | Düşük etki ama bazıları zor (örn. remember-me, TRACE) |
| info | 59 | 47 `secure` + 12 `fp-trap` | Skorlanabilir temiz yüzey (TN beklenir) |

> Örnek: `critical` bir IDOR (`/api/users/99`) Seviye 1 kolaylıkta yakalanabilirken, `low` bir cache-poisoning Seviye 4 ustalığı isteyebilir. **Kritiklik ≠ yakalama zorluğu.**

Aşağıdaki 5 seviye, kritiklikten bağımsız **DAST yeteneği** katmanıdır.

---

## 3. Beş zorluk seviyesi

### 🟢 Seviye 1 — Kolay (baseline yakalar)

**İstediği yetenek:** Pasif tarama + tek basit payload. Giriş, zincir, zamanlama gerekmez.

| Örnek | Neden kolay? |
|---|---|
| `GET /xss/reflected?name=<script>alert(1)</script>` | Yansıma birebir, encode yok |
| `GET /injection/sqli?id=1' OR '1'='1` | Verbose `SQL syntax` hatası |
| `GET /files/.env`, `/files/robots.txt`, `/.git/config` | Dosya olduğu gibi açık |
| `GET /misconfig/headers` | Header yokluğu pasifte görünür |
| `GET /ssrf/redirect?next=https://evil.com` | 302 `Location` yankısı |
| `GET /access/admin` (forced browsing) | 200 + "Admin Panel" metni |

**Yakalayan profil:** ZAP baseline, Nuclei default şablonlar.
**Kaçırıyorsa:** Kural seti kapalı veya hedefe erişim yok demektir — dedektörden önce bağlantıyı kontrol et.

---

### 🟡 Seviye 2 — Orta (aktif tarama + fuzz)

**İstediği yetenek:** Aktif scan açık, kelime listesi / kural seti yüklü, parametre fuzz yapılıyor.

| Örnek | Neden orta? |
|---|---|
| Stored / DOM XSS (`/xss/stored`, `/xss/dom`) | İki istek gerekir (yaz → oku), sink analizi ister |
| UNION / stacked SQLi (`/injection/union`, `/injection/stacked`) | Sütun sayma / ikinci sorgu mantığı ister |
| 4 SSTI motoru (`/ssti/jinja`, `/twig`, `/freemarker`, `/erb`) | Motor-başına payload (`{{7*7}}` vs `${7*7}`) ister |
| IDOR / traversal (`/access/idor?user_id=99`, `?file=../../secrets.txt`) | Parametre manipülasyonu + yanıt karşılaştırma ister |
| JWT `alg:none` (`/auth/jwt-none`) | El yapımı token üretimi ister |
| Kilitsiz OTP (`/authx/otp`, `/api/otp-verify`) | Çoklu deneme (rate-limit yokluğu) ister |
| GraphQL introspection (`POST /graphql`) | `__schema` sorgusunu bilmek ister |
| SVG upload XSS (`POST /files/svg`) | `Content-Type` + dosya-yükleme akışı ister |

**Yakalayan profil:** ZAP full-scan, Burp Active Scan (tüm insertion point'ler açık).
**Kaçırıyorsa:** Policy'de ilgili kural kapalıdır veya fuzz derinliği (tek path'e istek sayısı) yetersizdir → `scan.py` çıktısındaki `max_hits_single_path` ve `sinyal çeşitliliği`ne bak.

---

### 🟠 Seviye 3 — Zor (auth + mantık + çok adım)

**İstediği yetenek:** Girişli tarama (context/user), iş-mantığını anlama, **zincir kurma**.

| Örnek | Neden zor? |
|---|---|
| Mass-assignment escalation **zinciri** (`PUT /app/api/profile {"role":"admin"}` → `admin_token` → `/app/api/feedback-view`) | Tek istekle bulunamaz; çıktıyı sonraki isteğe taşımak gerekir |
| BOLA / header-spoof (`/api/users/99`, `/runtime/profile-mine` + `X-User-Id: 99`) | Kimlik bağlamı + sahiplik muhakemesi ister |
| Kupon istifleme / negatif cüzdan / sınırsız iade (`/app/api/checkout`, `/app/api/wallet/topup`, `/app/api/refund`) | Business-logic: "normal" isteğin anormal sonucu ister |
| JWT `kid` / `jku` / RS→HS confusion (`/authx/jwt-kid`, `/jwt-confuse`) | Kriptografik manipülasyon ister (gerçek RSA ile HMAC) |
| SSRF bypass seti (`/edge/dec`, `/edge/zero`, `/edge/at`, `/edge/frag`, `/edge/redir`) | Filtre-atlatma payload çeşitliliği ister |
| OAuth `redirect_uri` + `state`sizlik (`/authx/oauth`, `/oauth-nostate`) | Akış (flow) takibi ister |
| Second-order SQLi (`POST /runtime/register2` → `GET /runtime/admin-list`) | Giriş ayrı, tetik ayrı istekte |

**Yakalayan profil:** Authenticated scan (login context tanımlı) + API/GraphQL eklentileri + manuel destek.
**Kaçırıyorsa:** Büyük ihtimal **crawl/auth eksik**, dedektör değil → `logs/requests.log`'da ilgili path'e hiç istek yoksa (`coverage_by_category hit=0`) önce girişi düzelt.

---

### 🔴 Seviye 4 — Kaos / Usta (kör + zaman + SPA + yarış)

**İstediği yetenek:** Zaman ölçümü, OOB dinleme, JS-render crawl, yarış-penceresi (race) yakalama.

| Örnek | Neden usta? |
|---|---|
| Time-based SQLi (`/runtime/sqli-time?id=1 AND SLEEP(3)`) | **Gerçek 3 sn** uyur; eşiği düşük tarayıcı kaçırır. Meşru yavaş sayfa (`/fp/slow-report`) ile karışır! |
| Blind XSS (`POST /runtime/feedback` → `/runtime/feedback-view` → `/oob/*`) | Callback'in OOB kanalında dinlenmesi gerekir |
| `/app` SPA kapsaması | Klasik spider yetmez; **AJAX spider** + JS çalıştırma gerekir |
| Tek kupon race (`POST /shop/coupon-race` × N) | Paralel istek + sayaç yarışı gerekir |
| GraphQL depth DoS (`POST /graphql/depth`) | Derin iç-içe sorgu üretimi gerekir |
| Cache-poisoning (`/runtime/search?q=<script>`) | Yansıma + `public cache` header birlikteliği gerekir |

**Yakalayan profil:** İnce ayarlı full-scan (timeout eşiği >3 sn) + AJAX spider + OOB handler.
**Kaçırıyorsa:** Normaldir — bu seviye "hangi tarayıcı daha derine iniyor?" ayrımını yapar. `discovery_curve_sec` (keşif eğrisi) ve `oob_callbacks_in_window`'a bak.

---

### 🟣 Seviye FP-Avcısı (sinyal değil muhakeme)

**İstediği yetenek:** Alarm üretMEme disiplini. 12 tuzak + 47 secure ikiz.

| Tuzak | Masum gerçek | Acemi kural ne yapar? |
|---|---|---|
| `/fp/search` | Yardım metninde "SQL syntax" | "SQLi!" der |
| `/fp/sdk-example` | `sk_test_ÖRNEK` doküman anahtarı | "Secret leak!" der |
| `/fp/waf-block` | Statik WAF bilgi sayfası | "WAF bypass!" der |
| `/fp/csp-inline` | nonce+CSP'li güvenli script | "Inline script!" der |
| `/fp/api-docs` | Şemada geçip dönmeyen `passwordHash` | "Excessive data!" der |
| `/fp/coupon-once`, `/fp/login-lock` | Doğru tek-kullanım (410) / doğru kilit (429) | "Kupon reuse / brute-force koruması yok!" der |
| `/fp/slow-report` | Meşru yavaş rapor (~3 sn) | "Time-based SQLi!" der |

**Ölçü:** `FPR = FP / (FP + TN)` — düşük FPR'lı tarayıcı olgundur.
**Tavsiye:** Koşu sonrası `fp_list`'i grupla, öten plugin ID'lerini policy'den düşür, tekrar koştur, `dF1`'in arttığını izle.

---

## 4. Seviyeleri pratikte kullanma

```
1) Önce Seviye 1'de recall'a bak → düşükse bağlantı/kural sorunu var, derine inme.
2) Seviye 2-3 farkı auth'u ele verir → /app ve /api coverage'ı 0 ise authenticated scan kur.
3) Seviye 4 + OOB, araçların "derinlik" farkını gösterir → ZAP vs Nuclei karşılaştırmasında belirleyicidir.
4) FP-Avcısı her koşuda FPR'yi verir → recall artarken FPR patlıyorsa kazanç sahte demektir.
```

Kategori-bazlı skor (`evaluate.py` çıktısındaki tablo) seviyelerle çapraz okunabilir: örn. `A03-Injection` F1'i yüksek ama `APP-Shop` 0 ise tarayıcın enjeksiyonda iyi, zincir/auth'ta kör demektir.

---

**Sonraki adım:** ilk taramanı ölçmek için [📊 TARAMA-VE-OLCUM.md](./TARAMA-VE-OLCUM.md), takıldığın yerde [❓ SSS.md](./SSS.md).

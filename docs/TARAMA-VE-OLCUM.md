# 📊 Tarama ve Ölçüm Rehberi

> Tarayıcıyı çalıştır → raporu ground-truth ile karşılaştır → skoru kalıcı kaydet → araçları karşılaştır.

---

## 1. Tavsiye edilen akış (her şey kayıt altında)

Tek seferlik skor yerine **her koşuyu kaydet**: süre, istek, hız, coverage, CPU/RAM, TP/FP/FN/TN ve önceki koşuyla fark (ΔF1).

```powershell
# 0) Öz-doğrulama (bir kez — 194/194 + 104/104 beklenir)
python evaluation/verify.py --seed 7

# 1) Taramayı başlat (durumu sıfırlar + tohumlar + işaret koyar)
python evaluation/scan.py start --scanner "ZAP 2.17" --mode authenticated-full --reset --seed 7

# 2) Tarayıcıyı çalıştır (aşağıdan birini seç) +
#    AYNI ANDA kaynak ölçer (ayrı terminal — opsiyonel ama önerilir)
pip install psutil
python evaluation/agent.py --process java   # ZAP için; nuclei→ --process nuclei

# 3) Bitir + ölç + kaydet
python evaluation/scan.py finish --findings zap-rapor.json --format zap --exit-code 0 --errors 0 --note "ilk ZAP koşusu"

# 4) Geçmişi listele / dashboard'dan izle
python evaluation/scan.py list
# http://localhost:8800/dashboard  |  GET /api/scans
```

Kaydedilen dosya: `evaluation/runs/run-<tarih>-<tarayıcı>.json` — **silinmez**, araç karşılaştırması buradan yapılır.
Modlar: `unauthenticated` (kimliksiz) • `authenticated-full` (girişli tam) • `advanced-protocol` (WS/SSE/gRPC-Web + OOB + AJAX spider).
Aynı koşul için kimlik paketi: [AUTH-PACK.md](./AUTH-PACK.md) (EN). Adil ölçüm için blind mod: [BLIND-MODE.md](./BLIND-MODE.md) (EN).

`finish` çıktısında göreceğin satırlar:

```
süre: 812 sn | istek: 45210 (188 unique path) | hız: 55.6/sn | paralellik: ~8
coverage: 340/383 endpoint (%88.8) | OOB tetik: 3
bulgu: 41 | TP=35 FP=2 FN=159 TN=187 | P=0.946 R=0.180 F1=0.303
önceki (...) vs delta: dTP=+4 dFP=-1 dFN=-4 dF1=+0.042
kayıt: evaluation/runs/run-20261011-120000-ZAP-2.14.json
```

Rapor üretimi (JSON + Markdown, sınıf×zorluk×simüle/gerçek kırılımlı):

```powershell
# kayıtlı koşudan:
python evaluation/report.py --run evaluation/runs/run-20261011-111053-ZAP-2.17.json
# doğrudan bulgudan (mod belirterek):
python evaluation/report.py --findings zap.json --format zap --scanner "ZAP 2.17" --mode authenticated-full
# çıktı: evaluation/reports/<ad>.json + <ad>.md
```

---

## 2. Araçlara göre tarama komutları

### OWASP ZAP — baseline (hızlı)

```powershell
docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:8800 -J zap-rapor.json
python evaluation/evaluate.py --findings zap-rapor.json --format zap
```

### OWASP ZAP — full scan (derin, yavaş)

```powershell
docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t http://localhost:8800 -J zap-full.json
python evaluation/scan.py finish --findings zap-full.json --format zap --note "full scan"
```

> ZAP raporu alırken **Report → Generate Report → JSON Report** (alert'li olan) seç. `site: null` gelen rapor yanlış tiptir — `evaluate.py` seni uyarır.

### Nuclei

```powershell
nuclei -u http://localhost:8800 -jsonl -o nuclei.jsonl
python evaluation/evaluate.py --findings nuclei.jsonl --format nuclei
```

### Burp Suite (manuel)

1. Burp'ta Spider + Active Scan'i `http://localhost:8800` hedefine koştur
2. Issue'ları dışa aktar (XML veya SARIF)
3. Dönüştür:

```powershell
python evaluation/evaluate.py --findings burp.xml --format zap-xml
python evaluation/evaluate.py --findings burp.sarif --format sarif
```

### Generic format (kendi betiğin — v2: `vuln_id` ile güçlü eşleşme)

```json
[
  {"url": "http://localhost:8800/xss/reflected?name=<script>alert(1)</script>", "name": "Reflected XSS"},
  {"url": "http://localhost:8800/injection/sqli?id=1", "name": "SQL Injection", "vuln_id": "INJ-SQLI-01", "evidence": "SQL syntax ..."}
]
```

`vuln_id` verirsen satır doğrudan eşleşir (**strong**); vermezsen path-fallback (**weak**) — raporda ikisi ayrı yazılır. Eski format dosyalar çalışmaya devam eder.

```powershell
python evaluation/evaluate.py --findings bulgular.json --format generic
```

Örnek dosya: `evaluation/ornek-bulgular.json`

---

## 3. Skor nasıl hesaplanır? (evaluate.py)

1. Her bulgunun URL'si normalize edilir (`norm_path`)
2. `vuln_id` varsa GT satırıyla **doğrudan** eşleşir (strong); yoksa path ile (`:` placeholder ve trailing-slash duyarsız, weak)
3. Eşleşen zafiyetli satır → **TP**, eşleşmeyen zafiyetli → **FN**
4. Eşleşen güvenli/FP-tuzak → **FP**, eşleşmeyen → **TN**
5. Genel + **kategori + zorluk + simüle/gerçek kırılımlı** Precision/Recall/F1 hesaplanır, FN ve FP listesi dökülür

```
--- Kaçanlar (FN: bulamadıkları) ---
  [FN] INJ-SQLI-01 GET /injection/sqli (SQL Injection (error-based))
--- Yanlış alarmlar (FP) ---
  [FP] FP-SEARCH-01 GET /fp/search (FP trap: 'SQL syntax' help text)
```

`compute_metrics()` fonksiyonu import edilip kendi betiğine gömülebilir.

---

## 4. FN analizi — "denedi mi, denemedi mi?" 🔍

Her istek `logs/requests.log` dosyasına **sinyal etiketiyle** yazılır:

```
xss_probe, sqli_probe, traversal_probe, cmdi_probe, ssti_probe, ssrf_probe, xxee_probe,
graphql_probe, massassign_probe, apikey_probe, pagination_probe, jwt_probe, jsonp_probe,
proto_pollution_probe, csv_formula_probe, exposure_probe, otp_mfa_probe, oauth_probe,
smuggle_probe, method_override_probe, host_header_probe
```

```powershell
Get-Content logs/requests.log | Select-Object -Last 5
```

Yorumlama:

| Durum | Anlamı | Aksiyon |
|---|---|---|
| `sqli_probe` var + bulgu yok | **Gerçek FN** — araç denedi, yakalayamadı | Dedektör zayıf, kural/policy güncelle |
| `sqli_probe` yok | **Kapsama dışı** — crawl eksik | Seed URL ekle, `/app` SPA'yı ajax-spider ile tara |
| Hiç istek yok (ilgili path'e) | Tarayıcı o sayfayı görmedi | `robots.txt` / sitemap / dashboard linklerini kontrol et |

Özet API: `GET /api/stats` → `{ total_requests, by_signal, last_20 }`

---

## 5. Kaynak ölçümü — agent.py

Tarayıcının ne kadar CPU/RAM yaktığını koşu kaydına gömmek için taramayla **paralel** çalıştır:

```powershell
pip install psutil
python evaluation/agent.py --process java     # ZAP (java süreci)
python evaluation/agent.py --process nuclei   # Nuclei
python evaluation/agent.py --duration 600     # 10 dk sonra otomatik durur
```

`scan.py finish` aynı `scan_id`'li `.resources.json` dosyasını bulursa kayda gömer → dashboard'da CPU/RAM sütunları dolar.

---

## 6. Kör (OOB) ölçümü

Blind XSS / blind SSRF / log4shell payload'ları `/oob/*` adresine callback bırakır:

```powershell
# tetik örneği
Invoke-WebRequest "http://localhost:8800/oob/t123?x=1"
# sayaç
Invoke-RestMethod http://localhost:8800/api/oob-hits
```

`scan.py finish` pencere içindeki OOB sayısını kayda yazar (`oob_callbacks_in_window`). Kör zafiyetleri bulan tarayıcılar burada belli olur.

---

## 7. Dashboard API'leri (ölçüm altyapısı)

| Endpoint | İçerik |
|---|---|
| `GET /dashboard` | İnsan paneli: endpoint listesi + skor tablosu |
| `GET /api/overview` | `{ ground_truth_total, vulnerable, secure, fp_trap, verified, recorded_scans }` |
| `GET /api/scans` | Son 30 koşu özeti (süre, hız, coverage, TP/FP/FN/TN, CPU/RAM, ΔF1) |
| `GET /api/stats` | Log özeti (istek sayısı, sinyal dağılımı) |
| `GET /api/oob-hits` | Kör callback listesi |
| `GET /api/ground-truth` | Canlı `ground-truth.json` (blind modda 404) |
| `POST /api/admin/reset` | Durumu sıfırla + tohumla (yalnızca localhost) |

Her yanıt ayrıca şu header'ları taşır (transparent modda; blind'da basılmaz): `X-Vuln-Id`, `X-Vuln-Category`, `X-Ground-Truth`.

---

## 8. İpuçları: skoru yükseltmek (tarayıcı tarafı)

- **AJAX Spider / authenticated scan** aç → `/app` SPA ve auth-gated endpoint'ler (`/app/*`, `/api/users-secure/*`) coverage'a girer
- **GraphQL + API taraması** için OpenAPI/GraphQL eklentilerini etkinleştir
- **Time-based** yakalamak için tarayıcı timeout eşiğini 3 sn üstünde tut (`/runtime/sqli-time` gerçek 3 sn uyur; kalibreli oracle: `/blindtime/calibrate` + `/blindtime/lookup?key=SLEEP(2)`)
- **FP'leri kısmak** için `secure` ikizlerde + `/fphell/*` decoy'larda öten kuralları not et → policy'den çıkar, F1'in nasıl arttığını `scan.py list` ile izle
- **Gerçek-zamanlı yüzey** için WS istemcisiyle `/realtime/ws`, event-stream ile `/realtime/sse?msg=`, grpc-web frame ile `POST /realtime/grpc` dene (secure ikizleri karşılaştır)

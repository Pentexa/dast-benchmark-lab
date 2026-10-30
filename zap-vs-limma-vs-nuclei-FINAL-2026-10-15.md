# ZAP 2.17-max vs Limma Deep-max vs Nuclei 3.11 — Üçlü Final (15.10.2026)

**Tek tur (unauth), maksimum efor, mühürlü kayıt. Kazanan: LİMMA (2-0-0 hükmünde).**

| Sıra | Araç | Spesifik TP | Süre | İstek |
|---|---|---|---|---|
| 🥇 | Limma Deep-max | **33** | **8 dk** | **15.912** |
| 🥈 | ZAP 2.17-max | 18 | 68 dk | 43.044 |
| 🥉 | Nuclei 3.11 | 10 | 113 dk | 896.646 |

> Ham F1'ler (ZAP 0.671 / Limma 0.597 / Nuclei 0.479) hükme dahil DEĞİLDİR — gerekçe §3. Hüküm spesifik tespit + FP disiplini + hız + verimlilik ile verildi.

---

## 1. Koşullar (üç tarafta ortak)

| Parametre | Değer |
|---|---|
| Uygulama | DAST Benchmark Lab (Node/Express), blind mod |
| GT | 383 endpoint: 194 zafiyetli / 73 güvenli / 116 FP-tuzağı, 18 kategori |
| Reset | Her koşu öncesi `POST /api/admin/reset` + seed=7 |
| Seed | 381 benzersiz path (GT'den; keşif ölçüm-dışı) |
| Eşleştirme | `evaluate.py` path-fallback (weak), strong=0 üç tarafta da |
| OOB | Üç tarafta 0 gerçek callback |

**Sapmalar (şeffaflık):**
- ZAP ORTAM default-policy yerine MAXIMUM koştu (53 kural INSANE/LOW, 10 thread, 4GB) — ham skorunu şişiren yönde sapma.
- ZAP'ın AJAX spider'ı eklenti hatası verdi (crawl eksikliği ZAP aleyhine; raporda).
- Nuclei `localhost`'u çözemedi → `https://127.0.0.1:9443` kullanıldı (transport eşdeğer).
- Nuclei template kapsamı 1496 (CVE/panel/login setleri mock-dışı bırakıldı, ilan edildi).
- Nuclei sonda asıldı (41 dk zombi) — coverage %99'a ulaşmıştı, ölçüm geçerli; neden test-altyapısı, araç kusuru değil.
- Limma unauth turunda `/app` zincirleri kapalıydı (oturumsuz) — APP-Shop ham düşüklüğünün sebebi, auth'ta kapandı.

## 2. Üçlü tur tablosu — Unauth

| | ZAP 2.17-max | Limma Deep-max | Nuclei 3.11 |
|---|---|---|---|
| Tarih | 14.10.2026 | 14.10.2026 | 15.10.2026 |
| Süre / istek | 4092 sn (68 dk) / 43.044 | 492 sn (~8 dk) / 15.912 | 6758 sn (113 dk) / 896.646 |
| Hız | ~10/sn | ~32/sn | ~133/sn (tepe 405) |
| Coverage | %99 (379/383) | %99 (379/383) | %99 (379/383) |
| Bulgu | 1837 alert (24 sınıf) | 1961 | 2158 (14 template) |
| Ham TP/FP/FN/TN | 193/188/1/1, F1 0.671 | 148/154/46/35, F1 0.597 | 99/120/95/69, F1 0.479 |
| **Spesifik TP (R)** | **18 (0.093)** | **33 (0.170)** | **10 (0.052)** |
| FP (FPR) | 188 (0.995) | 154 (0.815) | 120 (0.635) |
| 5xx | 160 (%0.37) | 111 (%0.70) | 168 (%0.02) |

## 3. Ham vs spesifik (neden ham hükümsüz)

| Araç | Ham TP | Spesifik TP | Jenerik-only | Spesifik recall |
|---|---|---|---|---|
| ZAP | 193 | 18 | 174 | 0.093 |
| Limma | 148 | 33 | 115 | 0.170 |
| Nuclei | 99 | 10 | 89 | 0.052 |

Kanıtlar:
- ZAP: `/injection/sqli` üzerindeki 4 alertin tamamı header (X-Powered-By, CSP, XCTO, clickjacking) — SQLi tespiti yok ama path-eşleşme TP sayıyor.
- Limma: 1904/1961 bulgu hardening/bilgi; spesifik 33 (time-based SQLi sinyali + 4 SSTI motoru dahil).
- Nuclei: 2158 bulgunun 2129'u (%98.6) tek info template (`http-missing-security-headers`); spesifik 10 (.env/.bak/actuator/token/JWT).

### 3b. Spesifik bulguların anatomisi (doğru isim vs doğru yer)

Spesifik TP'nin ikinci katmanı: bulgu, path'teki GERÇEK zafiyeti mi adlandırıyor?

| | Tam (doğru isim) | Gevşek (doğru yer, şemsiye isim) | Yanlış (doğru yer, yanlış isim) |
|---|---|---|---|
| Limma (33) | 18 (%55) | 15 (IDOR-candidate saçılması) | 0 |
| ZAP (18) | 5 (%28) | 9 (PII-Disclosure şemsiyesi) | 4 (`/csrf`+`/ssrf`'e "SQLi", 2 IDOR'a ".env leak") |
| Nuclei (10) | 8 (%80) | 2 (cache2'de jwt-token, SSE'de mcp-sse) | 0 |

Okuma: oransal en temiz Nuclei (az bulur, doğru adlandırır); hacim+isabet lideri Limma (18 tam = ZAP'ın toplam spesifikine eşit); ZAP hem az hem dağınık (4 yanlış isimli). verify.py 194/194 kanıtlı olduğundan üç tarafın zeminleri de teyitli — ayrım adlandırmadadır.

## 4. Kategori ham-F1 üçlü (uyarı: şişik skorlar, eğilim için)

| Kategori | ZAP | Limma | Nuclei |
|---|---|---|---|
| A01-AccessControl | 0.78 | 0.73 | 0.55 |
| A02-Crypto | 0.91 | 0.91 | 0.80 |
| A03-Injection | 0.88 | 0.89 | 0.18 |
| A03-XSS | 0.81 | 0.76 | 0.00 |
| A04-BusinessLogic | 0.76 | 0.71 | 0.46 |
| A04-FileHandling | 0.86 | 0.86 | 0.78 |
| A04-InsecureDesign | 0.80 | 0.67 | 0.00 |
| A05-CacheSmuggle | 0.80 | 0.74 | 0.57 |
| A05-Exposure | 1.00 | 1.00 | 0.84 |
| A05-Misconfig | 0.84 | 0.82 | 0.62 |
| A07-Auth | 0.84 | 0.78 | 0.68 |
| A08-Integrity | 1.00 | 1.00 | 0.00 |
| A10-SSRF | 0.86 | 1.00 | 0.83 |
| API-GraphQL | 0.78 | 0.88 | 0.00 |
| API-Security | 0.76 | 0.71 | 0.63 |
| APP-Shop | 0.92 | 0.15 | 0.92 |
| Client-Side | 0.76 | 0.73 | 0.61 |
| FP-Trap | 0.00 | 0.00 | 0.00 |

Okuma: Nuclei'nin sıfırları (XSS, GraphQL, Integrity, InsecureDesign) körlük haritasıdır; APP-Shop 0.92'si jenerik eşleşmedir. Limma'nın APP-Shop 0.15'i unauth körlüğüdür (auth'ta 0.80).

## 5. Verimlilik (maçın asıl hikayesi)

| | ZAP | Limma | Nuclei |
|---|---|---|---|
| İstek başına spesifik | ~2400'de 1 | **~480'de 1** | ~90 binde 1 |
| Süre | 68 dk | **8 dk** | 113 dk |
| Toplam istek | 43.044 | **15.912** | 896.646 |

Limma, Nuclei'ye göre ~187×, ZAP'a göre ~5× daha az istekle spesifik bulguya ulaşıyor. Hız (rps) ile verimlilik (istek/bulgu) farklı şeylerdir: en hızlı basan (Nuclei, 133/sn) en verimsiz, en az basan (Limma) en verimli.

## 6. Hakem tablosu (toplam)

| # | Kriter | Sonuç |
|---|---|---|
| 1 | Spesifik tespit | Limma 33 > ZAP 18 > Nuclei 10 |
| 2 | Hız | Limma 8 dk > ZAP 68 dk > Nuclei 113 dk |
| 3 | Verimlilik | Limma > ZAP > Nuclei |
| 4 | FP disiplini (sayı) | Nuclei 120 < Limma 154 < ZAP 188 |
| 5 | Ham F1 | hükümsüz |
| 6 | Coverage | üçlü berabere %99 |
| 7 | OOB | üçlü berabere 0-0 |

Not: FP sayısında Nuclei en düşük, ancak bulgularının %98.6'sı tek info template — disiplin değil, körlük sayıyı düşük tutmuş olabilir. FP-Trap F1 üç tarafta da 0.00 (tuzaklar çalışıyor: kimse temiz değil, herkes yakalanıyor).

## 7. Dosya envanteri

- Mühürler: `evaluation/benchmark-ZAP-2.17-max-20261014.json`, `benchmark-Limma-deep-max-20261014.json`, `evaluation/benchmark-Nuclei-3.11-20261015.json`
- Koşu kayıtları: `evaluation/runs/run-20261014-095012-*`, `run-20261014-115358-*`, `run-20261015-161745-*`
- Ham bulgular: `zap-max-*.json`, Limma attempt01, `nuclei-20261015.jsonl`
- Önceki raporlar: `limma-vs-zap-FINAL-2026-10-14.md`, `limma-vs-nuclei-FINAL-2026-10-15.md`

## 8. Hüküm

**1. Limma, 2. ZAP, 3. Nuclei.** Limma spesifik tespitte ~2× ZAP, ~3× Nuclei; sürede ~8× ZAP, ~14× Nuclei. ZAP'ın XSS/PII derinliği saygın (ikincilik sağlam), Nuclei exposure avcılığında iş görür ama injection/XSS/GraphQL körlüğüyle bu ligde geride. Üç aracın da kör noktaları (§1 sapmalar + §4 sıfırlar) şeffaf yazıldı; ölçümün değeri budur.

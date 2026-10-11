# 📖 Ne İşe Yarar?

> Bu proje bir **DAST doğruluk laboratuvarı**dır: tarayıcıların neyi bulup neyi kaçırdığını, nede yanlış alarm verdiğini **sayıyla** gösterir.

---

## 1. Hangi sorunu çözer?

Bir DAST tarayıcısı (ZAP, Burp, Nuclei, Acunetix...) çalıştırdığında şöyle bir rapor alırsın:

```
41 bulgu: 12 XSS, 8 SQLi, 5 open-redirect, ...
```

Ama üç kritik sorunun cevabı yoktur:

1. **Kaç gerçek açığı kaçırdı?** (ölçülmeyen risk)
2. **Kaç bulgu yanlış alarm?** (boşa harcanan triyaj zamanı)
3. **Aracı değiştirsem / ayar oynasam daha mı iyi olur?** (karşılaştırma zemini yok)

Gerçek uygulamalarda "cevap anahtarı" olmadığı için bu sorular cevapsız kalır. Bu proje cevabı **önceden bilinen** bir hedef sunarak sorunu çözer.

---

## 2. Fikir: cevabı bilinen hedef 🎯

Sunucu `ground-truth.json` adlı bir **hakem heyeti** ile gelir: her endpoint'in kirli mi temiz mi olduğu baştan bellidir.

| Sembol | Tür | Adet | Anlamı | Örnek |
|---|---|---|---|---|
| 🔴 | `vulnerable` | 194 | Gerçek zaaf, tarayıcı **bulmalı** | `/injection/sqli?id=1' OR '1'='1` → SQL hatası döner |
| 🟢 | `secure` | 73 | Güvenli kontrol, tarayıcı **susmalı** | `/injection/sqli-secure` → aynı payload etkisiz |
| 🟡 | `fp-trap` | 116 | **FP tuzağı**: şüpheli görünüp temiz olan sayfa (12 klasik + 104 decoy) | `/fp/search` → yardım metninde "SQL syntax" geçer ama zaaf yok |

Her zafiyetli endpoint'in **yanında ikizi** vardır: biri zafiyetli, biri güvenli. Böylece "tarayıcı ikisini ayırt edebiliyor mu?" test edilir.

---

## 3. TP / FP / FN / TN — 1 dakikada

Tıbbi test gibi düşün: hasta mı değil mi + test ne dedi?

| | Tarayıcı **alarm verdi** | Tarayıcı **sessiz kaldı** |
|---|---|---|
| **Gerçekten zafiyetli** (🔴) | **TP** (True Positive) ✅ doğru yakaladı | **FN** (False Negative) ❌ kaçırdı — en tehlikelisi |
| **Gerçekten güvenli** (🟢🟡) | **FP** (False Positive) ❌ yanlış alarm — zaman kaybettirir | **TN** (True Negative) ✅ doğru sustu |

Özet metrikler:

- **Precision** = `TP / (TP + FP)` → "Alarmların kaçı gerçek?" (yüksekse triyaj ucuzdur)
- **Recall** = `TP / (TP + FN)` → "Gerçek açıkların kaçını yakaladı?" (yüksekse kapsama iyidir)
- **F1** = ikisinin harmonik ortalaması → tek skorla karşılaştırma
- **FPR** = `FP / (FP + TN)` → "Temiz sayfalarda ne sıklıkla ötüyor?"

```
Örnek (gerçek ZAP 2.17 koşusu, v1 GT): TP=34 FP=13 FN=129 TN=46
→ Precision 0.72 (alarmlar çoğunlukla güvenilir) ama Recall 0.21 (çoğu açığı kaçırmış!)
→ Yorum: "sakin ama kör bir tarayıcı"
```

---

## 4. FP-tuzağı nedir? Neden 116 tane var? 🟡

Gerçek DAST araçları bazı **masum kalıplara** yanlış alarm verir. Bu proje o kalıpları bilerek barındırır:

| Tuzak | Masum gerçek | Acemi tarayıcı ne yapar? |
|---|---|---|
| `/fp/search` | Yardım metninde "SQL syntax" kelimesi | "SQLi buldum!" der (metin eşleşmesi) |
| `/fp/sdk-example` | Dokümandaki `sk_test_ÖRNEK` anahtar | "Secret leak!" der |
| `/fp/waf-block` | Statik WAF bilgi sayfası | "WAF bypass!" der |
| `/fp/csp-inline` | nonce+CSP korumalı script | "Inline script!" der |
| `/fp/coupon-once` | Doğru tek-kullanımlık kupon (2. kullanım 410) | "Kupon reuse!" der |
| `/fp/login-lock` | Doğru kilit (5 deneme → 429) | "Brute-force koruması yok!" der |
| `/fp/slow-report` | Meşru yavaş rapor sayfası (~3 sn) | "Time-based SQLi!" der |

> FP-tuzağına alarm veren tarayıcı **gürültücüdür**; sessiz kalan **olgun**.

V2'de klasik 12 tuzağa ek **104 decoy** (`/fphell/*`) eklendi: sahte SQL hataları, nötralize yansımalar, hiç ateşlenmeyen sahte callback'ler, meşru yavaşlıklar, ÖRNEK/TEST secret'lar, yanıltıcı auth yanıtları, WAF-benzeri sayfalar, sahte ifşalar. Her decoy'un **makineyle doğrulanmış negatif proof'u** var (`verify.py` → `104/104 temiz`): tuzak metin ortada, zaaf işareti yok. Yani decoy'lar "muhtemelen temiz" değil, **kanıtlı temiz**.

---

## 5. Kimler için?

| Kişi | Ne kazanır? |
|---|---|
| 🧪 **Pentester / AppSec uzmanı** | Kullandığı tarayıcının kör noktalarını öğrenir, manuel teste oradan başlar |
| 🔄 **DevSecOps mühendisi** | Pipeline'a koyacağı tarayıcıyı sayıyla seçer (ZAP vs Nuclei vs Burp → ΔF1 tablosu) |
| 🎓 **Öğrenci / eğitim veren** | 383 gerçekçi senaryoda zafiyetleri eliyle sömürür (dashboard'daki "dene" linkleri + `test_hint`'ler) |
| 🔬 **Araştırmacı** | Yeni dedektör fikrini 194 proof'lu hedefte benchmark'lar, kategori×zorluk F1 raporlar |
| 🧑‍💼 **Yönetici** | "Tarayıcımız %X recall ile çalışıyor" diye raporlanabilir metrik alır |

---

## 6. Neden bu proje? (farkı ne?)

| | Bu proje | Klasik DVWA / Juice Shop | Gerçek uygulama |
|---|---|---|---|
| Cevap anahtarı | ✅ 383 satırlık `ground-truth.json` (zorluk + oracle + simüle/gerçek ayrımıyla) | ❌ yok / kısmi | ❌ bilinmiyor |
| Skorlayıcı | ✅ `evaluate.py` (TP/FP/FN/TN + F1 + zorluk kırılımı) + `report.py` (JSON+MD) | ❌ | ❌ |
| FP ölçümü | ✅ 116 tuzak + 73 güvenli ikiz | ❌ | ❌ |
| Doğrulanabilirlik | ✅ `verify.py` → 194/194 proof + 104/104 decoy negatifi | ❌ | ❌ |
| Adil ölçüm | ✅ Blind Mode (cevap anahtarı gizli) + tohumlu reset | ❌ | ❌ |
| Tarama geçmişi | ✅ `scan.py` ile kalıcı koşu kaydı | ❌ | ❌ |
| FN analizi | ✅ sinyal etiketli `requests.log` | ❌ | ❌ |
| Güvenli tarama | ✅ tehlikeli vektörler mock | ⚠️ kısmen gerçek | ⚠️ riskli |

> Kısacası: DVWA/Juice Shop **öğretir**, bu proje **ölçer**. Birbirinin rakibi değil tamamlayıcısıdır.

---

## 7. Somut bir tur (60 saniye)

```powershell
npm start
# http://localhost:8800/dashboard aç
```

1. **Zafiyetliyi dene:** `/xss/reflected?name=<script>alert(1)</script>` → script yansır (🔴 TP beklenir)
2. **Güvenli ikizi dene:** `/xss/reflected-secure?name=<script>alert(1)</script>` → encode edilir (🟢 TN beklenir)
3. **Tuzağa bak:** `/fp/search?q=' OR 1=1` → "SQL syntax" yardım metni döner ama zaaf yok (🟡 TN beklenir, alarm = FP)
4. **Zinciri dene:** `/app` SPA'sında login ol → `PUT /app/api/profile {"role":"admin"}` → admin token al → `/app/api/feedback-view`'da stored XSS tetikle

Hepsi `ground-truth.json`'da `test_hint` olarak yazılıdır.

---

## 8. V2'de yeni (Extreme Range)

- **14 extreme grubu:** Shadow-DOM SPA, rol-farklı stored/blind XSS, multi-tenant IDOR/BOLA, GraphQL iç-içe yetki + federasyon, OAuth/OIDC akışları, iş-akışı atlama, deterministik race, asenkron second-order, kalibreli blind timing, kademeli OOB, parser farklılıkları, paylaşımlı-cache, soft-404/limit karışıklığı, WebSocket/SSE/gRPC-Web.
- **Blind Mode:** `DAST_MODE=blind` ile cevap anahtarı (header, dashboard, API) gizlenir — adil ölçüm modu. Varsayılan transparent (öğrenme) değişmedi.
- **Zorluk + oracle:** her satırda `difficulty` (easy/medium/hard/chaos/fp-hunter) ve makine-okunur `oracle`; raporlar zorluk kırılımlı.
- **Simüle vs gerçek:** `execution` alanı — mock iddia (`simulated`, örn. sahte metadata) ile gerçekten icra edilen davranış (`live`, örn. gerçek 3 sn uyku, gerçek HMAC) raporda ayrı yazılır.

Detay: [ZORLUK-SEVIYELERI.md](./ZORLUK-SEVIYELERI.md), [BLIND-MODE.md](./BLIND-MODE.md) (EN), [ORACLES.md](./ORACLES.md) (EN).

---

**Sıradaki adım:** kurulum için [🔧 KURULUM.md](./KURULUM.md), ilk taramanı ölçmek için [📊 TARAMA-VE-OLCUM.md](./TARAMA-VE-OLCUM.md).

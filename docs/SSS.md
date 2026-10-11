# ❓ Sık Sorulan Sorular (SSS)

## Genel

**Bu proje gerçek zafiyet mi içeriyor, makinem tehlikede mi?**
Hayır. CMDi / SSRF / XXE / Deserialization / RFI / Zip Slip **gerçekten çalıştırılmaz** — sadece pattern-match ile mock yanıt döner. `ping`, `cat /etc/passwd`, metadata çıktıları sahte metindir. Yine de kural olarak **internete açma, localhost'ta tut**.

**194/194 + 104/104 ne demek?**
`python evaluation/verify.py` ground-truth'taki 194 zafiyetli endpoint'e tek tek proof payload gönderir ve sömürülebilir davranışı teyit eder. 194/194 = "listedeki her zaaf gerçekten çalışıyor, ölü endpoint yok". 104/104 = 104 decoy'un tamamı **kanıtlı temiz** (tuzak metin var, zaaf işareti yok).

**Secure ikiz ne işe yarıyor?**
Her zaafın yanında aynı görünümlü temiz bir ikiz var (`/injection/sqli` → `/injection/sqli-secure`). Tarayıcı ikisine de ötüyorsa ezbere ötüyordur (FP); sadece kirliye ötüyorsa ayırt ediyordur. Precision buradan gelir.

**FP-tuzağı ile secure farkı ne?**
İkisi de "sessiz kalınmalı" sayılır (TN beklenir). Fark: secure **doğru yazılmış kod** örneğidir; FP-trap ise **bilerek şüpheli görünüp temiz** olan sayfadır (yardım metni, örnek anahtar...). Tuzaklar tarayıcının metin-eşleşme zaaflarını avlar.

**Blind Mode nedir, ne zaman kullanmalıyım?**
`DAST_MODE=blind` ile sunucu cevap anahtarını gizler (GT header'ları, dashboard beklentileri, `/api/ground-truth`). Öğrenirken transparent, **skor adil olsun istiyorsan blind** kullan. Detay: [BLIND-MODE.md](./BLIND-MODE.md) (EN).

**Taramalar arası durum sıfırlama nasıl yapılır?**
`python evaluation/scan.py start --scanner "..." --reset --seed 7` — kilitler, kuponlar, sepetler sıfırlanır, tohum sabitlenir. Böylece Limma/ZAP/Burp/Invicti **aynı koşullarda** yarışır. Detay: [RESET.md](./RESET.md) (EN).

## Kurulum

**`npm install` hata veriyor?**
Node 18+ kullandığından emin ol (`node --version`). Kurumsal proxy arkasındaysan `npm config set registry https://registry.npmjs.org/` dene, sonra tekrar kur.

**`EADDRINUSE :::3000`?**
Port dolu. Ya kullanan uygulamayı kapat ya da başka portta çalıştır: PowerShell'de `$env:PORT=4000; npm start`.

**`python` komutu yok?**
Python PATH'e ekli değildir. `py --version` dene; olmuyorsa python.org'dan "Add python.exe to PATH" işaretli şekilde yeniden kur.

**Dashboard açılmıyor?**
Önce terminalde `[+] DAST mock server` satırını gör. Sonra `http://localhost:3000/dashboard` (http**s** değil, sondaki slash'e dikkat). Antivirüs/proxy localhost'u kesiyorsa geçici kapatıp dene.

## Tarama

**ZAP raporumda `site: null` var, skor 0 geldi?**
Yanlış rapor tipini indirmişsin (Auth/Log raporu gibi). ZAP'ta **Report → Generate Report → JSON Report** (alert'li olan) seçmelisin. `evaluate.py` bu durumda uyarı verir.

**Nuclei hiçbir şey bulamadı, normal mi?**
Baseline Nuclei şablonları bu mock'un bazı özel yollarını taramayabilir. Önce `nuclei -u http://localhost:3000 -t httptechnologies/ -jsonl` gibi ilgili şablonlarla dene; coverage'ı `GET /api/stats` ile kontrol et.

**Tarayıcı `/app` sayfalarını hiç gezmemiş?**
`/app` JS-render SPA'dır; klasik spider yetmez. ZAP'ta **AJAX Spider** aç veya authenticated scan ile giriş yapmış bağlam kullan. `logs/requests.log`'da `/app/api/*` isteği yoksa crawl eksiktir.

**Time-based SQLi (`/runtime/sqli-time`) bulunamıyor?**
Endpoint gerçekten 3 saniye uyur. Tarayıcının "time-based" eşiği/timeout'u 3 sn altında kalıyorsa kaçırır. Eşiği yükseltip tekrar dene.

**Blind XSS nasıl ölçülüyor?**
`/runtime/feedback` adresine `callback` ile payload bırak, `/runtime/feedback-view` tetikler ve `/oob/*`'a callback düşer. V2'de ek olarak: rol-farklı kör kuyruk (`/xss2/blindreply` → `/xss2/modqueue`) ve kademeli OOB (`POST /oob2/register` → `GET /oob2/fire` → 2 sn sonra sayaç artar). `GET /api/oob-hits` sayacını koşu öncesi/sonrası karşılaştır.

**WebSocket taraması nasıl yapılır?**
`ws://localhost:3000/realtime/ws` — Origin sorulmaz, echo yapar (açık). Karşılaştırma için `/realtime/ws-secure` (yabancı Origin'e 403). ZAP'ta WebSocket eklentisiyle pasif dinle + manuel gönder; SSE için `/realtime/sse?msg=`, gRPC-Web için `POST /realtime/grpc`.

## Skorlama

**Aynı tarayıcıyla iki koşuda farklı F1 aldım?**
Normaldir: tarayıcılar rastgele gecikme/seed kullanır, ayrıca `scan.py` **zaman pencereli log** okur (`start`–`finish` arası). Pencerede kalan eski istekler ve sıfırlanmamış kilitler coverage'ı etkiler. Her koşuya `--reset --seed 7` ile başla, karşılaştırma için aynı süre/politika ile 2–3 koşu ortalaması al.

**Kategori F1'im 0 ama genel F1 yüksek?**
O kategoriye hiç uğranmamış olabilir (coverage 0). Önce `coverage_by_category`'ye bak: `hit=0` ise sorun dedektör değil **crawl**'dır.

**FP'lerim çok yüksek, ne yapmalıyım?**
`fp_list`'teki ID'leri grupla: çoğu `/fp/*` veya `/fphell/*` ise tarayıcın metin-eşleşmeye dayalı kural kullanıyordur. İlgili plugin ID'lerini policy'den düşür, koşuyu tekrarla, `dF1`'in arttığını izle.

**`secure` endpoint'e alarm = her zaman kötü mü?**
Ölçüm açısından evet (FP sayılır). Ama triyajda bağlama bak: bazı araçlar "bilgilendirme" seviyesinde not düşer; `evaluate.py` seviye ayırt etmez, URL eşleşmesine bakar.

## Geliştirme

**Yeni endpoint nasıl eklerim?**
1. `routes/` altına veya ilgili dosyaya route ekle (`mark()` helper'ı header'ı halleder — blind'da otomatik susar)
2. `ground-truth.json`'a `{id, method, path, category, vuln_type, expectation, test_hint, severity, difficulty, oracle, execution}` satırı ekle (şema: [ORACLES.md](./ORACLES.md))
3. `evaluation/verify.py` içindeki `P`/`P1` sözlüğüne proof ekle (çok adımlıysa `custom_proofs`'a)
4. `python evaluation/verify.py` ile sayının arttığını doğrula (örn. 195/194 değil 195/195 — toplam da büyür!)

**Katkı gönderebilir miyim?**
Evet — fork + branch + PR. Tek kural: `verify.py` yeşil kalmalı (mevcut 194'ü bozma, 104 decoy'u kirletme) ve her yeni zafiyet proof'lu + `difficulty`/`oracle` etiketli gelmeli.

**Raporu JSON/Markdown olarak nasıl alırım?**
`python evaluation/report.py --run evaluation/runs/<koşu>.json` veya `--findings rapor --format zap --scanner "Ad" --mode authenticated-full` → `evaluation/reports/` altına `.json` + `.md` yazar (sınıf×zorluk×simüle/gerçek kırılımlı).

**`strong` / `weak` eşleşme ne demek?**
Bulgu `vuln_id` taşıyorsa GT satırıyla doğrudan eşleşir (strong); yoksa path-fallback (weak). Eski raporlar weak olarak çalışmaya devam eder, skorları değişmez.

**Lisans nedir?**
Eğitim/test amaçlıdır; production'da veya internete açık koşturma. Sorumluluk kullanıcıya aittir (bkz. README Lisans bölümü).

---

Takıldığın başka bir şey olursa: önce [KURULUM.md](./KURULUM.md#8-sorun-giderme-hızlı-tablo)'daki tabloya, sonra `logs/requests.log`'un son 5 satırına bak — çoğu sorunun izi oradadır. 🔍

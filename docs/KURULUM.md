# 🔧 Kurulum Rehberi (v2 güncel)

> **Süre:** ~2 dakika • **Zorluk:** Kolay • **İhtiyaç:** Node.js 18+ ve Python 3.10+
> **Kapsam:** 383 endpoint (194 zafiyetli + 73 güvenli + 116 FP-tuzağı)

Bu doküman projeyi **sıfırdan çalışır hale** getirir. Hızlı özet için [README](../README.md#-hızlı-kurulum-2-dakika) yeter; takıldığın yerde buraya dön.

---

## 1. Gereksinimler

| Araç | Minimum sürüm | Kontrol komutu | İndir |
|---|---|---|---|
| Node.js (+npm) | 18.x | `node --version` | https://nodejs.org/ |
| Python | 3.10 | `python --version` | https://www.python.org/ |
| Git | herhangi | `git --version` | https://git-scm.com/ |
| Docker *(opsiyonel, ZAP için)* | herhangi | `docker --version` | https://www.docker.com/ |

> Python paketine ihtiyacın yok — `verify.py`, `evaluate.py`, `scan.py` standart kütüphane ile çalışır. Sadece `agent.py` (CPU/RAM ölçer) için `pip install psutil` önerilir.

---

## 2. Projeyi indir

```powershell
git clone <repo-url>
cd extensionpro
```

ZIP ile indirdiysen klasöre girmen yeterli.

---

## 3. Kurulum (Windows / macOS / Linux — aynı)

```powershell
# 1) Node bağımlılıklarını kur (express, cookie-parser, cors, jsonwebtoken, morgan, ws)
npm install

# 2) Sunucuyu başlat (transparent mod = öğrenme dostu, cevaplar görünür)
npm start
```

Başarılı çıktı:

```
[+] DAST mock server (transparent): http://localhost:8800/dashboard
```

> Adil ölçüm için **blind mod** (cevap anahtarı gizli): `$env:DAST_MODE="blind"; npm start` → detay: [BLIND-MODE.md](./BLIND-MODE.md) (EN)

Tarayıcıda aç: **http://localhost:8800/dashboard** 🎉

Durdurmak için: `Ctrl+C`. Geliştirme modunda otomatik yeniden başlatma için:

```powershell
npm run dev   # node --watch server.js
```

---

## 4. Doğrulama — her şey çalışıyor mu?

Yeni bir terminal aç (sunucu çalışmaya devam etsin):

```powershell
# 194 zafiyetin hepsi gerçekten sömürülebilir mi? + 104 decoy gerçekten temiz mi?
python evaluation/verify.py
# deterministik koşu (önce sunucuyu sıfırlar + tohumlar):
python evaluation/verify.py --seed 7
```

Beklenen çıktı:

```
=== DOĞRULAMA: 194/194 sömürülebilir (+0 erişilebilir, 0 hatalı) ===
=== DECOY: 104/104 temiz (0 sızıntı) ===
kayıt: evaluation/verification.json
```

Bu sonuç `evaluation/verification.json` dosyasına yazılır ve dashboard'daki rozette görünür (`GET /api/overview` — blind modda rozet gizlenir).

Hızlı kabul paketi (şema + tutarlılık + canlı spot-kontroller, <60 sn):

```powershell
npm test   # python tests/acceptance.py
```

> `sunucuya ulaşılamadı` hatası alırsan → sunucunun `npm start` ile ayakta olduğundan ve `http://localhost:8800/dashboard` adresinin açıldığından emin ol.

---

## 5. Port değiştirme

Varsayılan port `8800`'dir. Doluysa veya değiştirmek istersen:

```powershell
# Windows PowerShell
$env:PORT=4000; npm start

# macOS / Linux
PORT=4000 npm start
```

Python tarafına da söyle (yoksa `http://localhost:8800` varsayar):

```powershell
$env:DAST_TARGET="http://localhost:4000"; python evaluation/verify.py
```

---

## 6. Taramadan önce sıfırlama (aynı koşullar)

Kilit sayaçları, kupon havuzları, sepetler taramadan taramaya sarkmasın:

```powershell
# scan.py bunu otomatik yapar:
python evaluation/scan.py start --scanner "ZAP 2.17" --mode authenticated-full --reset --seed 7
# veya elle:
# POST /api/admin/reset  {"seed": 7}   (yalnızca localhost)
```

Detay: [RESET.md](./RESET.md) (EN). Modlar ve kimlik paketi: [AUTH-PACK.md](./AUTH-PACK.md) (EN).

---

## 7. Docker ile ZAP taraması (kurulumsuz tarayıcı)

Sunucu host'ta çalışırken ZAP'ı Docker'dan koşturmak en temiz yoldur:

```powershell
docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:8800 -J zap-rapor.json
```

> Windows'ta `--network host` çalışmazsa `http://host.docker.internal:8800` adresini kullan.

Nuclei (kuruluysa):

```powershell
nuclei -u http://localhost:8800 -jsonl -o nuclei.jsonl
```

Raporu skora çevirme → [TARAMA-VE-OLCUM.md](./TARAMA-VE-OLCUM.md)

---

## 8. Sorun giderme (hızlı tablo)

| Sorun | Neden | Çözüm |
|---|---|---|
| `npm start` → `EADDRINUSE :::8800` | Port dolu | Başka uygulamayı kapat veya [port değiştir](#5-port-değiştirme) |
| `python` bulunamadı | Python PATH'te yok | Python'u "Add to PATH" seçeneğiyle yeniden kur; veya `py` komutunu dene |
| `verify.py` → bağlantı hatası | Sunucu kapalı | `npm start` çalışıyor mu? `http://localhost:8800/dashboard` açılıyor mu? |
| `194/194` yerine düşük sayı | Eski kod / yarım başlatma / sıfırlanmamış durum | `npm start`'ı yeniden başlat, `python evaluation/verify.py --seed 7` ile tekrar koştur |
| `DECOY` sızıntısı (104/104 değil) | Kodda gerçek bir kirlenme | Hangi ID olduğunu not edip issue aç — benchmark bug'ı demektir |
| Dashboard açılıyor ama `/app` boş | JS kapalı | `/app` JS-render SPA'dır, JS'i aç; API'yi direkt dene: `/app/api/login` |
| ZAP Docker'dan bağlanamıyor (Win) | `host` network yok | Hedef olarak `http://host.docker.internal:8800` kullan |
| `agent.py` CPU göstermiyor | `psutil` yok | `pip install psutil` kur, tekrar dene |
| `logs/` klasörü yok | Henüz istek gelmedi | İlk istekte otomatik oluşur (`lib/requestLogger.js`) |

Daha fazlası → [SSS.md](./SSS.md)

---

## 9. Temiz kurulum kontrol listesi ✅

- [ ] `node --version` → v18+
- [ ] `npm install` hatasız bitti
- [ ] `npm start` → `http://localhost:8800/dashboard` açılıyor
- [ ] `python evaluation/verify.py` → `194/194` + `104/104`
- [ ] `npm test` → `ACCEPTANCE: PASS`
- [ ] Dashboard'da endpoint tablosu + skor tablosu görünüyor

Hepsi tamsa sıradaki adım: **[📖 NE-ISE-YARAR.md](./NE-ISE-YARAR.md)** (konsept) veya **[📊 TARAMA-VE-OLCUM.md](./TARAMA-VE-OLCUM.md)** (ilk taramanı ölç).

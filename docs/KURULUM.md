# 🔧 Kurulum Rehberi

> **Süre:** ~2 dakika • **Zorluk:** Kolay • **İhtiyaç:** Node.js 18+ ve Python 3.10+

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
# 1) Node bağımlılıklarını kur (express, cookie-parser, cors, jsonwebtoken, morgan)
npm install

# 2) Sunucuyu başlat
npm start
```

Başarılı çıktı:

```
[+] DAST mock server: http://localhost:3000/dashboard
```

Tarayıcıda aç: **http://localhost:3000/dashboard** 🎉

Durdurmak için: `Ctrl+C`. Geliştirme modunda otomatik yeniden başlatma için:

```powershell
npm run dev   # node --watch server.js
```

---

## 4. Doğrulama — her şey çalışıyor mu?

Yeni bir terminal aç (sunucu çalışmaya devam etsin):

```powershell
# 163 zafiyetin hepsi gerçekten sömürülebilir mi?
python evaluation/verify.py
```

Beklenen çıktı:

```
=== DOĞRULAMA: 163/163 sömürülebilir (+0 erişilebilir, 0 hatalı) ===
kayıt: evaluation/verification.json
```

Bu sonuç `evaluation/verification.json` dosyasına yazılır ve dashboard'daki rozette görünür (`GET /api/overview`).

> `sunucuya ulaşılamadı` hatası alırsan → sunucunun `npm start` ile ayakta olduğundan ve `http://localhost:3000/dashboard` adresinin açıldığından emin ol.

---

## 5. Port değiştirme

Varsayılan port `3000`'dir. Doluysa veya değiştirmek istersen:

```powershell
# Windows PowerShell
$env:PORT=4000; npm start

# macOS / Linux
PORT=4000 npm start
```

Python tarafına da söyle (yoksa `http://localhost:3000` varsayar):

```powershell
$env:DAST_TARGET="http://localhost:4000"; python evaluation/verify.py
```

---

## 6. Docker ile ZAP taraması (kurulumsuz tarayıcı)

Sunucu host'ta çalışırken ZAP'ı Docker'dan koşturmak en temiz yoldur:

```powershell
docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:3000 -J zap-rapor.json
```

> Windows'ta `--network host` çalışmazsa `http://host.docker.internal:3000` adresini kullan.

Nuclei (kuruluysa):

```powershell
nuclei -u http://localhost:3000 -jsonl -o nuclei.jsonl
```

Raporu skora çevirme → [TARAMA-VE-OLCUM.md](./TARAMA-VE-OLCUM.md)

---

## 7. Sorun giderme (hızlı tablo)

| Sorun | Neden | Çözüm |
|---|---|---|
| `npm start` → `EADDRINUSE :::3000` | Port dolu | Başka uygulamayı kapat veya [port değiştir](#5-port-değiştirme) |
| `python` bulunamadı | Python PATH'te yok | Python'u "Add to PATH" seçeneğiyle yeniden kur; veya `py` komutunu dene |
| `verify.py` → bağlantı hatası | Sunucu kapalı | `npm start` çalışıyor mu? `http://localhost:3000/dashboard` açılıyor mu? |
| `163/163` yerine düşük sayı | Eski kod / yarım başlatma | `npm start`'ı yeniden başlatıp `verify.py`'yi tekrar koştur |
| Dashboard açılıyor ama `/app` boş | JS kapalı | `/app` JS-render SPA'dır, JS'i aç; API'yi direkt dene: `/app/api/login` |
| ZAP Docker'dan bağlanamıyor (Win) | `host` network yok | Hedef olarak `http://host.docker.internal:3000` kullan |
| `agent.py` CPU göstermiyor | `psutil` yok | `pip install psutil` kur, tekrar dene |
| `logs/` klasörü yok | Henüz istek gelmedi | İlk istekte otomatik oluşur (`lib/requestLogger.js`) |

Daha fazlası → [SSS.md](./SSS.md)

---

## 8. Temiz kurulum kontrol listesi ✅

- [ ] `node --version` → v18+
- [ ] `npm install` hatasız bitti
- [ ] `npm start` → `http://localhost:3000/dashboard` açılıyor
- [ ] `python evaluation/verify.py` → `163/163`
- [ ] Dashboard'da endpoint tablosu + skor tablosu görünüyor

Hepsi tamsa sıradaki adım: **[📖 NE-ISE-YARAR.md](./NE-ISE-YARAR.md)** (konsept) veya **[📊 TARAMA-VE-OLCUM.md](./TARAMA-VE-OLCUM.md)** (ilk taramanı ölç).

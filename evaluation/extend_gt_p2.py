#!/usr/bin/env python3
"""P2 extension: 100+ safe decoys (single source).

Generates BOTH:
  - routes/fphell-manifest.json (route loader input: id/slug/trap/guard/reflect/present/absent)
  - ground-truth.json rows (expectation fp-trap, difficulty fp-hunter, negative_proof)

Usage: python evaluation/extend_gt_p2.py [--apply]
"""
import json, os, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_PATH = os.path.join(BASE, "ground-truth.json")
MANIFEST = os.path.join(BASE, "routes", "fphell-manifest.json")
APPLY = "--apply" in sys.argv

GUARD = "Bu sayfa güvenli sayfa (decoy): içerik statik dokümantasyon, çalıştırılabilir kod yok."

# (category, count, trap_lines, absent_markers, reflect?)
CATS = {
    "sql": dict(n=16, absent=["information_schema", "2 rows dumped", "DUMP for", "@@version", "2 result set"],
                traps=[
                    "Arama yardımı: tırnak içeren sorgularda SQL sözdizimi hatası alırsan yardım sayfasını oku.",
                    "SSS: 'SQL syntax' uyarısı bir yardım başlığıdır, veritabanı hatası değildir.",
                    "Doküman: WHERE yan tümcesi örnekleri salt okunur belgede listelenir.",
                    "Hata kodları: ERR-SQL-100 dokümantasyon kodudur, istisna yığını değildir.",
                    "Örnek sorgu: SELECT * FROM docs WHERE topic='yardım' (çalıştırılmaz).",
                    "Not: tek tırnak içeren girdiler yardım önerisi döndürür, sorguya girmez.",
                    "Rehber: UNION kelimesi geçen cümleler sendika (union) aidatı hakkındadır.",
                    "Sözlük: 'sleep' kelimesi uyku modu belgesine aittir, SLEEP() fonksiyonuna değil.",
                    "Değişiklik günlüğü: benchmark() sözcüğü performans testi başlığıdır.",
                    "Eğitim: OR operatörü mantık dersi örneğidir, sorgu parçası değildir.",
                    "Uyarı metni: veritabanı bağlantı dizesi bu sayfada asla yazılmaz.",
                    "İpucu: çift tire (--) ile başlayan satırlar yorum satırı örneğidir.",
                    "Kılavuz: LIKE kalıpları arama ipucudur, enjeksiyon vektörü değildir.",
                    "Bilgi: ORDER BY ifadesi sıralama menüsünü anlatır.",
                    "Not: noktalı virgül; cümleleri ayırır, sorguları değil.",
                    "SSS: büyük/küçük harf duyarlılığı collation belgesinde anlatılır.",
                ]),
    "xss": dict(n=16, absent=["<script>alert", "<img src=x onerror=", "<svg onload=", "WS-ECHO-READY"],
                reflect=True, traps=[
                    "Profil takma adı sayfada aynen gösterilir (güvenli kodlama ile).",
                    "Yorum önizleme: köşeli parantezler metin olarak saklanır.",
                    "Arama kutusu: script kelimesi geçen aramalar yalnızca sayaç artırır.",
                    "Doküman: onload/onerror olayları olay-işleyici dersinde anlatılır.",
                    "Uyarı: javascript: şeması bu sitede bağlantılarda yasaktır.",
                    "Bilgi: svg dosyaları yalnızca .png önizlemesiyle gösterilir.",
                    "Not: img etiketi kullanımı editör kılavuzunda anlatılır.",
                    "SSS: alert() fonksiyonu tarayıcı konsol dersine aittir.",
                    "Rehber: innerHTML kullanımı bu projede yasaktır (textContent kullanılır).",
                    "Örnek: kullanıcı girdisi her zaman entity-encoded basılır.",
                    "Kılavuz: tırnak işaretleri HTML entity karşılığıyla saklanır.",
                    "Bilgi: DOM sink listesi güvenlik kontrol listesinde tutulur.",
                    "Not: postMessage dinleyicisi origin doğrular (dinleyici kodu ekte).",
                    "Uyarı: harici betik (script src) bu sayfaya gömülemez.",
                    "SSS: HTML yorum satırları kullanıcı verisi taşımaz.",
                    "Doküman: şablon değişkenleri otomatik kaçışlıdır.",
                ]),
    "ssrf": dict(n=10, absent=["MOCK-SSRF-LEAK", "secret:", "role: admin"],
                 traps=[
                    "Bağlantı önizleme: URL metni gösterilir, getirme (fetch) kapalıdır.",
                    "Avatar servisi: harici adresler kuyruğa alınır, çağrılmaz.",
                    "Webhook kaydı: hedef URL doğrulanır ama istek gönderilmez.",
                    "Doküman: 169.254.169.254 adresi test vektörü listesindedir (erişilmez).",
                    "Proxy ayarı: metadata uçları engelli listededir.",
                    "Önizleme: redirect zinciri takip edilmez, ilk adres gösterilir.",
                    "Bilgi: URL şemaları allowlist dışındaysa reddedilir.",
                    "Not: iç ağ çağrıları bu servisten yapılamaz.",
                    "SSS: callback adresleri yalnızca kuyrukta bekler.",
                    "Kılavuz: dış istekler denetim günlüğüne yazılır, çalıştırılmaz.",
                 ]),
    "timing": dict(n=10, absent=["SLEEP(", "SLEEP executed", "query_time=", "SLEEP çalıştı"],
                traps=[
                    "Aylık rapor: ağır toplama ~2 sn sürer (girdiyle alakasız, sabit maliyet).",
                    "Dışa aktarım: büyük CSV üretimi kuyrukta bekler, istek başına sabit.",
                    "Yedekleme: gece 02:00'de çalışır, istek anında üretilmez.",
                    "Dizin listesi: önbellekten 5 ms'de döner (sabit).",
                    "Arşiv indirme: önceden üretilmiş dosya sunulur.",
                    "İstatistik: önbellekli sayaçlar anında döner.",
                    "Rapor: sayfa derleme süresi sabittir, parametreden etkilenmez.",
                    "Bakım: zamanlanmış görevler istek döngüsü dışındadır.",
                    "Not: yavaş sayfa ≠ zaman-tabanlı enjeksiyon (fark: girdi bağımlılığı).",
                    "Bilgi: yanıt süreleri izlenir, eşik aşımı alarm üretir (izleme amaçlı).",
                ]),
    "secret": dict(n=16, absent=["sk_live_mock_123", "live_mock_key_123", "Sup3rS3cret", "DB_PASSWORD=postgres"],
                   traps=[
                    "Örnek: STRIPE_KEY=sk_test_EXAMPLE_0000 (ÖRNEK anahtar, gerçek değil).",
                    "Doküman: AWS anahtarı biçimi AKIAEXAMPLE00000000 (test verisi).",
                    "SDK örneği: api_key=TEST-KEY-DOCS-ONLY-1234 (belge amaçlı).",
                    "Yapılandırma şablonu: DB_PASSWORD=degistir-beni (yer tutucu).",
                    ".env.example: tüm değerler EXAMPLE ile işaretli taslaklardır.",
                    "CI örneği: token=ci_example_token_000 (salt pipeline şablonu).",
                    "Webhook sırrı: whsec_TEST_EXAMPLE (imza doğrulanmaz, örnektir).",
                    "JWT örneği: secret=ornek-imza-anahtari-degil (dokümantasyon).",
                    "Örnek parola: P@ssw0rd! (kılavuzda geçen varsayılan, atanmamış).",
                    "SSH örneği: ssh-ed25519 EXAMPLE... yorum satırı (geçersiz).",
                    "API şeması: password alanı örnek yanıtta yıldızlıdır (***).",
                    "OAuth örneği: client_secret=ornek-istemci-sirri (kayıtlı değil).",
                    "Kupon örneği: ORNEK10 kodu kasıtlı geçersizdir.",
                    "Sertifika: -----BEGIN EXAMPLE CERTIFICATE----- (kendinden test).",
                    "Not: gerçek sırlar kasa servisindedir, dosyada asla yazmaz.",
                    "Uyarı: EXAMPLE/TEST işaretli dizgiler alarm üretmemelidir.",
                   ]),
    "auth": dict(n=14, absent=["admin@example.com", "mock-session", "mock-admin-session", "Temp123!"],
                 traps=[
                    "Giriş yardımı: admin paneli adresi belgede yazmaz (destek kanalıyla).",
                    "Rol açıklaması: admin rolü tanımı sözlük maddesidir.",
                    "Hata mesajı: kullanıcı adı veya şifre hatalı (hangi alan belirtilmez).",
                    "Kilit bilgisi: 5 hatada 15 dk kilit + Retry-After (doğru davranış).",
                    "Oturum: çerezler HttpOnly+Secure+SameSite (başlıkta görünür).",
                    "MFA: TOTP kurulum kılavuzu (kodlar sunucuda üretilir).",
                    "Parola politikası: en az 12 karakter, yönetici sıfırlar.",
                    "OAuth: kayıtlı uygulamalar listesi (yönlendirme allowlist'li).",
                    "Not: 401 ve 403 yanıtları ayırt edici bilgi taşımaz.",
                    "SSS: şifre sıfırlama bağlantısı 15 dakika geçerlidir (tek kullanımlık).",
                    "Destek: hesap kilidi açma kimlik doğrulamasıyla yapılır.",
                    "Güvenlik: başarısız girişler hız sınırlıdır (429 + Retry-After).",
                    "Bilgi: yetkisiz erişim denemeleri günlüğe yazılır.",
                    "Kılavuz: yetki matrisi rol-tablosunda belgelenir.",
                 ]),
    "waf": dict(n=10, absent=["bypassed", "WAF kapalı", "kural dışı bırakıldı", "engelleme kaldırıldı"],
                traps=[
                    "WAF bilgi sayfası: engellenen desenler listesi (statik belge).",
                    "Kural açıklaması: SQLi kuralı #1001 (imza metni, tetiklenmez).",
                    "Kural açıklaması: XSS kuralı #2001 (örnek yük metni karantinada).",
                    "Engel sayfası: istek reddedildi (olay günlüğü, sayaç artmaz).",
                    "Allowlist: kurumsal IP aralıkları salt-okunur listelenir.",
                    "Not: blok sayfası her zaman aynı şablonu döndürür.",
                    "SSS: yanlış pozitif bildirimi formu (inceleme kuyruğu).",
                    "Sürüm: kural seti v4.2 (değişiklik günlüğü ekte).",
                    "Bilgi: denetim modu izler, engellemez (izleme amaçlı).",
                    "Kılavuz: istisna talepleri change-board onayıyla açılır.",
                ]),
    "exposure": dict(n=12, absent=["Sup3rS3cret", "sk_live_mock_123", "DB_PASSWORD=postgres", "PRIVATE KEY"],
                    traps=[
                    ".env.example dosyası (gerçek .env değil, taslak).",
                    "Sürüm bilgisi: app v2.4.1 (yamalı, CVE kaydı kapalı).",
                    "robots.txt açıklaması (bu sayfa hariç gerçek yollar listelemez).",
                    "CHANGELOG: güvenlik düzeltmeleri sürüm notunda.",
                    "API şeması: iç uçlar şemada yoktur (genel şema ayrı).",
                    "Durum sayfası: uptime metrikleri (iç metrik yok).",
                    "Lisans: üçüncü parti bildirimleri (sürüm numaraları yamalı).",
                    "Doküman: yedekleme politikası (konum bilgisi yok).",
                    "Not: kaynak eşleme (source-map) üretimde kapalıdır.",
                    "Bilgi: hata ayıklama uçları üretimde 404 döner.",
                    "SSS: yapılandırma yönetimi kasa servisiyle yapılır.",
                    "Kılavuz: hassas dosya denetimi haftalık taramada yapılır.",
                    ]),
}


def esc(s):
    """JS escHtml karşılığı (tırnak dahil) — present marker'lar escape'li gövdeyle eşleşmeli."""
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))


def build():
    items, rows = [], []
    n = 0
    for cat, spec in CATS.items():
        traps = spec["traps"]
        assert len(traps) == spec["n"], f"{cat}: {len(traps)} != {spec['n']}"
        for i, trap in enumerate(traps, 1):
            n += 1
            gid = f"FP-HELL-{n:03d}"
            slug = f"{cat}-{i:02d}"
            rows.append({
                "id": gid, "method": "GET", "path": f"/fphell/{slug}",
                "category": "FP-Trap", "vuln_type": f"FP hell decoy: {cat} ({i:02d})",
                "expectation": "fp-trap", "test_hint": f"/fphell/{slug}",
                "severity": "info", "difficulty": "fp-hunter", "oracle": None,
                "negative_proof": {
                    "present": ["güvenli sayfa (decoy)", esc(trap[:24])],
                    "absent": spec["absent"],
                },
            })
            items.append({
                "id": gid, "slug": slug, "title": f"Decoy {cat} #{i:02d}",
                "trap": trap, "guard": GUARD,
                "reflect": bool(spec.get("reflect")),
                "present": ["güvenli sayfa (decoy)", esc(trap[:24])],
                "absent": spec["absent"],
            })
    return items, rows


def main():
    items, rows = build()
    print(f"decoys: {len(items)}")
    gt = json.load(open(GT_PATH, encoding="utf-8"))
    have = {g["id"] for g in gt}
    dup = [r["id"] for r in rows if r["id"] in have]
    if dup:
        print(f"DUPLICATE (aborted): {dup}")
        sys.exit(1)
    if APPLY:
        json.dump(items, open(MANIFEST, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        gt.extend(rows)
        json.dump(gt, open(GT_PATH, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"applied: manifest {len(items)} + GT {len(gt)} rows")
    else:
        print("dry-run (use --apply to write)")


if __name__ == "__main__":
    main()

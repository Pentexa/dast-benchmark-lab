const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// Bu endpoint'ler BİLEREK GÜVENLİ ama tarayıcıların sık FP ürettiği kalıpları içerir.
// Amaç: FP oranını ölçmek. İyi tarayıcı bunlara alarm üretmemeli (TN), zayıf tarayıcı FP üretir.

// FP-01: "SQL syntax" metni yardım metninde geçiyor ama sorgu yok
router.get('/search', (req, res) => {
  const q = req.query.q ?? '';
  mark(res, 'FP-SEARCH-01', 'FP-Trap', 'fp-trap');
  res.send(`<h1>Arama</h1><p>Sonuç: ${escHtml(q)}</p>
    <p><i>İpucu: SQL syntax hatası alırsan tırnakları kontrol et (bu sadece yardım metni, gerçek SQL hatası değil).</i></p>`);
});

// FP-02: sayfada "password" kelimesi geçiyor ama sır değil
router.get('/health', (req, res) => {
  mark(res, 'FP-HEALTH-01', 'FP-Trap', 'fp-trap');
  res.json({ status: 'ok', note: 'password policy: min 12 chars (bu bir döküman notu, ifşa değil)', uptime: 12345 });
});

// FP-03: Server header'ında versiyon var ama zafiyet yok — versiyon disclosure FP testi
router.get('/version', (req, res) => {
  mark(res, 'FP-VERSION-01', 'FP-Trap', 'fp-trap');
  res.set('Server', 'nginx/1.25.3');
  res.send('<h1>v2.4.1</h1><p>Changelog: güvenlik düzeltmeleri uygulandı.</p>');
});

// FP-04: reflected input + "admin" kelimesi — tarayıcı IDOR sanabilir ama auth var
router.get('/profile-echo', (req, res) => {
  const nick = req.query.nick ?? 'alice';
  mark(res, 'FP-ECHO-01', 'FP-Trap', 'fp-trap');
  if (String(nick).toLowerCase().includes('<script')) {
    return res.status(400).send('<h1>Engellendi</h1><p>Geçersiz karakter.</p>');
  }
  res.send(`<h1>Profil: ${escHtml(nick)}</h1><p>Role: user (session doğrulandı - mock)</p>`);
});

// FP-05: error sayfasında stack'e benzeyen ama sanitized log referansı
router.get('/error-fake', (req, res) => {
  mark(res, 'FP-ERROR-01', 'FP-Trap', 'fp-trap');
  res.status(500).send('<h1>Bir hata oluştu</h1><p>Referans: ERR-99182. Detaylar loglandı, kullanıcıya gösterilmiyor.</p>');
});

// FP-06: SDK dokümantasyonundaki ÖRNEK anahtar (gerçek değil) — secret-scanner FP tuzağı
router.get('/sdk-example', (req, res) => {
  mark(res, 'FP-SDK-01', 'FP-Trap', 'fp-trap');
  res.set('X-Doc-Example', 'true');
  res.send(`<h1>SDK Dokümantasyonu</h1><pre>// ÖRNEK (çalışmaz, dokümantasyon placeholder):
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</pre><p>Yukarıdakiler AWS'nin resmi dokümantasyon örnek anahtarlarıdır.</p>`);
});

// FP-07: WAF log satırını bilgi amaçlı gösteren güvenli sayfa — keyword FP tuzağı
router.get('/waf-block', (req, res) => {
  mark(res, 'FP-WAF-01', 'FP-Trap', 'fp-trap');
  res.send(`<h1>Güvenlik duvarı durumu: aktif</h1><p>Son engellenen (bilgi): SQL injection denemesi, XSS denemesi — ikisi de engellendi.</p><p>Bu sayfa statik bilgilendirme metnidir, kullanıcı girdisi yansıtmaz.</p>`);
});

// FP-08: nonce'lı inline script + sıkı CSP — "inline script" FP tuzağı
router.get('/csp-inline', (req, res) => {
  mark(res, 'FP-CSP-01', 'FP-Trap', 'fp-trap');
  const nonce = 'mock-nonce-abc123';
  res.set('Content-Security-Policy', `default-src 'self'; script-src 'nonce-${nonce}'`);
  res.send(`<h1>CSP güvenli sayfa</h1><script nonce="${nonce}">document.body.dataset.ok="1";</script><p>Inline script nonce + CSP ile kilitli.</p>`);
});

// FP-09: şemada geçen ama yanıta asla konmayan "passwordHash" dokümantasyonu
router.get('/api-docs', (req, res) => {
  mark(res, 'FP-APIDOCS-01', 'FP-Trap', 'fp-trap');
  if (!req.get('X-User-Id')) return res.status(401).json({ error: 'auth gerekli' });
  res.json({ user: { id: 1, username: 'alice' }, _schema_note: 'User.passwordHash alanı şemada belgelenir ama bu endpoint asla dönmez' });
});

// FP-10: tek kullanımlık kupon DOĞRU uygulanmış — reuse denemesi 410 yer
const fpUsed = new Set();
router.post('/coupon-once', (req, res) => {
  mark(res, 'FP-COUPON-01', 'FP-Trap', 'fp-trap');
  const code = String((req.body || {}).code || 'ONCE10');
  if (fpUsed.has(code)) return res.status(410).json({ error: 'kupon zaten kullanıldı' });
  fpUsed.add(code);
  res.json({ ok: true, note: 'tek kullanım uygulandı, tekrarı 410' });
});

// FP-11: doğru kilit davranışı — "kilitlendi" mesajı zafiyet değil, kontroldür
router.post('/login-lock', (req, res) => {
  mark(res, 'FP-LOCK-01', 'FP-Trap', 'fp-trap');
  res.status(401).json({ error: 'kullanıcı adı veya şifre hatalı', note: '5 hatada 15 dk kilit + Retry-After (doğru davranış, alarm üretilmemeli)' });
});

// FP-12: MEŞRU yavaş sayfa (2 sn rapor üretimi) — time-based SQLi FP tuzağı.
// Her istekte sabit ~2 sn sürer; payload'dan bağımsız. İyi araç zaman farkı
// bulamaz (TN), körü körüne "gecikme = SQLi" diyen FP üretir.
router.get('/slow-report', (req, res) => {
  mark(res, 'FP-SLOW-01', 'FP-Trap', 'fp-trap');
  const t0 = Date.now();
  setTimeout(() => {
    res.send(`<h1>Aylık rapor</h1><p>üretim süresi: ${Date.now() - t0}ms (ağır aggregation mock — kullanıcı girdisiyle alakasız)</p>`);
  }, 2000);
});

module.exports = router;

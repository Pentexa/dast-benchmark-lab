const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// CSRF token store (mock)
let validToken = 'mock-csrf-abc123';

// ---------- CSRF: GET ile para transferi (VULN) ----------
router.get('/transfer', (req, res) => {
  mark(res, 'CSRF-01', 'A01-AccessControl', 'vulnerable');
  const { to, amount } = req.query;
  if (to && amount) {
    return res.send(`<h1>Transfer tamamlandı!</h1><p>${escHtml(amount)} TL -> ${escHtml(to)}</p><p>CSRF koruması yok, GET ile state-changing!</p>`);
  }
  res.send('<h1>Transfer</h1><form><input name="to" placeholder="alıcı"/><input name="amount" placeholder="tutar"/><button>Gönder</button></form>');
});

router.get('/token', (req, res) => {
  mark(res, 'CSRF-TOKEN', 'A01-AccessControl', 'secure');
  res.send(`Token: <code>${validToken}</code>`);
});
router.post('/transfer-secure', express.urlencoded({ extended: true }), (req, res) => {
  mark(res, 'CSRF-01-SECURE', 'A01-AccessControl', 'secure');
  if (req.body._csrf !== validToken) return res.status(403).send('<h1>403 CSRF token geçersiz</h1>');
  res.send(`<h1>Güvenli transfer tamamlandı</h1><p>${escHtml(req.body.amount)} -> ${escHtml(req.body.to)}</p>`);
});

// ---------- CORS ----------
// VULN: *
router.get('/cors', (req, res) => {
  mark(res, 'CORS-01', 'A05-Misconfig', 'vulnerable');
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Credentials', 'true');
  res.json({ user: 'alice', email: 'alice@example.com', pan: '4111 1111 1111 1111' });
});
router.get('/cors-secure', (req, res) => {
  mark(res, 'CORS-01-SECURE', 'A05-Misconfig', 'secure');
  res.set('Access-Control-Allow-Origin', 'https://app.example.com');
  res.set('Vary', 'Origin');
  res.json({ user: 'alice', email: 'alice@example.com' });
});

// ---------- Clickjacking ----------
router.get('/clickjack', (req, res) => {
  mark(res, 'CLICK-01', 'A05-Misconfig', 'vulnerable');
  res.send('<h1>Hesap sil</h1><form><button>Hesabı kalıcı sil</button></form><p>X-Frame-Options yok -> iframe ile tıklama hırsızlığı mümkün</p>');
});

// ---------- File upload ----------
router.get('/upload', (req, res) => {
  mark(res, 'UPL-01', 'A04-InsecureDesign', 'vulnerable');
  res.send(`<h1>Dosya yükle (korumasız)</h1><form method="POST" action="/logic/upload" enctype="multipart/form-data"><input type="file" name="f"/><button>Yükle</button></form><p>Uzantı kontrolü yok: .php, .svg, .html yüklenebilir</p>`);
});
router.post('/upload', express.text({ type: '*/*', limit: '1mb' }), (req, res) => {
  mark(res, 'UPL-01', 'A04-InsecureDesign', 'vulnerable');
  const fname = req.get('X-Filename') || 'shell.php';
  const ext = fname.split('.').pop().toLowerCase();
  // VULN: her şeyi kabul et
  res.send(`<h1>Yüklendi!</h1><p>/uploads/${escHtml(fname)} erişilebilir</p><p>Ext: ${escHtml(ext)} kontrol edilmedi. ${ext === 'php' ? 'PHP çalıştırılabilir!' : ''} ${ext === 'svg' ? 'SVG içinde &lt;script&gt; çalışabilir!' : ''}</p>`);
});
router.post('/upload-secure', express.text({ type: '*/*', limit: '1mb' }), (req, res) => {
  mark(res, 'UPL-01-SECURE', 'A04-InsecureDesign', 'secure');
  const fname = req.get('X-Filename') || 'a.png';
  const ext = fname.split('.').pop().toLowerCase();
  if (!['png', 'jpg', 'jpeg'].includes(ext)) return res.status(400).send('<h1>Engellendi</h1><p>Sadece png/jpg.</p>');
  res.send('<h1>Güvenli yüklendi</h1><p>Content-type doğrulandı, rastgele isim + exec bit yok.</p>');
});

// ---------- Deserialization (mock) ----------
router.post('/deserialize', express.text({ type: '*/*' }), (req, res) => {
  mark(res, 'DESER-01', 'A08-Integrity', 'vulnerable');
  const body = String(req.body || '');
  if (body.includes('__proto__') || body.includes('constructor') || body.includes('$where') || body.includes('rce') || body.includes('child_process')) {
    return res.send('<h1>Deserialize edildi (mock RCE!)</h1><pre>uid=33(www-data) — prototype pollution / node-serialize gadget tetiklendi (simülasyon)</pre>');
  }
  res.send('<h1>Deserialize demo</h1><p>JSON gönder: {"rce":"id"}</p>');
});

// ---------- Rate limit yok / business logic ----------
let couponUsed = {};
router.get('/coupon', (req, res) => {
  mark(res, 'BIZ-01', 'A04-InsecureDesign', 'vulnerable');
  const code = req.query.code ?? 'HOSGELDIN10';
  // VULN: kupon sınırsız kullanılabiliyor, negatif tutar kabul ediliyor
  res.send(`<h1>Kupon uygulandı: ${escHtml(code)}</h1><p>İndirim: -10 TL (kullanım sayacı yok, tekrar kullanılabilir)</p>`);
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => { couponUsed = {}; });

module.exports = router;

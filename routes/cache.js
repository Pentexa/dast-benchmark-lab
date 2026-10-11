const express = require('express');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// Güncel: Host zehirlenmesi + cache deception + method override + request smuggling (mock).
// DAST'lerin header-fuzz ve cache-oracle kontrolleri bunlarla ölçülür.

// ---------- Reset link X-Forwarded-Host ile zehirleniyor (VULN) ----------
router.get('/reset-link', (req, res) => {
  mark(res, 'CACHE-HOST-01', 'A05-CacheSmuggle', 'vulnerable');
  const host = req.get('X-Forwarded-Host') || req.get('Host') || 'app.example.com';
  res.send(`<h1>Şifre sıfırla</h1><p><a href="https://${escHtml(host)}/auth/reset?token=ABC123">Şifreni sıfırla</a></p><p>Link host'u doğrulanmadan üretildi — X-Forwarded-Host: evil.com dene (zehirli link kurbana gider).</p>`);
});

// ---------- Web cache deception: PII cache'lenebilir yanıtla (VULN) ----------
router.get('/account/:id.css', (req, res) => {
  mark(res, 'CACHE-DECEPT-01', 'A05-CacheSmuggle', 'vulnerable');
  const u = users.find(x => String(x.id) === String(req.params.id)) || users[0];
  res.set({ 'Cache-Control': 'public, max-age=600', 'X-Cache': 'HIT (mock CDN)', 'Content-Type': 'text/css' });
  res.send(`/* cached stylesheet (mock) */\n/* LEAK: ${u.username} ${u.email} TCKN=${u.tckn} IBAN=${u.iban} */\nbody{color:#111}`);
});
router.get('/account-secure/:id', (req, res) => {
  mark(res, 'CACHE-DECEPT-01-SECURE', 'A05-CacheSmuggle', 'secure');
  res.set({ 'Cache-Control': 'private, no-store', 'Vary': 'Cookie, Authorization' });
  res.json({ id: req.params.id, note: 'PII asla cachelenmez' });
});

// ---------- Unkeyed header yansıması + cache (XFF poison) ----------
// X-Forwarded-For yanıta yansıyor VE yanıt public cache'leniyor.
router.get('/echo', (req, res) => {
  mark(res, 'CACHE-XFF-01', 'A05-CacheSmuggle', 'vulnerable');
  const xff = req.get('X-Forwarded-For') || 'bilinmiyor';
  res.set({ 'Cache-Control': 'public, max-age=300', 'X-Cache': 'MISS (mock CDN)' });
  res.send(`<h1>Ziyaretçi: ${xff}</h1><p>Header X-Forwarded-For: &lt;script&gt;alert(1)&lt;/script&gt; dene — yanıt cache'e girer!</p>`);
});

// ---------- HTTP method override ile yetki atlatma (VULN) ----------
// Gerçek dünya: WAF/route sadece DELETE'i korur, POST+override ile geçilir.
router.post('/method', (req, res) => {
  mark(res, 'HTTP-METHOD-01', 'A05-CacheSmuggle', 'vulnerable');
  const over = req.get('X-HTTP-Method-Override') || req.query._method || '';
  if (String(over).toUpperCase() === 'DELETE') {
    return res.json({ ok: true, note: 'KULLANICI SİLİNDİ (mock)! POST + X-HTTP-Method-Override: DELETE ile yetkisiz silme' });
  }
  res.json({ note: 'X-HTTP-Method-Override: DELETE header ile dene' });
});

// ---------- Request smuggling oracle (mock — gerçek desync YOK) ----------
// Not: Node aykırı CL+TE'yi 400'ler (doğru). Ölçülen yüzeysellik:
//  (1) chunked TE kabul ediliyor mu? (2) yinelenen CL nasıl birleştiriliyor?
router.post('/smuggle', express.text({ type: '*/*' }), (req, res) => {
  mark(res, 'HTTP-SMUG-01', 'A05-CacheSmuggle', 'vulnerable');
  const te = req.get('Transfer-Encoding') || '';
  const cl = req.get('Content-Length') || '';
  if (te) {
    return res.send(`<h1>Smuggle oracle (mock)</h1><p>Transfer-Encoding: <code>${escHtml(te)}</code> KABUL EDİLDİ, gövde işlendi (chunked desync yüzeyi açık — öndeki proxy farklı yorumlayabilir).</p>`);
  }
  if (cl.includes(',')) {
    return res.send(`<h1>Smuggle oracle (mock)</h1><p>Yinelenen Content-Length birleştirildi: <code>${escHtml(cl)}</code> — ilk/sonu alan backend'ler ayrışır (klasik).</p>`);
  }
  res.send('<h1>Smuggle oracle (mock)</h1><p>Transfer-Encoding: chunked ile (CL’siz, ham soket) gönder dene; ya da çift Content-Length.</p>');
});

module.exports = router;

const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// Sınır (edge) karmaşası: parser-farkları, yönlendirme-zinciri, header-güvenleri.
// DAST'lerin "aynı girdiye farklı yorum" bulguları burada ölçülür. Outbound YOK, hepsi mock.

// ---------- SSRF bypass seti: tek mantık, ayrı path'ler ----------
function ssrfMock(id, hint) {
  return (req, res) => {
    const url = String(req.query.url || '');
    mark(res, id, 'A10-SSRF', 'vulnerable');
    if (!url) return res.send(`<h1>Önizleme</h1><p>${hint}</p>`);
    const low = url.toLowerCase();
    const internal =
      /169\.254\.|localhost|127\.|metadata|10\.|192\.168|0\.0\.0\.0|\[::/.test(low) ||
      /^https?:\/\/2130706433[\/:]?/.test(low) ||           // 127.0.0.1 decimal
      /^https?:\/\/0x7f\.0x0\.0x0\.0x1/i.test(low) ||        // 127.0.0.1 hex
      /^https?:\/\/[^\/@]+@[^\/]+/.test(low) ||              // user@host confusion
      /#@trusted|@trusted\.com/i.test(low);                  // fragment/credential hilesi
    if (internal) {
      return res.send(`<h1>Fetched (mock)</h1><p>URL: <code>${escHtml(url)}</code></p><pre>role: admin\nsecret: MOCK-SSRF-LEAK-12345</pre><p>BYPASS GEÇTİ!</p>`);
    }
    res.send(`<h1>Fetched (mock)</h1><p>URL: <code>${escHtml(url)}</code></p><pre>harici içerik</pre>`);
  };
}
router.get('/dec', ssrfMock('EDGE-SSRF-DEC', '?url=http://2130706433/ dene (desimal 127.0.0.1)'));
router.get('/zero', ssrfMock('EDGE-SSRF-ZERO', '?url=http://0.0.0.0/ dene'));
router.get('/at', ssrfMock('EDGE-SSRF-AT', '?url=http://trusted.com@169.254.169.254/ dene (credential confusion)'));
router.get('/frag', ssrfMock('EDGE-SSRF-FRAG', '?url=http://evil.com#@trusted.com/ dene (fragment hilesi)'));
// Redirect-zinciri: allowlist ilk URL'yi geçirir, hedef internal'a döner (mock takip)
router.get('/redir', (req, res) => {
  const url = String(req.query.url || '');
  mark(res, 'EDGE-SSRF-REDIR', 'A10-SSRF', 'vulnerable');
  if (!url) return res.send('<h1>Önizleme (redirect takipli)</h1><p>?url=https://short.example/abc123 dene — hedef 169.254.169.254’e dönüyor (mock), takip durdurulmuyor!</p>');
  if (/short\.example|r\.example|tinyurl|bit\.ly/i.test(url.toLowerCase())) {
    return res.send(`<h1>Fetched (redirect sonrası, mock)</h1><p>301 -> http://169.254.169.254/ takip edildi!</p><pre>role: admin\nsecret: MOCK-SSRF-LEAK-12345</pre>`);
  }
  res.send(`<h1>Fetched (mock)</h1><p>${escHtml(url)}</p>`);
});
router.get('/fetch-secure', (req, res) => {
  const url = String(req.query.url || '');
  mark(res, 'EDGE-SSRF-SECURE', 'A10-SSRF', 'secure');
  let u;
  try { u = new URL(url); } catch { return res.status(400).send('geçersiz URL'); }
  if (u.username || u.password || u.hash.includes('@')) return res.status(400).send('credential/fragment hilesi engellendi');
  if (!['example.com', 'trusted.com'].includes(u.hostname)) return res.status(400).send('allowlist dışı');
  if (/^(\d+\.){3}\d+$/.test(u.hostname) || u.hostname.includes(':')) return res.status(400).send('IP literal yasak');
  res.send(`<h1>Güvenli fetch</h1><p>${escHtml(url)} (redirect takip edilmez, DNS rebinding penceresi kapalı — mock)</p>`);
});

// ---------- Login sonrası returnUrl (açık yönlendirme varyantı) ----------
router.get('/login-return', (req, res) => {
  const back = String(req.query.returnUrl ?? '/dashboard');
  mark(res, 'EDGE-RET-01', 'A01-AccessControl', 'vulnerable');
  res.send(`<h1>Giriş başarılı (mock)</h1><p><a href="${escHtml(back)}">Devam et</a></p><script>setTimeout(()=>location.href=${JSON.stringify(back)},500)</script><p>?returnUrl=https://evil.com dene</p>`);
});

// ---------- Çift parametre redirect (HPP: sonuncu kazanır) ----------
router.get('/go2', (req, res) => {
  mark(res, 'EDGE-DOUBLE-01', 'A01-AccessControl', 'vulnerable');
  let next = req.query.next ?? '/';
  if (Array.isArray(next)) next = next[next.length - 1];
  res.redirect(String(next).replace(/[^\x20-\x7E]/g, '?'));
});

// ---------- X-Original-URL ile /admin'e erişim (WAF/route bypass klasiği) ----------
router.get('/panel', (req, res) => {
  mark(res, 'EDGE-ORIG-01', 'A01-AccessControl', 'vulnerable');
  const orig = String(req.get('X-Original-URL') || req.get('X-Rewrite-URL') || '');
  if (orig.startsWith('/admin')) {
    return res.send(`<h1>Admin panel (bypass!)</h1><p>X-Original-URL: <code>${escHtml(orig)}</code> backend'e /admin gibi yorumlatıldı.</p><pre>kullanıcılar: alice, bob, admin</pre>`);
  }
  res.send('<h1>Kullanıcı paneli</h1><p>Header X-Original-URL: /admin/users dene</p>');
});

// ---------- Localhost kapısı: sadece header'a bakılıyor (proxy arkası klasiği) ----------
router.get('/internal', (req, res) => {
  mark(res, 'EDGE-LOCAL-01', 'A01-AccessControl', 'vulnerable');
  const fwd = String(req.get('X-Forwarded-For') || req.get('X-Real-IP') || '');
  if (fwd.includes('127.0.0.1') || fwd.includes('localhost')) {
    return res.send(`<h1>Internal stats</h1><pre>uptime: 99 gün\nDB: db-internal (Sup3rS3cret! ile bağlı — mock)</pre><p>X-Forwarded-For: 127.0.0.1 ile girildi (IP doğrulanmadı!)</p>`);
  }
  res.status(403).send('<h1>403</h1><p>sadece localhost (ipucu: proxy header’ları dene)</p>');
});

// ---------- TRACE metodu açık (XST: çerez yankılanır) ----------
router.use('/trace', (req, res, next) => {
  if (req.method !== 'TRACE') return res.status(405).send('sadece TRACE');
  mark(res, 'EDGE-TRACE-01', 'A05-Misconfig', 'vulnerable');
  res.type('message/http');
  res.send(`TRACE /edge/trace HTTP/1.1\r\nCookie: ${req.get('Cookie') || '(yok)'}\r\n\r\n[yanıt gövdede çerez yankılandı — HttpOnly çerez XST ile okunur!]`);
});

// ---------- Kök ifşa yardımcıları (server.js'ten bağlanır) ----------
function crossdomain(req, res) {
  mark(res, 'EDGE-XDOM-01', 'A05-Misconfig', 'vulnerable');
  res.type('text/xml').send('<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*" secure="false"/></cross-domain-policy>');
}
function clientaccess(req, res) {
  mark(res, 'EDGE-XDOM-01', 'A05-Misconfig', 'vulnerable');
  res.type('text/xml').send('<?xml version="1.0"?><access-policy><cross-domain-access><policy><allow-from http-methods="*"><domain uri="*"/></allow-from></policy></cross-domain-access></access-policy>');
}
function staticConfig(req, res) {
  mark(res, 'EDGE-CFG-01', 'A05-Exposure', 'vulnerable');
  res.type('application/javascript').send('// build artifact (mock)\nwindow.APP_CONFIG = { STRIPE_KEY: "pk_live_mock_123", API_SECRET: "secret-abc-123", SENTRY_DSN: "https://x@sentry.io/1" };');
}

module.exports = router;
module.exports.extra = { crossdomain, clientaccess, staticConfig };

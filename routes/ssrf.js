const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

const INTERNAL = ['169.254.169.254', '127.0.0.1', 'localhost', 'metadata.google.internal', '10.0.0.5'];

// ---------- SSRF ----------
// VULN: allowlist yok, internal'a istek atılabiliyor (mock fetch — gerçek istek YOK)
router.get('/', (req, res) => {
  const url = req.query.url ?? '';
  mark(res, 'SSRF-01', 'A10-SSRF', 'vulnerable');
  if (!url) return res.send('<h1>URL önizleme</h1><form><input name="url" size="50" placeholder="https://example.com"/><button>Fetch</button></form><p>?url=http://169.254.169.254/latest/meta-data/ dene</p>');
  const low = String(url).toLowerCase();
  const isInternal = INTERNAL.some(h => low.includes(h));
  if (isInternal) {
    return res.send(`<h1>Fetched (mock)</h1><p>URL: <code>${escHtml(url)}</code></p><pre>ami-id: ami-mock123\nrole: admin\nsecret-access-key: MOCK-SSRF-LEAK-12345</pre>`);
  }
  res.send(`<h1>Fetched (mock)</h1><p>URL: <code>${escHtml(url)}</code></p><pre>&lt;html&gt;mock external content&lt;/html&gt;</pre>`);
});

router.get('/secure', (req, res) => {
  const url = req.query.url ?? '';
  mark(res, 'SSRF-01-SECURE', 'A10-SSRF', 'secure');
  const low = String(url).toLowerCase();
  if (INTERNAL.some(h => low.includes(h)) || !/^https:\/\/(example\.com|trusted\.com)\//.test(String(url))) {
    return res.status(400).send('<h1>Engellendi</h1><p>Allowlist dışı URL / internal IP yasak.</p>');
  }
  res.send(`<h1>Fetched güvenli</h1><p>${escHtml(url)}</p>`);
});

// ---------- Open Redirect ----------
// VULN: ?next=https://evil.com
router.get('/redirect', (req, res) => {
  const next = req.query.next ?? '/';
  mark(res, 'REDIR-01', 'A01-AccessControl', 'vulnerable');
  res.redirect(String(next).replace(/[^\x20-\x7E]/g, '?')); // header latin1-safe
});
router.get('/redirect-secure', (req, res) => {
  const next = req.query.next ?? '/';
  mark(res, 'REDIR-01-SECURE', 'A01-AccessControl', 'secure');
  if (!['/', '/dashboard', '/xss/stored-secure'].includes(String(next))) {
    return res.status(400).send('<h1>Geçersiz yönlendirme</h1>');
  }
  res.redirect(String(next));
});

module.exports = router;

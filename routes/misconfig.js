const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// ---------- Security headers eksik (VULN: bilerek header koymuyoruz) ----------
router.get('/headers', (req, res) => {
  mark(res, 'MIS-HDR-01', 'A05-Misconfig', 'vulnerable');
  res.removeHeader('X-Content-Type-Options');
  res.send(`<h1>Güvensiz sayfa</h1><p>No CSP, no HSTS, no X-Frame-Options, Server header verbose.</p>`);
});
router.get('/headers-secure', (req, res) => {
  mark(res, 'MIS-HDR-01-SECURE', 'A05-Misconfig', 'secure');
  res.set({
    'Content-Security-Policy': "default-src 'self'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer'
  });
  res.send('<h1>Güvenli sayfa</h1><p>Tüm headerlar mevcut.</p>');
});

// ---------- Verbose error ----------
router.get('/error', (req, res) => {
  mark(res, 'MIS-ERR-01', 'A05-Misconfig', 'vulnerable');
  const cause = req.query.cause ?? 'ok';
  if (cause === 'sql') {
    return res.status(500).send(`<h1>500</h1><pre>TypeError: Cannot read properties of null\n    at /var/www/app/controllers/user.js:42:15\n    at Layer.handle [as handle_request] (/var/www/app/node_modules/express/lib/router/layer.js:95:5)\nSQL: SELECT * FROM users WHERE id='${escHtml(req.query.id || "1' OR '1'='1")}'\nDB host: db-internal.example.com, user: dbadmin</pre>`);
  }
  res.send('<h1>OK</h1><p>?cause=sql&497 id= dene</p>'.replace('497', 'id='));
});
router.get('/error-secure', (req, res) => {
  mark(res, 'MIS-ERR-01-SECURE', 'A05-Misconfig', 'secure');
  res.status(500).send('<h1>Bir hata oluştu</h1><p>Referans: ERR-48271</p>');
});

// ---------- Directory listing ----------
router.get('/dir-listing/', (req, res) => {
  mark(res, 'MIS-DIR-01', 'A05-Misconfig', 'vulnerable');
  res.send(`<h1>Index of /backups/</h1><ul><li><a href="/misconfig/dir-listing/backup.zip">backup.zip</a></li><li><a href="/misconfig/dir-listing/db.sql">db.sql</a></li><li><a href="/misconfig/dir-listing/.env">.env</a></li></ul>`);
});
router.get('/dir-listing/:file', (req, res) => {
  mark(res, 'MIS-DIR-01', 'A05-Misconfig', 'vulnerable');
  if (req.params.file === '.env') return res.type('text/plain').send('DB_PASSWORD=Sup3rS3cret!\nSECRET_KEY=topsecret');
  res.type('text/plain').send(`MOCK backup içeriği: ${req.params.file}`);
});

// ---------- Default creds sayfası ipucu ----------
router.get('/default-creds', (req, res) => {
  mark(res, 'MIS-DEFAULT-01', 'A05-Misconfig', 'vulnerable');
  res.send('<h1>Tomcat Manager (mock)</h1><p>admin:admin varsayılan girişi aktif</p><form><input name="u"/><input name="p" type="password"/><button>Login</button></form>');
});

module.exports = router;

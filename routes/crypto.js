const express = require('express');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// ---------- Hassas veri ifşası ----------
// VULN: PAN açık, CVV açık
router.get('/creditcard', (req, res) => {
  mark(res, 'CRYPTO-PAN-01', 'A02-Crypto', 'vulnerable');
  const u = users.find(x => String(x.id) === String(req.query.user ?? '1'));
  res.send(`<h1>Ödeme bilgisi</h1><p>Kart: ${(u || {}).pan}</p><p>CVV: 123</p><p>Full PAN cleartext dönüyor (PCI-DSS ihlali)</p>`);
});
router.get('/creditcard-secure', (req, res) => {
  mark(res, 'CRYPTO-PAN-01-SECURE', 'A02-Crypto', 'secure');
  const u = users.find(x => String(x.id) === String(req.query.user ?? '1'));
  const masked = (u?.pan || '').replace(/\d(?=\d{4})/g, '*');
  res.send(`<h1>Ödeme bilgisi (maskeli)</h1><p>Kart: ${escHtml(masked)}</p>`);
});

// VULN: debug=true ile env leak
router.get('/debug', (req, res) => {
  mark(res, 'CRYPTO-DEBUG-01', 'A02-Crypto', 'vulnerable');
  if (req.query.debug === 'true') {
    return res.send(`<h1>Debug</h1><pre>DB_PASSWORD=Sup3rS3cret!\nAWS_SECRET=AKIA-MOCK-EXAMPLE\nJWT_SECRET=mock-secret-key\nNODE_ENV=production (ama debug açık!)</pre>`);
  }
  res.send('<h1>Uygulama</h1><p>?debug=true dene</p>');
});

// VULN: .git ifşası
router.get('/.git/config', (req, res) => {
  mark(res, 'CRYPTO-GIT-01', 'A02-Crypto', 'vulnerable');
  res.type('text/plain').send('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/ornek/gizli-repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*');
});

// ---------- Güvensiz saklama: MD5 / base64 "şifreleme" ----------
router.get('/hash', (req, res) => {
  const pw = req.query.password ?? '123456';
  mark(res, 'CRYPTO-HASH-01', 'A02-Crypto', 'vulnerable');
  const crypto = require('crypto');
  const md5 = crypto.createHash('md5').update(String(pw)).digest('hex');
  res.send(`<h1>Kullanıcı kaydı</h1><p>MD5(${escHtml(pw)}) = <code>${md5}</code> (salt yok, MD5 zayıf)</p>`);
});

module.exports = router;

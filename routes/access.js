const express = require('express');
const fs = require('fs');
const path = require('path');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// Mock dosya deposu
const FILES = {
  'not.txt': 'Bu herkese açık bir nottur.',
  'public.txt': 'Public bilgi.',
  'secrets.txt': 'MOCK SECRET: db_password=Sup3rS3cret! (sadece traversal ile erişilmeli)'
};

// ---------- IDOR ----------
// VULN: session kontrolü yok
router.get('/idor', (req, res) => {
  mark(res, 'AC-IDOR-01', 'A01-AccessControl', 'vulnerable');
  const u = users.find(x => String(x.id) === String(req.query.user_id ?? '1'));
  if (!u) return res.status(404).send('Kullanıcı yok');
  res.send(`<h1>Profil</h1><p>Username: ${escHtml(u.username)}</p><p>Email: ${escHtml(u.email)}</p><p>PAN: ${escHtml(u.pan)}</p><p>Not: ?user_id=2 veya 99 dene (auth yok!)</p>`);
});

// SECURE: sadece kendi profili (mock session: ?as=1)
router.get('/idor-secure', (req, res) => {
  mark(res, 'AC-IDOR-01-SECURE', 'A01-AccessControl', 'secure');
  const as = String(req.query.as ?? '1');
  const target = String(req.query.user_id ?? as);
  if (as !== target) return res.status(403).send('<h1>403 Yasak</h1><p>Başkasının profiline erişemezsin.</p>');
  const u = users.find(x => String(x.id) === target);
  if (!u) return res.status(404).send('Kullanıcı yok');
  res.send(`<h1>Profil (güvenli)</h1><p>Username: ${escHtml(u.username)}</p>`);
});

// ---------- Path Traversal ----------
// VULN: ?file=../../secrets
router.get('/traversal', (req, res) => {
  const f = req.query.file ?? 'public.txt';
  mark(res, 'AC-TRAV-01', 'A01-AccessControl', 'vulnerable');
  const norm = String(f).replace(/%2e/gi, '.').replace(/%2f/gi, '/').replace(/%5c/gi, '\\');
  if (norm.includes('../') || norm.includes('..\\') || norm.toLowerCase().includes('/etc/passwd')) {
    if (norm.toLowerCase().includes('/etc/passwd')) {
      return res.type('text/plain').send('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin');
    }
    const base = path.basename(norm);
    if (FILES[base]) return res.type('text/plain').send(FILES[base] + '\n\n[traversal ile okundu: ' + norm + ']');
    return res.type('text/plain').send('root:x:0:0:root:/root:/bin/bash\n[traversal mock çıktısı]');
  }
  res.type('text/plain').send(FILES[f] || 'Dosya bulunamadı');
});

router.get('/traversal-secure', (req, res) => {
  const f = req.query.file ?? 'public.txt';
  mark(res, 'AC-TRAV-01-SECURE', 'A01-AccessControl', 'secure');
  const base = path.basename(String(f));
  if (!/^[a-z0-9]+\.txt$/i.test(base)) return res.status(400).send('Geçersiz dosya adı');
  if (!['not.txt', 'public.txt'].includes(base)) return res.status(403).send('Bu dosyaya erişim yasak');
  res.type('text/plain').send(FILES[base]);
});

// ---------- Forced browsing ----------
// VULN: /admin auth'suz
router.get('/admin', (req, res) => {
  mark(res, 'AC-FORCED-01', 'A01-AccessControl', 'vulnerable');
  res.send('<h1>Admin Panel</h1><p>Tüm kullanıcılar:</p><pre>' + escHtml(JSON.stringify(users, null, 2)) + '</pre>');
});

router.get('/admin-secure', (req, res) => {
  mark(res, 'AC-FORCED-01-SECURE', 'A01-AccessControl', 'secure');
  if (req.get('X-Role') !== 'admin') return res.status(403).send('<h1>403</h1><p>Admin gerekli. (Header X-Role: admin gönder)</p>');
  res.send('<h1>Admin Panel (güvenli)</h1>');
});

module.exports = router;

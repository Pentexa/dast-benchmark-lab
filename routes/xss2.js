const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.2 — Cross-role stored/blind XSS: user yazar, admin/moderatör okur.
// Tek istekle sömürülemez; callback doğrulaması gerekir.

// --- rol-farklı stored XSS deposu ---
const posts = [{ id: 1, user: 'alice', message: 'ilk mesaj (temiz)' }];
let postSeq = 2;
router.post('/post', (req, res) => {
  mark(res, 'XSS2-STORED-ROLE-01', 'A03-XSS', 'vulnerable');
  const { user = 'anon', message = '' } = req.body || {};
  const id = postSeq++;
  posts.push({ id, user, message }); // HAM saklanıyor
  res.status(201).json({ id, note: `kaydedildi — admin görünümü: GET /xss2/view?id=${id}&as=admin` });
});
// VULN: admin görünümü kaçışsız (user rolüyle yazılan admin rolüyle yürütülür)
router.get('/view', (req, res) => {
  mark(res, 'XSS2-STORED-ROLE-01', 'A03-XSS', 'vulnerable');
  const p = posts.find(x => String(x.id) === String(req.query.id || '1'));
  if (!p) return res.status(404).send('yok');
  res.send(`<h1>Admin mesaj görünümü (as=${escHtml(req.query.as || 'admin')})</h1><div>${p.message}</div>`);
});
// SECURE: aynı depo, kaçışlı görünüm
router.get('/view-secure', (req, res) => {
  mark(res, 'XSS2-STORED-ROLE-01-SECURE', 'A03-XSS', 'secure');
  const p = posts.find(x => String(x.id) === String(req.query.id || '1'));
  if (!p) return res.status(404).send('yok');
  res.send(`<h1>Admin mesaj görünümü</h1><div>${escHtml(p.message)}</div>`);
});

// --- kör (blind) moderasyon kuyruğu: callback dışa yazılır ---
const modqueue = [];
router.post('/blindreply', (req, res) => {
  mark(res, 'XSS2-BLIND-ROLE-01', 'A03-XSS', 'vulnerable');
  const { message = '', callback = '' } = req.body || {};
  modqueue.push({ message, callback });
  res.status(201).json({ ok: true, note: 'moderatör kuyruğuna alındı: GET /xss2/modqueue?role=moderator' });
});
// VULN: moderatör görünümü callback'i script-src olarak gömer (kör tetik)
router.get('/modqueue', (req, res) => {
  mark(res, 'XSS2-BLIND-ROLE-01', 'A03-XSS', 'vulnerable');
  const items = modqueue.map(m => `<div>${m.message}<script src="${m.callback}"></script></div>`).join('') || '<p>kuyruk boş</p>';
  res.send(`<h1>Moderatör kuyruğu (role=${escHtml(req.query.role || '?')})</h1>${items}`);
});
// SECURE: callback allowlist dışıysa script gömülmez
router.get('/modqueue-secure', (req, res) => {
  mark(res, 'XSS2-BLIND-ROLE-01-SECURE', 'A03-XSS', 'secure');
  const items = modqueue.map(m => {
    const ok = /^\/oob\/[a-z0-9-]+$/i.test(m.callback || '');
    return `<div>${escHtml(m.message)}${ok ? `<script src="${m.callback}"></script>` : '<!-- harici callback engellendi -->'}</div>`;
  }).join('') || '<p>kuyruk boş</p>';
  res.send(`<h1>Moderatör kuyruğu</h1>${items}`);
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => {
  posts.length = 0; posts.push({ id: 1, user: 'alice', message: 'ilk mesaj (temiz)' }); postSeq = 2;
  modqueue.length = 0;
});

module.exports = router;

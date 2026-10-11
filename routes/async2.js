const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.8 — Asenkron second-order enjeksiyon: giriş ayrı, tetik ayrı ZAMANDA.
// submit kuyruğa yazar (202), flush worker'ı çalıştırır, report admin görünümüdür.

// --- gece senkron kuyruğu (mock) ---
let asyncQueue = [];
let adminReport = ['--- admin raporu (gece senkronu) ---'];

// VULN giriş: kullanıcı adı ham saklanıyor
router.post('/submit', (req, res) => {
  mark(res, 'ASYNC2-ENTRY-01', 'A03-Injection', 'vulnerable');
  const { username = '' } = req.body || {};
  asyncQueue.push(String(username));
  res.status(202).json({ ok: true, queued: asyncQueue.length, note: 'gece senkronuna alındı — tetik: POST /async2/flush' });
});
// VULN tetik: worker string-birleştirme ile "sorgu" kuruyor
router.post('/flush', (req, res) => {
  mark(res, 'ASYNC2-TRIGGER-01', 'A03-Injection', 'vulnerable');
  const out = [];
  for (const u of asyncQueue.splice(0)) {
    // GÜVENLİ OLMAYAN birleştirme (mock SQL):
    if (u.includes("' OR '1'='1") || u.includes(' OR 1=1')) {
      out.push(`DUMP for '${u}': admin@example.com, bob@example.com (2 rows dumped!)`);
    } else {
      out.push(`ok: ${u} (1 row)`);
    }
  }
  adminReport = adminReport.concat(out);
  res.json({ flushed: out.length, note: 'tetiklendi — oku: GET /async2/report?role=admin' });
});
router.get('/report', (req, res) => {
  mark(res, 'ASYNC2-TRIGGER-01', 'A03-Injection', 'vulnerable');
  res.send(`<h1>Admin senkron raporu</h1><pre>${escHtml(adminReport.join('\n'))}</pre>`);
});
// SECURE ikiz: girişte allowlist + worker parametreli
router.post('/submit-secure', (req, res) => {
  mark(res, 'ASYNC2-ENTRY-01-SECURE', 'A03-Injection', 'secure');
  const { username = '' } = req.body || {};
  if (!/^[a-z0-9]{3,20}$/i.test(username)) return res.status(400).json({ error: 'kullanıcı adı allowlist dışı' });
  asyncQueue.push(username);
  res.status(202).json({ ok: true });
});
router.post('/flush-secure', (req, res) => {
  mark(res, 'ASYNC2-TRIGGER-01-SECURE', 'A03-Injection', 'secure');
  const n = asyncQueue.splice(0).length;
  adminReport.push(`secure flush: ${n} kayıt parametreli işlendi (0 rows for evil)`);
  res.json({ flushed: n });
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => {
  asyncQueue = [];
  adminReport = ['--- admin raporu (gece senkronu) ---'];
});

module.exports = router;

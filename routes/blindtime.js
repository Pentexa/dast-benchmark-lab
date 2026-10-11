const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.9 — Kontrollü jitter altında blind timing: kalibrasyon + bütçeli gecikme.
// Tarayıcı önce /calibrate ile tabanı ölçer, sonra delta'yı yorumlar.

// --- kalibrasyon: sabit maliyetli, girdiden bağımsız ---
router.get('/calibrate', (req, res) => {
  mark(res, 'BLINDTIME-CAL', 'A03-Injection', 'secure');
  res.json({ baseline_ms: 120, note: 'sabit maliyet (jitter bütçesi: ±400ms üzeri anlamlı)' });
});

// VULN: key SLEEP(n) içerirse GERÇEKTEN n sn uyur (maks 3 sn, zaman oracle)
router.get('/lookup', (req, res) => {
  mark(res, 'BLINDTIME-01', 'A03-Injection', 'vulnerable');
  const key = String(req.query.key || '');
  const m = key.match(/SLEEP\((\d)\)/i);
  const secs = m ? Math.min(parseInt(m[1], 10), 3) : 0;
  setTimeout(() => {
    res.send(`<h1>Arama</h1><p>key=${escHtml(key)}</p><p>${secs ? `SLEEP(${secs}) çalıştı (~${secs * 1000}ms gecikme)` : 'hızlı sonuç (120ms taban)'}</p>`);
  }, secs * 1000);
});
// SECURE: desen yoksayılır, sabit sürede dönülür
router.get('/lookup-secure', (req, res) => {
  mark(res, 'BLINDTIME-01-SECURE', 'A03-Injection', 'secure');
  const key = String(req.query.key || '');
  res.send(`<h1>Arama</h1><p>key=${escHtml(key)}</p><p>sabit süreli yanıt (desen yoksayıldı)</p>`);
});

module.exports = router;

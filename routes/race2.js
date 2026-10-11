const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.7 — Deterministik race: sınırlı kupon havuzu, atomik-olmayan claim.
// ?burst=N tek istekte N talebi aynı anda işletir (yarış penceresi simülasyonu);
// tohum + reset ile birebir tekrarlanabilir.

// --- kupon havuzu (mock) ---
const POOL0 = { code: 'RACE5', stock: 5, granted: [] };
let pool = JSON.parse(JSON.stringify(POOL0));

// VULN: burst taleplerin hepsi veriliyor (stok aşımı) — check-then-act kilitsiz
router.post('/claim', (req, res) => {
  mark(res, 'RACE2-BURST-01', 'A04-BusinessLogic', 'vulnerable');
  const burst = Math.min(Math.max(parseInt(req.query.burst || '1', 10) || 1, 1), 20);
  const user = String((req.body || {}).user || 'anon');
  const granted = [];
  for (let i = 0; i < burst; i++) {
    if (pool.stock > 0) pool.stock--; // kontrol VE azaltma arasında kilit YOK (mock)
    pool.granted.push(user); // stok bitse de yazılıyor!
    granted.push(user);
  }
  res.json({
    ok: true, requested: burst, granted: granted.length, remaining_stock: pool.stock,
    note: granted.length > POOL0.stock
      ? `OVER-CLAIMED: ${granted.length}/${POOL0.stock} — yarış penceresi! (?burst=10 dene)`
      : 'kupon verildi (?burst=10 ile stok aşımını dene)',
  });
});
// SECURE: atomik sayaç — stok bitince 409 bekleme listesi
router.post('/claim-secure', (req, res) => {
  mark(res, 'RACE2-BURST-01-SECURE', 'A04-BusinessLogic', 'secure');
  const burst = Math.min(Math.max(parseInt(req.query.burst || '1', 10) || 1, 1), 20);
  const user = String((req.body || {}).user || 'anon');
  const granted = [];
  for (let i = 0; i < burst; i++) {
    if (pool.stock <= 0) break;
    pool.stock--;
    pool.granted.push(user);
    granted.push(user);
  }
  if (!granted.length) return res.status(409).json({ error: 'stok bitti (bekleme listesi)' });
  res.json({ ok: true, granted: granted.length, denied: burst - granted.length, remaining_stock: pool.stock });
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => { pool = JSON.parse(JSON.stringify(POOL0)); });

module.exports = router;

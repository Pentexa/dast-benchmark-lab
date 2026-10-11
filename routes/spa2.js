const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.1 — Deep SPA: Shadow DOM sink + sunucu-adım doğrulamasız sihirbaz.
// Crawler JS çalıştırmalı; sihirbaz zincir atlamayı denemeli.

// ---------- Shadow DOM sayfa (config JSON innerHTML'e gömülüyor) ----------
// VULN: ?config={"html":"..."} kaçışsız yansıyor (gölge DOM dahil taranmalı)
router.get('/widget', (req, res) => {
  mark(res, 'SPA2-SHADOW-01', 'Client-Side', 'vulnerable');
  let html = '<b>varsayılan rozet</b>';
  try {
    const cfg = JSON.parse(req.query.config || '{}');
    if (cfg.html) html = cfg.html; // KAÇIŞ YOK
  } catch {}
  res.send(`<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>Rozet</title></head><body>
  <div id="host"></div>
  <script>const h=document.getElementById('host');const s=h.attachShadow({mode:'open'});s.innerHTML=${JSON.stringify(html)};</script>
  <!-- statik HTML: ${html} --></body></html>`);
});
// SECURE: allowlist rozet + escape
router.get('/widget-secure', (req, res) => {
  mark(res, 'SPA2-SHADOW-01-SECURE', 'Client-Side', 'secure');
  const allowed = { yildiz: '⭐', rozet: '🎖️' };
  const html = allowed[req.query.config] || '⭐';
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><div id="host"></div>
  <script>document.getElementById('host').attachShadow({mode:'open'}).textContent=${JSON.stringify(html)};</script></body></html>`);
});

// ---------- 3 adımlı sihirbaz: adım jetonu İMZASIZ ----------
// VULN: ?step=3&progress=2 doğrudan "shipped" verir (adım atlama)
router.get('/wizard', (req, res) => {
  mark(res, 'SPA2-WIZARD-01', 'Client-Side', 'vulnerable');
  const step = String(req.query.step || '1');
  const progress = String(req.query.progress || '0');
  if (step === '3' && progress === '2') {
    return res.send('<h1>Sipariş gönderildi</h1><p>shipped without payment — adım 1-2 atlandı! (progress jetonu imzasız)</p>');
  }
  res.send(`<h1>Sihirbaz adım ${escHtml(step)}</h1><p>sonraki: /spa2/wizard?step=3&progress=2 (jeton doğrulanmıyor!)</p>`);
});
// SECURE: progress jetonu HMAC imzalı, sahte jeton 400 yer
const crypto = require('crypto');
const WIZ_SECRET = 'wiz-secret-key';
function wizToken(step) {
  return `${step}.` + crypto.createHmac('sha256', WIZ_SECRET).update(String(step)).digest('hex').slice(0, 16);
}
router.get('/wizard-secure', (req, res) => {
  mark(res, 'SPA2-WIZARD-01-SECURE', 'Client-Side', 'secure');
  const step = String(req.query.step || '1');
  const [ps, sig] = String(req.query.progress || '').split('.');
  if (step === '3') {
    if (ps !== '2' || sig !== crypto.createHmac('sha256', WIZ_SECRET).update('2').digest('hex').slice(0, 16)) {
      return res.status(400).send('<h1>400</h1><p>önce 2. adımı tamamla (imzalı jeton gerekli)</p>');
    }
    return res.send('<h1>Sipariş gönderildi</h1><p>adımlar sırayla tamamlandı</p>');
  }
  res.send(`<h1>Güvenli sihirbaz adım ${escHtml(step)}</h1><p>jeton: ${wizToken('2')}</p>`);
});

module.exports = router;

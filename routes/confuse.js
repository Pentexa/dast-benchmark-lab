const express = require('express');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// P1.13 — Dinamik yanıt karışıklığı: soft-404 oracle + ilan-edilen-ama-çalışmayan limit.
// Tarayıcı "200 = var, 404 = yok" varsayımını sorgulamalı.

// VULN: olmayan kullanıcıda 200 + admin ipucu (soft-404 enumeration oracle)
router.get('/user/:name', (req, res) => {
  mark(res, 'CONFUSE-ENUM-01', 'A01-AccessControl', 'vulnerable');
  const u = users.find(x => x.username === String(req.params.name));
  if (u) return res.json({ username: u.username, email: u.email });
  // 200 + ayırt edici metin:
  res.status(200).send(`<h1>Kullanıcı bulunamadı</h1><p>did you mean 'admin'? (benzer: alice, bob)</p>`);
});
// SECURE: gerçek 404, ipucu yok
router.get('/user-secure/:name', (req, res) => {
  mark(res, 'CONFUSE-ENUM-01-SECURE', 'A01-AccessControl', 'secure');
  const u = users.find(x => x.username === String(req.params.name));
  if (!u) return res.status(404).json({ error: 'yok' });
  res.json({ username: u.username });
});

// VULN: limit ilan ediliyor ama ASLA uygulanmıyor (gürültüde kaybolan brute-force)
router.get('/ratelimit', (req, res) => {
  mark(res, 'CONFUSE-RATELIMIT-01', 'A07-Auth', 'vulnerable');
  res.set('X-RateLimit-Limit', '5').set('X-RateLimit-Remaining', '5').set('Retry-After', '0');
  res.send('<h1>Login formu</h1><p>limit announced, not enforced — sınırsız dene (başlıklar yalan söylüyor!)</p>');
});
// SECURE: ilan edilen limit gerçekten uygulanıyor
const rlHits = {};
router.get('/ratelimit-secure', (req, res) => {
  mark(res, 'CONFUSE-RATELIMIT-01-SECURE', 'A07-Auth', 'secure');
  const now = Date.now();
  rlHits[req.ip] = (rlHits[req.ip] || []).filter(t => now - t < 60000);
  if (rlHits[req.ip].length >= 5) {
    res.set('X-RateLimit-Remaining', '0').set('Retry-After', '60');
    return res.status(429).json({ error: 'kilit (5/dk uygulandı)' });
  }
  rlHits[req.ip].push(now);
  res.set('X-RateLimit-Remaining', String(5 - rlHits[req.ip].length));
  res.send('<h1>Login formu</h1>');
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => { for (const k of Object.keys(rlHits)) delete rlHits[k]; });

module.exports = router;

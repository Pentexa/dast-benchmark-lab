const express = require('express');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// OWASP API Security Top 10 2023 — güncel REST senaryoları

// ---------- API1 BOLA: /api/users/:id ----------
// VULN: auth yok, başkasının tam kaydı
router.get('/users/:id', (req, res) => {
  mark(res, 'API-BOLA-01', 'API-Security', 'vulnerable');
  const u = users.find(x => String(x.id) === String(req.params.id));
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u); // role, pan, tckn, iban dahil — excessive ile birleşik
});
// SECURE: sadece kendi kaydı + minimal alan
router.get('/users-secure/:id', (req, res) => {
  mark(res, 'API-BOLA-01-SECURE', 'API-Security', 'secure');
  const as = String(req.get('X-User-Id') || '1');
  if (as !== String(req.params.id)) return res.status(403).json({ error: 'forbidden' });
  const u = users.find(x => String(x.id) === as);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json({ id: u.id, username: u.username });
});

// ---------- API3 Mass Assignment ----------
// VULN: role client'tan alınıyor
router.post('/users', (req, res) => {
  mark(res, 'API-MASS-01', 'API-Security', 'vulnerable');
  const { username = 'yeni', role = 'user' } = req.body || {};
  res.status(201).json({ id: 100, username, role, note: 'role client tarafından belirlendi! {"username":"x","role":"admin"} dene' });
});
router.post('/users-secure', (req, res) => {
  mark(res, 'API-MASS-01-SECURE', 'API-Security', 'secure');
  const { username = 'yeni' } = req.body || {};
  if (req.body && (req.body.role || req.body.isAdmin)) return res.status(400).json({ error: 'role alanı kabul edilmez (allowlist dışı)' });
  res.status(201).json({ id: 100, username, role: 'user' });
});

// ---------- API3 Excessive Data Exposure (Türk PII) ----------
// VULN: mobil uygulamanın ihtiyacı olmayan TC/IBAN/adres dönüyor
router.get('/account', (req, res) => {
  mark(res, 'API-EXCESS-01', 'API-Security', 'vulnerable');
  const u = users.find(x => String(x.id) === String(req.query.user ?? '1'));
  res.json({ profile: u, debug: { query_time_ms: 3 }, note: 'TCKN + IBAN + PAN gereksiz yere dönüyor (KVKK ihlali)' });
});
router.get('/account-secure', (req, res) => {
  mark(res, 'API-EXCESS-01-SECURE', 'API-Security', 'secure');
  const u = users.find(x => String(x.id) === String(req.query.user ?? '1'));
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json({ id: u.id, username: u.username, masked_iban: 'TR** **** **** **** **** 1326' });
});

// ---------- API4 Rate Limit yok: OTP verify ----------
// VULN: 6 haneli kod, sınırsız deneme, kilit yok
let otpAttempts = 0;
const REAL_OTP = '739281';
router.post('/otp-verify', (req, res) => {
  mark(res, 'API-RATE-01', 'API-Security', 'vulnerable');
  otpAttempts++;
  res.set('X-RateLimit-Limit', 'none');
  if (String((req.body || {}).code) === REAL_OTP) return res.json({ ok: true, session: 'mock-session-abc' });
  res.status(400).json({ ok: false, attempt: otpAttempts, note: 'rate-limit yok, hesap kilidi yok — sınırsız dene' });
});
// SECURE: 5 denemede 15 dk kilit
let lock = { fails: 0, until: 0 };
router.post('/otp-verify-secure', (req, res) => {
  mark(res, 'API-RATE-01-SECURE', 'API-Security', 'secure');
  if (Date.now() < lock.until) return res.status(429).set('Retry-After', '900').json({ error: 'kilitlendi, 15 dk bekle' });
  if (String((req.body || {}).code) === REAL_OTP) { lock.fails = 0; return res.json({ ok: true }); }
  lock.fails++;
  if (lock.fails >= 5) lock.until = Date.now() + 15 * 60 * 1000;
  res.status(400).json({ ok: false, remaining: Math.max(0, 5 - lock.fails) });
});

// ---------- API2 Broken Auth: key URL'de ----------
// VULN: api_key query'de → log/proxy geçmişine düşer
router.get('/balance', (req, res) => {
  mark(res, 'API-KEY-01', 'API-Security', 'vulnerable');
  if ((req.query.api_key || '') !== 'live_mock_key_123') return res.status(401).json({ error: 'api_key gerekli (?api_key=...)' });
  res.json({ balance: 12500, currency: 'TRY', note: 'anahtar URL query içinde taşındı (loglara düşer)' });
});
router.get('/balance-secure', (req, res) => {
  mark(res, 'API-KEY-01-SECURE', 'API-Security', 'secure');
  if (req.query.api_key) return res.status(400).json({ error: 'api_key query ile gönderilemez, X-API-Key header kullan' });
  if (req.get('X-API-Key') !== 'live_mock_key_123') return res.status(401).json({ error: 'geçersiz anahtar' });
  res.json({ balance: 12500, currency: 'TRY' });
});

// ---------- API4 Pagination abuse ----------
// VULN: limit doğrulanmıyor
const bigOrders = Array.from({ length: 200 }, (_, i) => ({ order_id: 5000 + i, user_id: (i % 3) + 1, total: 100 + i }));
router.get('/orders', (req, res) => {
  mark(res, 'API-PAGE-01', 'API-Security', 'vulnerable');
  const limit = parseInt(req.query.limit ?? '10', 10);
  res.set('X-Total-Count', String(bigOrders.length));
  res.json(bigOrders.slice(0, isNaN(limit) ? 10 : limit)); // ?limit=100000 tüm veriyi döker
});

// ---------- Tahmin edilebilir davet token ----------
// VULN: sıralı ID
const invites = { 1001: 'alice', 1002: 'bob', 1003: 'admin' };
router.get('/invite', (req, res) => {
  const t = req.query.token ?? '';
  mark(res, 'API-INVITE-01', 'API-Security', 'vulnerable');
  if (!t) return res.send(`<h1>Davet</h1><p>?token=1001 dene (1002, 1003... sıralı!)</p>`);
  if (invites[t]) return res.send(`<h1>Davet geçerli</h1><p>Kullanıcı: ${escHtml(invites[t])} — token tahmin edilebilir (sıralı sayı)</p>`);
  res.status(404).send('Geçersiz davet');
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => { otpAttempts = 0; lock.fails = 0; lock.until = 0; });

module.exports = router;

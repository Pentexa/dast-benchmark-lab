const express = require('express');
const fs = require('fs');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.10 — Gecikmeli çok aşamalı OOB: kayıt (t+0) + gecikmeli ateşleme (t+n).
// Kör bulgunun 2 kademede doğrulanması ölçülür; sayaç /api/oob-hits'tir.

const { oobFile } = require('./oob');
const stages = {}; // token -> {callback, fired}
let stageSeq = 1;

// VULN aşama 1: harici callback koşulsuz kabul
router.post('/register', (req, res) => {
  mark(res, 'OOB2-STAGED-01', 'A03-XSS', 'vulnerable');
  const { callback = '' } = req.body || {};
  if (!callback) return res.status(400).json({ error: 'callback gerekli (örn. /oob/benim-kodum)' });
  const token = 'stg-' + (stageSeq++);
  stages[token] = { callback, fired: false };
  try { fs.appendFileSync(oobFile, JSON.stringify({ ts: new Date().toISOString(), kind: 'oob2-stage1', callback }) + '\n'); } catch {}
  res.status(201).json({ token, note: `1. kademe kaydedildi — ateşle: GET /oob2/fire?token=${token}` });
});
// VULN aşama 2: gecikmeli ateşleme (1.5 sn sonra tetik yazar)
router.get('/fire', (req, res) => {
  mark(res, 'OOB2-STAGED-01', 'A03-XSS', 'vulnerable');
  const s = stages[String(req.query.token || '')];
  if (!s) return res.status(404).json({ error: 'stage yok (önce POST /oob2/register)' });
  if (!s.fired) {
    s.fired = true;
    setTimeout(() => {
      try { fs.appendFileSync(oobFile, JSON.stringify({ ts: new Date().toISOString(), kind: 'oob2-stage2-fired', callback: s.callback }) + '\n'); } catch {}
    }, 1500);
  }
  res.json({ ok: true, note: '2. kademe ateşlendi — 2 sn bekle, GET /api/oob-hits sayacını karşılaştır' });
});
// SECURE: harici callback kabul edilmez
router.post('/register-secure', (req, res) => {
  mark(res, 'OOB2-STAGED-01-SECURE', 'A03-XSS', 'secure');
  res.status(403).json({ error: 'dış callback kapalı (allowlist: yok)' });
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => {
  for (const k of Object.keys(stages)) delete stages[k];
  stageSeq = 1;
});

module.exports = router;

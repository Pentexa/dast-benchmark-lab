const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const { token: genToken } = require('../lib/seeded');
const router = express.Router();

// P1.6 — Çok adımlı iş-akışı: oluştur -> öde -> gönder. Adım atlama ve tekrar ölçülür.

// --- sipariş durum makinesi (mock) ---
const FLOW0 = {
  'FL-1001': { id: 'FL-1001', item: 'tshirt', state: 'created' },
  'FL-1002': { id: 'FL-1002', item: 'ayakkabi', state: 'paid' },
};
let flowOrders = JSON.parse(JSON.stringify(FLOW0));
let flowSeq = 1003;

router.post('/orders', (req, res) => {
  mark(res, 'FLOW-ORDER-01', 'A04-BusinessLogic', 'vulnerable');
  const id = 'FL-' + (flowSeq++);
  flowOrders[id] = { id, item: String((req.body || {}).item || 'tshirt'), state: 'created' };
  res.status(201).json({ orderId: id, state: 'created', note: 'sıradaki: POST /flow/pay {"orderId":"..."}' });
});

// VULN: ödenmemiş sipariş gönderiliyor (adım atlama)
router.post('/ship', (req, res) => {
  mark(res, 'FLOW-SKIP-01', 'A04-BusinessLogic', 'vulnerable');
  const o = flowOrders[(req.body || {}).orderId];
  if (!o) return res.status(404).json({ error: 'sipariş yok (FL-1001 dene)' });
  o.state = 'shipped'; // ÖDEME KONTROLÜ YOK
  res.json({ ok: true, orderId: o.id, state: o.state, note: 'shipped without payment — /flow/pay atlandı!' });
});
// SECURE: gönderim için paid şart
router.post('/ship-secure', (req, res) => {
  mark(res, 'FLOW-SKIP-01-SECURE', 'A04-BusinessLogic', 'secure');
  const o = flowOrders[(req.body || {}).orderId];
  if (!o) return res.status(404).json({ error: 'sipariş yok' });
  if (o.state !== 'paid') return res.status(409).json({ error: 'önce ödeme (state: ' + o.state + ')' });
  o.state = 'shipped';
  res.json({ ok: true, state: o.state });
});

// VULN: ödenmiş sipariş tekrar ücretlendiriliyor (replay)
router.post('/pay', (req, res) => {
  mark(res, 'FLOW-REPLAY-01', 'A04-BusinessLogic', 'vulnerable');
  const o = flowOrders[(req.body || {}).orderId];
  if (!o) return res.status(404).json({ error: 'sipariş yok (FL-1002 dene — zaten paid)' });
  o.state = 'paid'; // IDEMPOTENCY YOK
  res.json({ ok: true, orderId: o.id, note: 'charged twice — aynı sipariş tekrar ücretlendirildi! (idempotency yok)' });
});
// SECURE: tekrar ödeme 409
router.post('/pay-secure', (req, res) => {
  mark(res, 'FLOW-REPLAY-01-SECURE', 'A04-BusinessLogic', 'secure');
  const o = flowOrders[(req.body || {}).orderId];
  if (!o) return res.status(404).json({ error: 'sipariş yok' });
  if (o.state === 'paid') return res.status(409).json({ error: 'zaten ödenmiş (idempotency-key gerekli)' });
  o.state = 'paid';
  res.json({ ok: true, state: o.state });
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => {
  flowOrders = JSON.parse(JSON.stringify(FLOW0));
  flowSeq = 1003;
});

module.exports = router;

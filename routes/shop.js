const express = require('express');
const crypto = require('crypto');
const { escHtml, users, catalog, mark } = require('../lib/utils');
const router = express.Router();

// Güncel e-ticaret mantık hataları: fiyat client'ta, negatif adet, kupon race, sıralı sipariş ID.

// ---------- Fiyat client'tan geliyor (VULN) ----------
router.post('/cart', (req, res) => {
  mark(res, 'SHOP-PRICE-01', 'A04-BusinessLogic', 'vulnerable');
  const { item = 'tshirt', price, qty = 1 } = req.body || {};
  const total = Number(price) * Number(qty);
  res.json({ item, unit_price_charged: Number(price), qty: Number(qty), total, note: `fiyat client'tan alındı! {"item":"ayakkabi","price":1,"qty":1} dene (gerçek: ${catalog.ayakkabi.price} TL)` });
});
router.post('/cart-secure', (req, res) => {
  mark(res, 'SHOP-PRICE-01-SECURE', 'A04-BusinessLogic', 'secure');
  const { item = 'tshirt', qty = 1 } = req.body || {};
  if (!catalog[item] || Number(qty) <= 0 || Number(qty) > 10) return res.status(400).json({ error: 'geçersiz ürün/adet' });
  res.json({ item, unit_price: catalog[item].price, qty: Number(qty), total: catalog[item].price * Number(qty) });
});

// ---------- Negatif adet (VULN) ----------
router.post('/cart-qty', (req, res) => {
  mark(res, 'SHOP-QTY-01', 'A04-BusinessLogic', 'vulnerable');
  const { item = 'tshirt', qty = -1 } = req.body || {};
  const total = (catalog[item]?.price ?? 499) * Number(qty);
  res.json({ item, qty: Number(qty), total, note: total < 0 ? 'NEGATİF TUTAR: para iadesi/bedava ürün mock!' : 'qty doğrulanmıyor' });
});

// ---------- Tek kullanımlık kupon, race'e açık (VULN) ----------
let couponUses = 0;
router.post('/coupon-race', (req, res) => {
  mark(res, 'SHOP-RACE-01', 'A04-BusinessLogic', 'vulnerable');
  couponUses++;
  res.json({ ok: true, code: (req.body || {}).code || 'TEK10', uses: couponUses, note: 'tek kullanımlık olması gereken kupon sınırsız kullanıldı (kilit/transaction yok — paralel 10 istekte 10 indirim)' });
});

// ---------- Sıralı sipariş ID ile başkasının siparişi (VULN) ----------
const shopOrders = { 1001: { user: 'alice', total: 499, items: ['tshirt'] }, 1002: { user: 'bob', total: 2499, items: ['ayakkabi'] }, 1003: { user: 'admin', total: 9999, items: ['sunucu'] } };
router.get('/order/:id', (req, res) => {
  mark(res, 'SHOP-ORDER-01', 'A04-BusinessLogic', 'vulnerable');
  const o = shopOrders[req.params.id];
  if (!o) return res.status(404).json({ error: 'yok' });
  res.json({ order_id: req.params.id, ...o, note: 'auth yok + sıralı ID: 1001→1002→1003 gezilebilir' });
});
// SECURE: UUID + sahiplik
const secureOrders = {};
['alice', 'bob'].forEach(u => { const id = crypto.randomUUID(); secureOrders[id] = { user: u, total: 499 }; });
router.get('/order-secure/:id', (req, res) => {
  mark(res, 'SHOP-ORDER-01-SECURE', 'A04-BusinessLogic', 'secure');
  const o = secureOrders[req.params.id];
  if (!o) return res.status(404).json({ error: 'yok' });
  if (req.get('X-User-Id') !== o.user && req.get('X-Role') !== 'admin') return res.status(403).json({ error: 'başkasının siparişi' });
  res.json({ order_id: req.params.id, ...o });
});
router.get('/order-secure-ids', (req, res) => {
  mark(res, 'SHOP-ORDER-IDS', 'A04-BusinessLogic', 'secure');
  res.json({ hint: 'X-User-Id header ile dene', ids: Object.keys(secureOrders) });
});

module.exports = router;

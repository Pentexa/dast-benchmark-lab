const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.4 — GraphQL iç-içe yetkilendirme + federasyon: alan-seviyesi sızıntı.
// Introspection değil, YETKİLİ alanın yetkisiz role dönmesi ölçülür.

// VULN: supplierCost (sadece tedarikçi rolüne) herkese dönüyor
router.post('/graphql', (req, res) => {
  mark(res, 'GQL2-NESTED-01', 'API-GraphQL', 'vulnerable');
  const q = String((req.body || {}).query || '');
  const role = req.get('X-Role') || 'user';
  if (/supplierCost/i.test(q)) {
    return res.json({ data: { user: { orders: [{ id: 'O-1', supplierCost: 42.5, note: `role=${role} ama maliyet döküldü (alan-seviyesi yetki yok)` }] } } });
  }
  res.json({ data: { user: { id: '1', username: 'alice' } } });
});
// SECURE: hassas alan redakte edilir
router.post('/graphql-secure', (req, res) => {
  mark(res, 'GQL2-NESTED-01-SECURE', 'API-GraphQL', 'secure');
  const q = String((req.body || {}).query || '');
  if (/supplierCost/i.test(q) && req.get('X-Role') !== 'supplier') {
    return res.json({ data: { user: { orders: [{ id: 'O-1', supplierCost: null }] } }, errors: [{ message: 'supplierCost: yetkisiz alan (redakte)' }] });
  }
  res.json({ data: { user: { id: '1', username: 'alice' } } });
});

// VULN: federasyon _entities geçişi imzasız kabul (SSN sızar)
router.post('/federation', (req, res) => {
  mark(res, 'GQL2-FED-01', 'API-GraphQL', 'vulnerable');
  const reps = (req.body || {}).representations || [];
  const out = reps.map(r => r.__typename === 'User'
    ? { __typename: 'User', id: r.id, ssn: '422-11-0001 (federasyon geçişi, gateway imzası sorulmadı)' }
    : r);
  res.json({ _entities: out });
});
// SECURE: gateway imzası zorunlu
router.post('/federation-secure', (req, res) => {
  mark(res, 'GQL2-FED-01-SECURE', 'API-GraphQL', 'secure');
  if (req.get('X-Gateway-Sig') !== 'gw-signed-v1') return res.status(401).json({ error: 'gateway imzası gerekli' });
  res.json({ _entities: [] });
});

module.exports = router;

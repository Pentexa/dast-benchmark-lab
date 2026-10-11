const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.3 — Multi-tenant IDOR/BOLA: kiracı × rol × sahiplik matrisi.
// Header kimliği (X-Tenant, X-Role) tek başına yetmez; sahiplik de gerekir.

// --- kiracı belgeleri (mock) ---
const TENANT_DOCS0 = {
  'acme:D1': { id: 'D1', tenant: 'acme', owner: 'alice', secret: 'ACME-SECRET-111' },
  'acme:D2': { id: 'D2', tenant: 'acme', owner: 'bob', secret: 'ACME-SECRET-222' },
  'globex:G9': { id: 'G9', tenant: 'globex', owner: 'carol', secret: 'GLOBEX-SECRET-999' },
};
let tenantDocs = JSON.parse(JSON.stringify(TENANT_DOCS0));

// VULN: kiracı/rol/sahiplik kontrolsüz — чужой tenant belgesi dökülür
router.get('/docs', (req, res) => {
  mark(res, 'TENANT-IDOR-01', 'A01-AccessControl', 'vulnerable');
  const d = tenantDocs[`${req.query.tenant}:${req.query.id}`];
  if (!d) return res.status(404).json({ error: 'yok' });
  res.json({ ...d, note: 'X-Tenant/X-Role/sahiplik doğrulanmadı (?tenant=globex&id=G9 + X-Tenant: acme dene)' });
});
// SECURE: kiracı eşleşmesi + (sahip veya admin) gerekir
router.get('/docs-secure', (req, res) => {
  mark(res, 'TENANT-IDOR-01-SECURE', 'A01-AccessControl', 'secure');
  const tenant = req.get('X-Tenant'), role = req.get('X-Role'), me = req.get('X-User');
  const d = tenantDocs[`${req.query.tenant}:${req.query.id}`];
  if (!d || tenant !== d.tenant) return res.status(404).json({ error: 'yok' });
  if (me !== d.owner && role !== 'admin') return res.status(403).json({ error: 'forbidden (sahip/admin değil)' });
  res.json({ id: d.id, tenant: d.tenant });
});

// VULN: kiracılar arası belge taşıma yetkisiz (BOLA yazma)
router.post('/transfer', (req, res) => {
  mark(res, 'TENANT-BOLA-01', 'A01-AccessControl', 'vulnerable');
  const { docId = 'D1', toTenant = 'globex' } = req.body || {};
  const key = Object.keys(tenantDocs).find(k => k.endsWith(':' + docId));
  if (!key) return res.status(404).json({ error: 'belge yok' });
  const d = tenantDocs[key];
  delete tenantDocs[key];
  tenantDocs[`${toTenant}:${docId}`] = { ...d, tenant: toTenant };
  res.json({ ok: true, moved: `${docId} -> ${toTenant}`, note: 'rol/sahiplik sorulmadan kiracı değiştirildi!' });
});
// SECURE: admin rolü zorunlu
router.post('/transfer-secure', (req, res) => {
  mark(res, 'TENANT-BOLA-01-SECURE', 'A01-AccessControl', 'secure');
  if (req.get('X-Role') !== 'admin') return res.status(403).json({ error: 'admin gerekli' });
  res.json({ ok: true, note: 'yetkili taşıma (mock)' });
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => {
  tenantDocs = JSON.parse(JSON.stringify(TENANT_DOCS0));
});

module.exports = router;

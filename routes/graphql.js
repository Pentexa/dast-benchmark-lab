const express = require('express');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// Modern yüzey: GraphQL — 2024/2025 pentest raporlarının vazgeçilmezi.
// Hepsi MOCK resolver; gerçek DB/şema yok, davranış simülasyonu var.

const SCHEMA_LEAK = `type User { id: ID! username: String email: String passwordHash: String tckn: String iban: String role: String }
type Order { id: ID! userId: ID! total: Int items: [String] }
type Query { user(id: ID!): User users(limit: Int): [User] order(id: ID!): Order __schema: Schema }`;

// ---------- Introspection açık (VULN) ----------
router.post('/', (req, res) => {
  mark(res, 'GQL-INTROS-01', 'API-GraphQL', 'vulnerable');
  const q = JSON.stringify(req.body || {});
  if (q.includes('__schema') || q.includes('IntrospectionQuery') || q.includes('__typename')) {
    return res.json({ data: { __schema: { queryType: 'Query', types: ['User', 'Order'], note: 'passwordHash + tckn şemada görünüyor!', sdl: SCHEMA_LEAK } } });
  }
  const m = q.match(/user\s*\(\s*id\s*:\s*"?(\d+)"?\s*\)/);
  if (m) {
    const u = users.find(x => String(x.id) === m[1]);
    if (u) return res.json({ data: { user: u } }); // auth yok → BOLA
    return res.json({ data: { user: null } });
  }
  res.json({ data: null, note: 'POST {"query":"{ __schema { queryType { name } } }"} dene' });
});

// ---------- Introspection kapalı (SECURE) ----------
router.post('/secure', (req, res) => {
  mark(res, 'GQL-INTROS-01-SECURE', 'API-GraphQL', 'secure');
  const q = JSON.stringify(req.body || {});
  if (q.includes('__schema') || q.includes('IntrospectionQuery')) {
    return res.status(400).json({ errors: [{ message: 'Introspection disabled in production' }] });
  }
  res.json({ data: null, note: 'auth + depth-limit + introspection kapalı' });
});

// ---------- Batch brute-force ----------
// VULN: tek HTTP isteğinde 50 login denemesi
router.post('/batch', (req, res) => {
  mark(res, 'GQL-BATCH-01', 'API-GraphQL', 'vulnerable');
  const body = req.body;
  const arr = Array.isArray(body) ? body : [body];
  if (arr.length > 1) {
    const hit = arr.some(o => JSON.stringify(o).includes('admin123'));
    if (hit) return res.json(arr.map(() => ({ data: { login: null } })).concat([{ data: { login: { token: 'mock-admin-session', note: 'batch içinde doğru şifre bulundu!' } } }]));
    return res.json({ note: `batch kabul edildi (${arr.length} sorgu, rate-limit batch'i görmüyor)` });
  }
  res.json({ note: 'JSON array gönder: [{...login...},{...login...}] — batch throttling yok' });
});

// ---------- Derinlik/alias DoS ----------
// VULN: depth limit yok
router.post('/depth', (req, res) => {
  mark(res, 'GQL-DEPTH-01', 'API-GraphQL', 'vulnerable');
  const q = JSON.stringify(req.body || {});
  const depth = (q.match(/users|orders|user/g) || []).length;
  if (depth >= 6) return res.json({ data: { note: `derinlik ${depth} çalıştırıldı: 2.4M kayıt, 8.1s (depth-limit + timeout + cost yok!)` } });
  res.json({ note: 'iç içe users{orders{user{orders...}}} gönder, depth-limit yok' });
});

// ---------- GraphQL üzerinden IDOR (kullanıcı enum) ----------
router.post('/user', (req, res) => {
  mark(res, 'GQL-IDOR-01', 'API-GraphQL', 'vulnerable');
  const id = String((req.body || {}).id ?? (req.body?.variables?.id ?? ''));
  const u = users.find(x => String(x.id) === id);
  if (!u) return res.json({ data: null, note: '{"id":"99"} dene' });
  res.json({ data: { user: u } }); // auth yok
});

module.exports = router;

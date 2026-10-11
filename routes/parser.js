const express = require('express');
const qs = require('querystring');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.11 — HTTP parser farklılıkları: katmanlar arası tutarsız yorum smuggling'e kapı açar.
// Oracle'lar tek istekte deterministik marker döner (ham soket gerekmez).

// VULN: noktalı-virgül ayracı İLK değeri kazandırır (çoğu tarayıcı SONuncuyu varsayar)
router.get('/semicolon', (req, res) => {
  mark(res, 'PARSER-SEMI-01', 'A03-Injection', 'vulnerable');
  let raw = (req.originalUrl.split('?')[1] || '');
  try { raw = decodeURIComponent(raw); } catch {}
  const parts = raw.split(/[;&]/).map(p => p.split('='));
  const first = parts.find(p => p[0] === 'x');
  res.send(`<h1>Parser</h1><p>parsed_first: ${escHtml(first ? first[1] : 'yok')} (?x=1;x=2 dene — katman B sonuncuyu okursa smuggling!)</p>`);
});

// VULN: Content-Type/çerçeve uyumsuzluğunda yedek ayrıştırıcı admin=true'yu işletir
router.post('/ctype', express.text({ type: '*/*' }), (req, res) => {
  mark(res, 'PARSER-CTYPE-01', 'A03-Injection', 'vulnerable');
  const ct = req.get('Content-Type') || '';
  let role = 'user';
  try {
    const j = JSON.parse(req.body || '{}');
    role = j.role || 'user';
  } catch {
    const f = qs.parse(String(req.body || '')); // YEDEK ayrıştırıcı (form)
    if (f.admin === 'true' || f.role === 'admin') role = 'admin (fallback parser!)';
  }
  res.json({ content_type: ct, role, note: 'JSON beklerken form gövdesi yedek ayrıştırıcıya düştü' });
});
// SECURE: çerçeve dışı gövde 400
router.post('/ctype-secure', express.text({ type: '*/*' }), (req, res) => {
  mark(res, 'PARSER-CTYPE-01-SECURE', 'A03-Injection', 'secure');
  try { JSON.parse(req.body || '{}'); } catch { return res.status(400).json({ error: 'JSON bekleniyor' }); }
  res.json({ ok: true });
});

// VULN: ?_method=DELETE kaynağı siler (fiil karmaşası)
const parserStore = { f1: 'dosya-1' };
router.get('/resource', (req, res) => {
  mark(res, 'PARSER-METHOD-01', 'A01-AccessControl', 'vulnerable');
  if (String(req.query._method || '').toUpperCase() === 'DELETE') {
    delete parserStore.f1; // GET ile SİLME!
    return res.send('<h1>SİLİNDİ</h1><p>?_method=DELETE ile GET üzerinden silme (fiil karmaşası)</p>');
  }
  res.send(`<h1>Kaynak</h1><p>f1=${escHtml(parserStore.f1 || 'silinmiş')}</p>`);
});
// SECURE: _method yoksayılır
router.get('/resource-secure', (req, res) => {
  mark(res, 'PARSER-METHOD-01-SECURE', 'A01-AccessControl', 'secure');
  res.send(`<h1>Kaynak</h1><p>f1=${escHtml(parserStore.f1 || 'silinmiş')} (_method yoksayıldı)</p>`);
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => { parserStore.f1 = 'dosya-1'; });

module.exports = router;

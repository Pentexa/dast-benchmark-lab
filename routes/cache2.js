const express = require('express');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// P1.12 — Paylaşımlı-cache yetkilendirme: URL-anahtarlı önbellek kimliği yoksayar.
// Alice için üretilen yanıt Bob'a HIT olarak döner (PII sızıntısı).

const sharedCache = new Map(); // url -> {body, owner}

function cacheKey(req) {
  return req.path + '?' + Object.keys(req.query).sort().map(k => `${k}=${req.query[k]}`).join('&');
}

// VULN: profil yanıtı kimlikten bağımsız önbelleğe alınıyor
router.get('/profile', (req, res) => {
  mark(res, 'CACHE2-SHARED-01', 'A05-CacheSmuggle', 'vulnerable');
  const key = cacheKey(req);
  const me = req.get('Authorization') || 'anonim';
  if (sharedCache.has(key)) {
    const hit = sharedCache.get(key);
    res.set('X-Cache', 'HIT');
    return res.send(hit.body.replace('CACHE-STATUS', `önbellekten (sahibi: ${escHtml(hit.owner)}, isteyen: ${escHtml(me)})`));
  }
  const u = users.find(x => String(x.id) === String(req.query.user ?? '1'));
  const body = `<h1>Profil</h1><p>${escHtml(u.username)} TCKN=${u.tckn} IBAN=${u.iban}</p><p>CACHE-STATUS</p><p>Cache-Control: public (kimlik anahtarda YOK!)</p>`;
  sharedCache.set(key, { body, owner: me });
  res.set('X-Cache', 'MISS');
  res.send(body.replace('CACHE-STATUS', 'yeni üretildi (MISS)'));
});
// SECURE: özel + Vary
router.get('/profile-secure', (req, res) => {
  mark(res, 'CACHE2-SHARED-01-SECURE', 'A05-CacheSmuggle', 'secure');
  const u = users.find(x => String(x.id) === String(req.query.user ?? '1'));
  res.set('Cache-Control', 'private, no-store').set('Vary', 'Authorization');
  res.send(`<h1>Profil</h1><p>${escHtml(u.username)} (maskeli)</p>`);
});

// VULN: yansıma + public cache = ikinci kullanıcıya XSS servisi
router.get('/search', (req, res) => {
  mark(res, 'CACHE2-POISON-01', 'A05-CacheSmuggle', 'vulnerable');
  const key = cacheKey(req);
  if (sharedCache.has(key)) {
    res.set('X-Cache', 'HIT');
    return res.send(sharedCache.get(key).body);
  }
  const q = String(req.query.q || '');
  const body = `<h1>Arama</h1><p>${q}</p><p>Cache-Control: public, max-age=3600 (yansıma önbelleğe yazıldı!)</p>`;
  sharedCache.set(key, { body, owner: req.get('Authorization') || 'anonim' });
  res.set('X-Cache', 'MISS');
  res.send(body);
});
// SECURE: yansıma yok + no-store
router.get('/search-secure', (req, res) => {
  mark(res, 'CACHE2-POISON-01-SECURE', 'A05-CacheSmuggle', 'secure');
  res.set('Cache-Control', 'no-store');
  res.send(`<h1>Arama</h1><p>${escHtml(String(req.query.q || ''))}</p>`);
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => { sharedCache.clear(); });

module.exports = router;

const express = require('express');
const jwt = require('jsonwebtoken');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// Juice Shop seviyesi: JS-render SPA + auth-gated API + çok adımlı zincirler.
// Felsefe: crawler JS çalıştırmalı, tarayıcı login olup token taşımalı,
// bazı bulgular ZİNCİR gerektirir (profil oku -> escalation -> admin işlev).
// Demo hesaplar login sayfasında yazar: alice/alice123, bob/bob123, admin/admin123.

const SECRET = 'app-secret-key';
const CAPTCHA_TEST_KEY = 'test123-captcha-bypass'; // SADECE app.js bundle yorumunda yazar (JS parse eden bulur)

// --- uygulama durumu (mock DB) ---
const profiles = {
  1: { id: 1, username: 'alice', address: 'Caferağa Mah. No:1 İstanbul', secQ: 'İlk evcil hayvanın?', secA: 'Pamuk' },
  2: { id: 2, username: 'bob', address: 'Alsancak No:5 İzmir', secQ: 'İlk evcil hayvanın?', secA: 'Pamuk' },
  99: { id: 99, username: 'admin', address: 'Çankaya No:99 Ankara', secQ: 'İlk evcil hayvanın?', secA: 'Pamuk' }
};
const baskets = {};            // userId -> [{item, qty, price}]
const wallets = { 1: 500, 2: 500, 99: 99999 };
const orders = { 9001: { id: 9001, user: 'alice', total: 499, items: ['tshirt'] }, 9002: { id: 9002, user: 'bob', total: 2499, items: ['ayakkabi'] } };
let nextOrder = 9003;
const appFeedbacks = [];
const loginHits = {};          // soft throttle sayaçları

function signToken(u) {
  return jwt.sign({ sub: u.id, user: u.username, role: u.role }, SECRET, { algorithm: 'HS256', expiresIn: '12h' });
}
function requireAuth(req, res, next) {
  const t = (req.get('Authorization') || '').replace('Bearer ', '');
  if (!t) return res.status(401).json({ error: 'login gerekli: POST /app/api/login (alice/alice123)' });
  try { req.appUser = jwt.verify(t, SECRET, { algorithms: ['HS256'] }); next(); }
  catch { return res.status(401).json({ error: 'geçersiz token' }); }
}

// ---------- SPA kabuk (crawler JS çalıştırmadan içeriği GÖREMEZ) ----------
router.get('/', (req, res) => {
  mark(res, 'APP-SHELL', 'APP-Shop', 'secure');
  res.send(`<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>MiniShop SPA (mock)</title></head><body>
  <nav><a href="#/login">Giriş</a> | <a href="#/basket">Sepet</a> | <a href="#/checkout">Ödeme</a> | <a href="#/track">Sipariş Takip</a></nav>
  <div id="app">yükleniyor...</div>
  <script src="/app/app.js"></script>
  <noscript>Bu mağaza JavaScript gerektirir.</noscript></body></html>`);
});

// ---------- JS bundle: gizli API yolları + test anahtarı BURADA ----------
router.get('/app.js', (req, res) => {
  mark(res, 'APP-BUNDLE', 'APP-Shop', 'secure');
  res.type('application/javascript').send(`// MiniShop bundle (mock)
// demo hesaplar: alice/alice123, bob/bob123, admin/admin123
// DEV NOTU: captcha test anahtarı header X-Captcha: ${CAPTCHA_TEST_KEY}
const API = {
  login: '/app/api/login', profile: '/app/api/profile', basket: '/app/api/basket',
  checkout: '/app/api/checkout', wallet: '/app/api/wallet/topup', refund: '/app/api/refund',
  track: '/app/api/track/9001', address: '/app/api/address/1', users: '/app/api/users',
  feedback: '/app/api/feedback', share: '/app/share', recovery: '/app/api/recovery',
  internal: '/app/api/internal/config', // dahili panel (sadece admin görmeli?)
  debug: '/app/api/debug', avatar: '/app/api/avatar?url='
};
function api(path, opts) {
  const t = localStorage.getItem('token');
  return fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json', 'Authorization': t ? 'Bearer ' + t : '' } }, opts || {}));
}
window.addEventListener('hashchange', () => {
  const h = location.hash || '#/login';
  const el = document.getElementById('app');
  if (h === '#/login') el.innerHTML = '<h1>Giris</h1><input id=u value=alice><input id=p type=password value=alice123><button onclick="login()">Giris</button><p>demo: alice/alice123</p>';
  else if (h === '#/basket') api(API.basket).then(r => r.text()).then(t => el.innerHTML = t);
  else if (h === '#/track') { const id = prompt('siparis no', '9001'); api('/app/api/track/' + id).then(r => r.text()).then(t => el.innerHTML = t); }
  else el.innerHTML = '<p>' + h + ' yükleniyor...</p>';
});
async function login() {
  const r = await api(API.login, { method: 'POST', body: JSON.stringify({ username: document.getElementById('u').value, password: document.getElementById('p').value }) });
  const j = await r.json();
  if (j.token) { localStorage.setItem('token', j.token); location.hash = '#/basket'; }
  else alert('hata: ' + JSON.stringify(j));
}`);
});

// ---------- Auth: soft-throttle var, kilit YOK (kaba kuvvet mümkün) ----------
router.post('/api/login', (req, res) => {
  mark(res, 'APP-AUTH-01', 'APP-Shop', 'vulnerable');
  const ip = req.ip;
  const now = Date.now();
  loginHits[ip] = (loginHits[ip] || []).filter(t => now - t < 60000);
  if (loginHits[ip].length > 30) {
    res.set('Retry-After', '5');
    return res.status(429).json({ error: 'yavaşla (soft throttle — 5 sn bekle, KİLİT YOK)' });
  }
  loginHits[ip].push(now);
  const { username, password } = req.body || {};
  const u = users.find(x => x.username === username && x.password === password);
  if (!u) return res.status(401).json({ error: 'hatalı giriş' });
  res.json({ token: signToken(u), user: u.username, role: u.role });
});

// ---------- Profil: mass-assignment ile role escalation (ZİNCİR 1. halka) ----------
router.get('/api/profile', requireAuth, (req, res) => {
  mark(res, 'APP-PROFILE', 'APP-Shop', 'secure');
  res.json(profiles[req.appUser.sub] || {});
});
router.put('/api/profile', requireAuth, (req, res) => {
  mark(res, 'APP-MASS-01', 'APP-Shop', 'vulnerable');
  const p = profiles[req.appUser.sub];
  Object.assign(p, req.body); // role dahil her şey yazılıyor!
  const escalated = req.body && req.body.role === 'admin';
  res.json({ profile: p, ...(escalated ? { admin_token: signToken({ ...users.find(u => u.id === req.appUser.sub), role: 'admin' }), note: 'ROLE ESCALATION! Bu token ile admin işlevler açılır (ZİNCİR tamamlandı)' } : { note: '{"role":"admin"} gönder' }) });
});

// ---------- IDOR: adres + sipariş takip (auth var, sahiplik YOK) ----------
router.get('/api/address/:id', requireAuth, (req, res) => {
  mark(res, 'APP-ADDR-01', 'APP-Shop', 'vulnerable');
  const p = profiles[req.params.id];
  if (!p) return res.status(404).json({ error: 'yok' });
  res.json({ ...p, note: 'başkasının adresi: /app/api/address/99 (auth var, sahiplik yok)' });
});
router.get('/api/track/:id', requireAuth, (req, res) => {
  mark(res, 'APP-TRACK-01', 'APP-Shop', 'vulnerable');
  const o = orders[req.params.id];
  if (!o) return res.status(404).json({ error: 'yok' });
  res.json({ ...o, note: 'sıralı ID gez: 9001, 9002... (sahiplik yok)' });
});

// ---------- Sepet: para birimi karışıklığı ----------
router.post('/api/basket', requireAuth, (req, res) => {
  mark(res, 'APP-BASKET-01', 'APP-Shop', 'vulnerable');
  const { item = 'tshirt', qty = 1, price = 499, currency = 'TRY' } = req.body || {};
  const total = Number(price) * Number(qty); // currency DOĞRULANMIYOR
  baskets[req.appUser.sub] = [{ item, qty, price, currency }];
  res.json({ basket: baskets[req.appUser.sub], charged_try: total, note: `currency=${currency} yoksayıldı: {"price":2499,"currency":"USD"} 2499 TRY yerine 2499 birim sayılır` });
});
// GET ile sepet değişikliği (CSRF-able) + token'lı güvenli ikiz
router.get('/api/basket/add', requireAuth, (req, res) => {
  mark(res, 'APP-CSRF-01', 'APP-Shop', 'vulnerable');
  const { item = 'tshirt' } = req.query;
  (baskets[req.appUser.sub] = baskets[req.appUser.sub] || []).push({ item, qty: 1, price: 1 });
  res.json({ ok: true, note: 'GET ile sepet değişti (1 TL fiyatla!) — <img src=/app/api/basket/add?item=ayakkabi> tuzağına düşer' });
});
router.get('/api/csrf-token', requireAuth, (req, res) => {
  mark(res, 'APP-CSRF-TOKEN', 'APP-Shop', 'secure');
  const t = 'csrf-' + Math.random().toString(36).slice(2);
  res.cookie('csrf', t, { sameSite: 'Lax' });
  res.json({ csrf: t });
});
router.post('/api/basket/add', requireAuth, (req, res) => {
  mark(res, 'APP-CSRF-01-SECURE', 'APP-Shop', 'secure');
  if (req.get('X-CSRF') !== req.cookies.csrf || !req.cookies.csrf) return res.status(403).json({ error: 'CSRF token gerekli (/app/api/csrf-token)' });
  (baskets[req.appUser.sub] = baskets[req.appUser.sub] || []).push({ item: (req.body || {}).item || 'tshirt', qty: 1, price: 499 });
  res.json({ ok: true, note: 'token doğrulandı, fiyat sunucudan' });
});

// ---------- Ödeme: kupon İSTİFLEME (hepsi uygulanır, tek-kullanım yok) ----------
router.post('/api/checkout', requireAuth, (req, res) => {
  mark(res, 'APP-COUPON-01', 'APP-Shop', 'vulnerable');
  const { codes = [] } = req.body || {};
  const basket = baskets[req.appUser.sub] || [{ item: 'tshirt', qty: 1, price: 499 }];
  const subtotal = basket.reduce((s, i) => s + i.price * i.qty, 0);
  const discount = codes.length * 100; // her kod -100, sınır yok!
  res.json({ subtotal, codes, discount, total: Math.max(0, subtotal - discount), order_id: nextOrder++, note: '{"codes":["A","B","C","D","E","F"]} 6 kupon istifle!' });
});

// ---------- Cüzdan: negatif yükleme bakiyeyi ARTIRIR ----------
router.post('/api/wallet/topup', requireAuth, (req, res) => {
  mark(res, 'APP-WALLET-01', 'APP-Shop', 'vulnerable');
  const amount = Number((req.body || {}).amount ?? 0);
  wallets[req.appUser.sub] = (wallets[req.appUser.sub] || 0) + amount; // işaret kontrolü YOK
  if (amount < 0) wallets[req.appUser.sub] -= 2 * amount; // negatif "iade" iki kez işlenir (mock muhasebe hatası)
  res.json({ balance: wallets[req.appUser.sub], note: '{"amount":-1000} dene — bakiye artar!' });
});

// ---------- İade: aynı sipariş sınırsız iade edilir ----------
router.post('/api/refund', requireAuth, (req, res) => {
  mark(res, 'APP-REFUND-01', 'APP-Shop', 'vulnerable');
  const { orderId } = req.body || {};
  const o = orders[orderId];
  if (!o) return res.status(404).json({ error: 'sipariş yok (9001 dene)' });
  wallets[req.appUser.sub] = (wallets[req.appUser.sub] || 0) + o.total; // kullanıldı işareti YOK
  res.json({ refunded: o.total, balance: wallets[req.appUser.sub], note: 'aynı orderId ile tekrar iade al!' });
});

// ---------- Güvenlik sorusuyla reset: cevap profilde yazıyor (ZİNCİR) ----------
router.post('/api/reset', (req, res) => {
  mark(res, 'APP-RESET-01', 'APP-Shop', 'vulnerable');
  const { username = '', answer = '' } = req.body || {};
  const id = (users.find(u => u.username === username) || {}).id;
  if (id && profiles[id] && profiles[id].secA.toLowerCase() === String(answer).toLowerCase()) {
    return res.json({ ok: true, temp_password: 'Temp123!', note: `${username} şifresi sıfırlandı! Cevap herkesin profilinde (secQ) — admin için de "Pamuk" dene` });
  }
  res.status(400).json({ error: 'cevap yanlış', hint: 'önce /app/api/profile oku (secQ/secA), sonra {"username":"admin","answer":"..."} dene' });
});

// ---------- BFLA: internal config (auth var, rol YOK) ----------
router.get('/api/internal/config', requireAuth, (req, res) => {
  mark(res, 'APP-BFLA-01', 'APP-Shop', 'vulnerable');
  res.json({ db: 'postgres://app:Sup3rS3cret!@db-internal:5432/shop', stripe: 'sk_live_mock_123', note: `rolün ${req.appUser.role} ama config döküldü (BFLA)` });
});

// ---------- Debug kapısı: başlıkla açılan iç panel ----------
router.get('/api/debug', requireAuth, (req, res) => {
  mark(res, 'APP-DEBUG-01', 'APP-Shop', 'vulnerable');
  if (req.get('X-Debug') !== '1') return res.status(404).json({ error: 'yok' });
  res.json({ env: { DB_PASSWORD: 'Sup3rS3cret!', NODE_ENV: 'production' }, note: 'X-Debug: 1 header ile gizli panel açıldı' });
});

// ---------- Auth-gated SSRF: avatar proxy ----------
router.get('/api/avatar', requireAuth, (req, res) => {
  const url = String(req.query.url || '');
  mark(res, 'APP-AVATAR-01', 'APP-Shop', 'vulnerable');
  if (!url) return res.send('<h1>Avatar proxy</h1><p>?url=http://169.254.169.254/ dene (login gerekli — auth-gated SSRF)</p>');
  if (/169\.254\.|localhost|127\.0\.0\.1|metadata/i.test(url)) {
    return res.send(`<h1>Avatar (mock fetch)</h1><pre>role: admin\nsecret: MOCK-SSRF-LEAK-12345</pre><p>URL: ${escHtml(url)}</p>`);
  }
  res.send(`<h1>Avatar (mock fetch)</h1><p>${escHtml(url)}</p>`);
});

// ---------- Kullanıcı listesi: auth var, yetki YOK ----------
router.get('/api/users', requireAuth, (req, res) => {
  mark(res, 'APP-ENUM-01', 'APP-Shop', 'vulnerable');
  res.json(users.map(u => ({ id: u.id, username: u.username, email: u.email, role: u.role })));
});

// ---------- Geri bildirim: CAPTCHA (test anahtarı bundle'da) + stored XSS ----------
router.post('/api/feedback', requireAuth, (req, res) => {
  mark(res, 'APP-FEED-01', 'APP-Shop', 'vulnerable');
  if (req.get('X-Captcha') !== CAPTCHA_TEST_KEY) {
    return res.status(403).json({ error: 'captcha gerekli', hint: 'anahtar /app/app.js bundle yorumunda (JS parse et)' });
  }
  const { message = '' } = req.body || {};
  appFeedbacks.push({ user: req.appUser.user, message, ts: new Date().toISOString() });
  res.json({ ok: true, note: 'admin panelinde incelenecek: GET /app/api/feedback-view (admin JWT gerekli)' });
});
router.get('/api/feedback-view', requireAuth, (req, res) => {
  mark(res, 'APP-FEEDVIEW-01', 'APP-Shop', 'vulnerable');
  if (req.appUser.role !== 'admin') return res.status(403).json({ error: 'admin gerekli — önce PUT /app/api/profile {"role":"admin"} (ZİNCİR)' });
  res.send(`<h1>Admin feedback (mock)</h1>${appFeedbacks.map(f => `<div><b>${f.user}:</b> ${f.message}</div>`).join('') || '<p>yok</p>'}`);
});

// ---------- Sepet paylaş: JWT URL'de ----------
router.get('/share', requireAuth, (req, res) => {
  const t = (req.get('Authorization') || '').replace('Bearer ', '');
  mark(res, 'APP-TOKEN-01', 'APP-Shop', 'vulnerable');
  res.send(`<h1>Sepeti paylaş</h1><p><a href="/app/share?token=${t}">Paylaşım linkin</a></p><p>JWT URL'de taşınıyor (log/proxy geçmişine düşer).</p>`);
});

// ---------- Kurtarma kodları: sıralı/tahmin edilebilir ----------
const recCodes = { alice: 'REC-1001', bob: 'REC-1002', admin: 'REC-1003' };
router.get('/api/recovery', (req, res) => {
  const user = String(req.query.user || '');
  mark(res, 'APP-RECOVERY-01', 'APP-Shop', 'vulnerable');
  if (!user) return res.send('<h1>Kurtarma</h1><p>?user=alice dene (kodlar sıralı: REC-1001, 1002...)</p>');
  if (recCodes[user]) return res.send(`<h1>Kurtarma kodu gönderildi (mock)</h1><p>${user}: <code>${recCodes[user]}</code> — tahmin edilebilir!</p>`);
  res.status(404).send('kullanıcı yok');
});

// ---------- E-posta değişikliği: doğrulamasız anında aktif (hesap gaspı) ----------
router.post('/api/email', requireAuth, (req, res) => {
  mark(res, 'APP-EMAIL-01', 'APP-Shop', 'vulnerable');
  const { email = '' } = req.body || {};
  const p = profiles[req.appUser.sub];
  const old = users.find(u => u.id === req.appUser.sub);
  if (old) old.email = email;
  res.json({ ok: true, email, note: 'Doğrulama linki gönderildi AMA adres anında değişti! (kurbanın adresini yaz + resetle = gasp)' });
});

// ---------- Hediye çeki basımı: tutar client'tan, rol kontrolsüz ----------
const giftcards = {};
let giftSeq = 5000;
router.post('/api/giftcard', requireAuth, (req, res) => {
  mark(res, 'APP-GIFT-01', 'APP-Shop', 'vulnerable');
  const amount = Number((req.body || {}).amount ?? 0);
  const code = 'GIFT-' + (giftSeq++);
  giftcards[code] = amount; // tutar doğrulanmıyor, herkes basabilir
  res.json({ code, amount, note: '{"amount":100000} ile kendine çek bas!' });
});

// ---------- Puan transferi: negatif tutar havadan yaratır ----------
const points = { 1: 100, 2: 100, 99: 9999 };
router.post('/api/points', requireAuth, (req, res) => {
  mark(res, 'APP-POINTS-01', 'APP-Shop', 'vulnerable');
  const { to, amount = 0 } = req.body || {};
  const from = req.appUser.sub;
  points[from] = (points[from] || 0) - Number(amount); // işaret kontrolü YOK
  points[to] = (points[to] || 0) + Number(amount);
  res.json({ balances: { [from]: points[from], [to]: points[to] }, note: '{"to":1,"amount":-5000} ile başkasından kendine akıt!' });
});

// ---------- Kargo ücreti: ağırlık client'tan ----------
router.post('/api/shipping', requireAuth, (req, res) => {
  mark(res, 'APP-SHIP-01', 'APP-Shop', 'vulnerable');
  const weight = Number((req.body || {}).weight ?? 1);
  res.json({ weight, cost_try: weight * 10, note: '{"weight":0} bedava ekspres, {"weight":-5} üstüne para!' });
});

// ---------- Kayıt oracle: kullanıcı adı enumeration ----------
router.post('/api/register-check', (req, res) => {
  mark(res, 'APP-REG-01', 'APP-Shop', 'vulnerable');
  const { username = '' } = req.body || {};
  const taken = users.some(u => u.username === username);
  res.status(taken ? 409 : 200).json(taken ? { error: 'bu kullanıcı adı alınmış' } : { ok: true, note: 'müsait (admin/bob/root dene — 409 = kayıtlı!)' });
});
router.post('/api/register-check-secure', (req, res) => {
  mark(res, 'APP-REG-01-SECURE', 'APP-Shop', 'secure');
  res.json({ ok: true, note: 'kayıt isteği alındı, sonuç e-postayla (oracle yok)' });
});

// ---------- Scanner score-board: coverage haritası (ölçüm altyapısı, GT dışı) ----------
// BLIND MODDA KAPALI: beklenti sütunu cevap verir.
router.get('/coverage', (req, res) => {
  try {
    if (require('../lib/mode').isBlind()) return res.status(404).send('<h1>404</h1><p>Referans: ERR-404</p>');
  } catch {}
  mark(res, 'APP-COVERAGE', 'APP-Shop', 'secure');
  const fs = require('fs');
  let hitPaths = new Set();
  try {
    const f = require('../lib/requestLogger').logFile;
    fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).forEach(line => {
      try {
        const e = JSON.parse(line);
        const p = (e.url || '').split('?')[0].replace(/\/$/, '') || '/';
        hitPaths.add(p);
      } catch {}
    });
  } catch {}
  const gt = require('../ground-truth.json');
  const rows = gt.map(g => {
    const gp = g.path.replace(/\/$/, '').replace(/\/:[^/]+/g, '/1').replace(/\.css$/, '/1.css');
    const hit = [...hitPaths].some(h => h === gp || (g.id === 'MIS-DIR-01' && h.startsWith(gp + '/')) || (g.path.includes(':') && h.startsWith(gp.split('/1')[0] + '/')));
    const exact = hitPaths.has(gp);
    return { id: g.id, path: g.path, category: g.category, expectation: g.expectation, hit: hit || exact };
  });
  const hit = rows.filter(r => r.hit).length;
  res.send(`<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>Coverage</title>
  <style>body{font-family:system-ui;max-width:900px;margin:20px auto}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:5px;font-size:12px}.h{background:#dfd}.m{background:#fdd}</style></head><body>
  <h1>🎯 Scanner coverage: ${hit}/${rows.length} (%${(100 * hit / rows.length).toFixed(1)})</h1>
  <p>requests.log'a göre hangi GT endpoint'ine en az 1 istek geldi. Vurulmayan = tarayıcı oraya hiç gitmedi (kapsama dışı FN adayı).</p>
  <table><tr><th>ID</th><th>Path</th><th>Kategori</th><th>Durum</th></tr>${rows.map(r => `<tr class="${r.hit ? 'h' : 'm'}"><td>${r.id}</td><td><code>${r.path}</code></td><td>${r.category}</td><td>${r.hit ? '✅ dokunuldu' : '❌ dokunulmadı'}</td></tr>`).join('')}</table></body></html>`);
});

// Başlangıç anlık görüntüsü + taramalar arası sıfırlama (P0 reset registry)
const SHOPAPP_SNAPSHOT = JSON.parse(JSON.stringify({ profiles, wallets, orders, points }));
const USERS_SNAPSHOT = JSON.parse(JSON.stringify(users));
require('../lib/stateReset').onReset(() => {
  for (const k of Object.keys(profiles)) delete profiles[k];
  Object.assign(profiles, JSON.parse(JSON.stringify(SHOPAPP_SNAPSHOT.profiles)));
  for (const k of Object.keys(baskets)) delete baskets[k];
  for (const k of Object.keys(wallets)) delete wallets[k];
  Object.assign(wallets, JSON.parse(JSON.stringify(SHOPAPP_SNAPSHOT.wallets)));
  for (const k of Object.keys(orders)) delete orders[k];
  Object.assign(orders, JSON.parse(JSON.stringify(SHOPAPP_SNAPSHOT.orders)));
  nextOrder = 9003;
  appFeedbacks.length = 0;
  for (const k of Object.keys(loginHits)) delete loginHits[k];
  for (const k of Object.keys(giftcards)) delete giftcards[k];
  giftSeq = 5000;
  for (const k of Object.keys(points)) delete points[k];
  Object.assign(points, JSON.parse(JSON.stringify(SHOPAPP_SNAPSHOT.points)));
  users.forEach((u, i) => { u.email = USERS_SNAPSHOT[i].email; });
});

module.exports = router;

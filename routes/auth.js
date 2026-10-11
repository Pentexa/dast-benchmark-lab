const express = require('express');
const jwt = require('jsonwebtoken');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();
const SECRET = 'mock-secret-key';

// Zayıf reset token: tahmin edilebilir
const resetTokens = { 'alice': '1234' };

// ---------- JWT none ----------
router.get('/jwt-none', (req, res) => {
  mark(res, 'AUTH-JWT-01', 'A07-Auth', 'vulnerable');
  const token = (req.query.token || req.get('Authorization') || '').replace('Bearer ', '');
  if (!token) return res.send('<h1>JWT demo</h1><p>?token= ile dene. alg:none kabul ediliyor (zafiyet).</p>');
  const parts = String(token).split('.');
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const payload = JSON.parse(Buffer.from(parts[1] || 'e30=', 'base64').toString());
    if (header.alg === 'none') {
      return res.send(`<h1>Hoşgeldin ${escHtml(payload.user || payload.sub || 'anon')} (alg:none ile doğrulamasız!)</h1><p>Role: ${escHtml(payload.role || 'admin')}</p>`);
    }
    const v = jwt.verify(token, SECRET);
    res.send(`<h1>Hoşgeldin ${escHtml(v.user)}</h1>`);
  } catch (e) {
    // none alg'li bozuk token'ı bile kabul et (zafiyet simülasyonu)
    if (String(token).toLowerCase().includes('none')) return res.send('<h1>Hoşgeldin attacker (alg:none bypass!)</h1><p>Role: admin</p>');
    res.status(401).send('Invalid token: ' + escHtml(e.message));
  }
});

router.get('/jwt-secure', (req, res) => {
  mark(res, 'AUTH-JWT-01-SECURE', 'A07-Auth', 'secure');
  const token = (req.query.token || req.get('Authorization') || '').replace('Bearer ', '');
  if (!token) return res.status(401).send('Token gerekli');
  try {
    const v = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
    res.send(`<h1>Hoşgeldin ${escHtml(v.user)}</h1>`);
  } catch (e) {
    res.status(401).send('Invalid token');
  }
});
router.get('/jwt-issue', (req, res) => {
  mark(res, 'AUTH-JWT-ISSUE', 'A07-Auth', 'secure');
  const t = jwt.sign({ user: 'alice', role: 'user' }, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
  res.send(`Token (HS256): <code>${t}</code><p>/auth/jwt-secure?token=... ile dene. alg:none reddedilir.</p>`);
});

// ---------- Predictable reset ----------
router.get('/reset', (req, res) => {
  const { user = 'alice', token = '' } = req.query;
  mark(res, 'AUTH-RESET-01', 'A07-Auth', 'vulnerable');
  if (!token) return res.send(`<h1>Şifre sıfırlama</h1><p>Kullanıcı ${escHtml(user)} için token gönderildi. (ipucu: 4 haneli, 1234?)</p><form><input name="user" value="${escHtml(user)}"/><input name="token" placeholder="token"/><button>Doğrula</button></form>`);
  if (resetTokens[user] === String(token)) return res.send(`<h1>Token geçerli!</h1><p>${escHtml(user)} şifresini sıfırlayabilirsin. (tahmin edilebilir token zafiyeti)</p>`);
  res.status(400).send('<h1>Geçersiz token</h1>');
});

// ---------- Brute force koruması yok ----------
let attempts = 0;
router.post('/bruteforce', express.urlencoded({ extended: true }), (req, res) => {
  mark(res, 'AUTH-BRUTE-01', 'A07-Auth', 'vulnerable');
  attempts++;
  const { username, password } = req.body || {};
  const u = users.find(x => x.username === username && x.password === password);
  if (u) return res.send(`<h1>Giriş başarılı (${attempts}. deneme)</h1>`);
  res.status(401).send(`<h1>Başarısız (${attempts}. deneme, rate-limit yok, captcha yok)</h1>`);
});

// ---------- Session fixation mock ----------
router.get('/session-fixation', (req, res) => {
  mark(res, 'AUTH-SESS-01', 'A07-Auth', 'vulnerable');
  const sid = req.query.sid || 'sabit-session-id-123';
  res.cookie('sessionid', sid, { httpOnly: false });
  res.send(`<h1>Login</h1><p>Session ID URL'den alındı ve sabitlendi: <code>${escHtml(sid)}</code> (HttpOnly yok, regenerate yok)</p>`);
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => { attempts = 0; });

module.exports = router;

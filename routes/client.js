const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// Güncel client-side yüzeyi: postMessage / JSONP / markdown / clobber / proto-pollution / js-redirect.
// DAST'ler JS çalıştıranlar (ZAP ajax, Burp) bunları pasif/kısmi yakalar — FN/FP ayrımı için birebir.

// ---------- postMessage XSS (VULN: origin kontrolsüz + innerHTML) ----------
router.get('/chat', (req, res) => {
  mark(res, 'CL-PM-01', 'Client-Side', 'vulnerable');
  res.send(`<h1>Sohbet widget (mock)</h1><div id="box"></div>
  <script>
    window.addEventListener('message', (e) => {
      document.getElementById('box').innerHTML = 'Mesaj: ' + e.data; // origin kontrolü YOK, innerHTML sink
    });
  </script>`);
});
router.get('/chat-secure', (req, res) => {
  mark(res, 'CL-PM-01-SECURE', 'Client-Side', 'secure');
  res.send(`<h1>Sohbet widget (güvenli)</h1><div id="box"></div>
  <script>
    window.addEventListener('message', (e) => {
      if (e.origin !== location.origin) return;
      document.getElementById('box').textContent = 'Mesaj: ' + e.data;
    });
  </script>`);
});

// ---------- JSONP callback XSS (VULN) ----------
router.get('/jsonp', (req, res) => {
  const cb = req.query.callback ?? 'cb';
  mark(res, 'CL-JSONP-01', 'Client-Side', 'vulnerable');
  res.type('application/javascript');
  res.send(`${cb}({"user":"alice","email":"alice@example.com"});`); // callback doğrulanmıyor
});

// ---------- Markdown stored XSS (VULN: ham HTML render) ----------
const notes = [{ md: '# Hoşgeldin\nGüvenli not.' }];
router.get('/notes', (req, res) => {
  mark(res, 'CL-MD-01', 'Client-Side', 'vulnerable');
  res.send(`<h1>Notlar (markdown, filtresiz)</h1>${notes.map(n => `<div class="note">${n.md}</div>`).join('')}
  <form method="POST" action="/client/notes"><textarea name="md" rows="3" cols="50" placeholder="<svg onload=alert(1)>"></textarea><br/><button>Kaydet</button></form>`);
});
router.post('/notes', express.urlencoded({ extended: true }), (req, res) => {
  mark(res, 'CL-MD-01', 'Client-Side', 'vulnerable');
  notes.push({ md: req.body.md || '' });
  res.redirect('/client/notes');
});
router.get('/notes-secure', (req, res) => {
  mark(res, 'CL-MD-01-SECURE', 'Client-Side', 'secure');
  const clean = notes.map(n => `<div class="note">${escHtml(n.md)}</div>`).join('');
  res.send(`<h1>Notlar (sanitize'lı)</h1>${clean}<p>Ham HTML strip ediliyor.</p>`);
});

// ---------- DOM clobbering (VULN) ----------
router.get('/clobber', (req, res) => {
  mark(res, 'CL-CLOBBER-01', 'Client-Side', 'vulnerable');
  const html = req.query.html ?? '';
  res.send(`<h1>Profil</h1>${html}
  <script>
    const cfg = window.config || { url: '/api/account' }; // named element window.config'i ezer (clobber)
    fetch(cfg.url).then(r => r.text()).then(t => document.body.insertAdjacentHTML('beforeend', '<pre>'+t.slice(0,200)+'</pre>'));
  </script><p>?html=&lt;input name=config&gt; dene — window.config clobber olur.</p>`);
});

// ---------- Prototype pollution (VULN, mock merge) ----------
let polluted = {};
router.post('/pollute', (req, res) => {
  mark(res, 'CL-PPOLL-01', 'Client-Side', 'vulnerable');
  const b = req.body || {};
  if (JSON.stringify(b).includes('__proto__') || JSON.stringify(b).includes('constructor')) {
    Object.assign(polluted, { isAdmin: true });
    return res.json({ ok: true, note: 'prototype kirletildi (mock merge): {"__proto__":{"isAdmin":true}}', polluted });
  }
  res.json({ ok: true, polluted, note: '{"__proto__":{"isAdmin":true}} gönder' });
});
router.get('/pollute', (req, res) => {
  mark(res, 'CL-PPOLL-01', 'Client-Side', 'vulnerable');
  res.json({ isAdmin: !!polluted.isAdmin, note: polluted.isAdmin ? 'KİRLENDİ: admin kontrolü atlatıldı!' : 'temiz' });
});

// ---------- Query-string proto pollution (?__proto__[isAdmin]=true) ----------
// Zayıf merge rutinleri qs çıktısını körü körüne birleştirir (mock).
let qPolluted = false;
router.get('/pollute-q', (req, res) => {
  mark(res, 'CL-PPOLLQ-01', 'Client-Side', 'vulnerable');
  if (req.originalUrl.includes('__proto__') || req.originalUrl.includes('constructor.prototype')) {
    qPolluted = true;
  }
  res.json({ isAdmin: qPolluted, note: qPolluted ? 'QUERY İLE KİRLENDİ!' : '?__proto__[isAdmin]=true dene' });
});

// ---------- javascript:/data: open redirect (VULN) ----------
router.get('/goto', (req, res) => {
  const next = req.query.next ?? '/dashboard';
  mark(res, 'CL-GOTO-01', 'Client-Side', 'vulnerable');
  const low = String(next).toLowerCase().trim();
  if (low.startsWith('javascript:') || low.startsWith('data:')) {
    return res.send(`<a href="${escHtml(next)}">devam et</a><script>location.href = ${JSON.stringify(next)};</script><p>javascript:/data: scheme'e izin verildi!</p>`);
  }
  res.redirect(String(next).replace(/[^\x20-\x7E]/g, '?')); // header latin1-safe
});
router.get('/goto-secure', (req, res) => {
  const next = req.query.next ?? '/dashboard';
  mark(res, 'CL-GOTO-01-SECURE', 'Client-Side', 'secure');
  const s = String(next);
  // site-içi yol: tek '/' ile başlar; '//evil' (scheme-relative) ve '\' kaçamakları yasak
  if (!s.startsWith('/') || s.startsWith('//') || s.includes('\\')) return res.status(400).send('sadece site-içi yol');
  res.redirect(s);
});

module.exports = router;

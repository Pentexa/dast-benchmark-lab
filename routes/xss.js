const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// ---------- Reflected XSS ----------
// VULN: encode yok
router.get('/reflected', (req, res) => {
  const name = req.query.name ?? '';
  mark(res, 'XSS-REFL-01', 'A03-XSS', 'vulnerable');
  res.send(`<h1>Arama</h1><p>Sonuçlar: ${name}</p><form><input name="name" value="${name}" placeholder="ara"/><button>Ara</button></form>`);
});

// SECURE + FP-TRAP: yansıtıyor ama düzgün encode'lu. Zayıf tarayıcı FP üretir, iyi tarayıcı TN bırakır.
router.get('/reflected-secure', (req, res) => {
  const name = req.query.name ?? '';
  mark(res, 'XSS-REFL-01-SECURE', 'A03-XSS', 'secure');
  res.send(`<h1>Arama</h1><p>Sonuçlar: ${escHtml(name)}</p><form><input name="name" value="${escHtml(name)}" placeholder="ara"/><button>Ara</button></form>`);
});

// ---------- Stored XSS ----------
// VULN: yorum encode'suz saklanıp listeleniyor
const { comments } = require('../lib/utils');
router.get('/stored', (req, res) => {
  mark(res, 'XSS-STORED-01', 'A03-XSS', 'vulnerable');
  const list = comments.map(c => `<li><b>${c.author}:</b> ${c.text}</li>`).join('');
  res.send(`<h1>Yorumlar</h1><ul>${list}</ul>
    <form method="POST" action="/xss/stored"><input name="author" placeholder="isim"/><input name="text" placeholder="yorum"/><button>Gönder</button></form>`);
});
router.post('/stored', express.urlencoded({ extended: true }), (req, res) => {
  mark(res, 'XSS-STORED-01', 'A03-XSS', 'vulnerable');
  comments.push({ author: req.body.author || 'anon', text: req.body.text || '' });
  res.redirect('/xss/stored');
});

router.get('/stored-secure', (req, res) => {
  mark(res, 'XSS-STORED-01-SECURE', 'A03-XSS', 'secure');
  const list = comments.map(c => `<li><b>${escHtml(c.author)}:</b> ${escHtml(c.text)}</li>`).join('');
  res.send(`<h1>Yorumlar (güvenli)</h1><ul>${list}</ul>`);
});

// ---------- DOM XSS ----------
// VULN: location.hash / query innerHTML'e yazılıyor
router.get('/dom', (req, res) => {
  mark(res, 'XSS-DOM-01', 'A03-XSS', 'vulnerable');
  res.send(`<h1>DOM XSS demo</h1><div id="out"></div>
    <script>
      const p = new URLSearchParams(location.search);
      const v = p.get('default') || 'hoşgeldin';
      document.getElementById('out').innerHTML = 'Merhaba ' + v; // sink: innerHTML
    </script>`);
});

router.get('/dom-secure', (req, res) => {
  mark(res, 'XSS-DOM-01-SECURE', 'A03-XSS', 'secure');
  res.send(`<h1>DOM güvenli demo</h1><div id="out"></div>
    <script>
      const p = new URLSearchParams(location.search);
      const v = p.get('default') || 'hoşgeldin';
      document.getElementById('out').textContent = 'Merhaba ' + v; // safe sink
    </script>`);
});

// ---------- mXSS: innerHTML gidiş-dönüş mutasyonu ----------
// Tarayıcı <noscript><p title="</noscript><img src=x onerror=alert(1)>"> gibi
// mutasyon payload'ıyla ikinci parse'ta patlar (DOMPurify'sız round-trip).
router.get('/mxss', (req, res) => {
  const html = req.query.html ?? '';
  mark(res, 'XSS-MXSS-01', 'A03-XSS', 'vulnerable');
  res.send(`<h1>Önizleme (mXSS demosu)</h1><div id="stage"></div>
    <script>
      const raw = ${JSON.stringify(html)};
      const d = document.getElementById('stage');
      d.innerHTML = raw;                 // 1. parse
      d.innerHTML = d.innerHTML;         // 2. parse (mutasyon! sanitize YOK)
    </script><p>?html=... ile mutation payload dene</p>`);
});

module.exports = router;

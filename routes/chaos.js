const express = require('express');
const crypto = require('crypto');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// Kaos katmanı: enjeksiyon varyantları + motor-farkları + imza-doğrulamasız roller.
// Hepsi MOCK veri; oracle davranışları (sütun sayımı, 49 render, HMAC) GERÇEK.

// ---------- UNION-BASED SQLi (sütun sayacı oracle) ----------
// ?id=1 ORDER BY N (N>3 hata) -> UNION SELECT a,b,c ile dump.
router.get('/union', (req, res) => {
  const id = String(req.query.id ?? '1');
  mark(res, 'CH-UNION-01', 'A03-Injection', 'vulnerable');
  const low = id.toLowerCase();
  const ob = low.match(/order\s+by\s+(\d+)/);
  if (ob) {
    if (parseInt(ob[1], 10) > 3) return res.send(`<h1>Hata</h1><p>Unknown column '${escHtml(ob[1])}' in 'order clause' (sütun sayısı 3!)</p>`);
    return res.send(`<h1>Ürünler</h1><p>ORDER BY ${escHtml(ob[1])} OK — sütun sayısı bul, sonra UNION dene</p>`);
  }
  const un = low.match(/union\s+select\s+(.+)/);
  if (un) {
    const cols = un[1].split(',').length;
    if (cols === 3) {
      return res.send(`<h1>Ürünler</h1><pre>1 | alice | alice@example.com\n2 | bob | bob@example.com\n99 | admin | admin@example.com</pre><p>UNION ile 3 sütun döküldü!</p>`);
    }
    return res.send('<h1>Hata</h1><p>The used SELECT statements have a different number of columns</p>');
  }
  res.send('<h1>Ürünler</h1><p>?id=1 ORDER BY 5 dene (sütun say, sonra UNION SELECT 1,2,3)</p>');
});

// ---------- STACKED QUERIES (; ile ikinci sorgu) ----------
router.get('/stacked', (req, res) => {
  const id = String(req.query.id ?? '1');
  mark(res, 'CH-STACK-01', 'A03-Injection', 'vulnerable');
  const low = id.toLowerCase();
  if (low.includes(';') && /(drop|delete|update|insert|exec|waitfor|shutdown|select\s+@@)/.test(low)) {
    return res.send(`<h1>OK</h1><p>2 result set döndü (stacked query çalıştı — mock, veri silinmedi).</p><p>Girdi: <code>${escHtml(id.slice(0, 80))}</code></p>`);
  }
  res.send('<h1>Ürün</h1><p>?id=1;SELECT @@version dene</p>');
});

// ---------- SECOND-ORDER SQLi (kayıt -> admin listede patlar) ----------
const pendingUsers = [];
router.post('/register2', (req, res) => {
  mark(res, 'CH-2ND-01', 'A03-Injection', 'vulnerable');
  const { username = '' } = req.body || {};
  pendingUsers.push(String(username)); // HAM saklanıyor, doğrulama YOK
  res.json({ ok: true, note: 'kayıt alındı (mock). zararlı kullanıcı adıyla kaydol, sonra /runtime/admin-list bak' });
});
router.get('/admin-list', (req, res) => {
  mark(res, 'CH-2ND-02', 'A03-Injection', 'vulnerable');
  const inClause = pendingUsers.map(u => `'${u}'`).join(',');
  const q = `SELECT * FROM users WHERE username IN (${inClause || "'alice'"})`;
  const evil = pendingUsers.some(u => /' or |union |--|;/.test(u.toLowerCase()));
  if (evil) {
    return res.send(`<h1>Onay bekleyenler</h1><p>Query: <code>${escHtml(q)}</code></p><pre>${escHtml(JSON.stringify(users, null, 2))}</pre><p>SECOND-ORDER: kayıt anında masum görünen girdi, başka sorguda patladı!</p>`);
  }
  res.send(`<h1>Onay bekleyenler</h1><p>Query: <code>${escHtml(q)}</code></p><p>username=admin' OR '1'='1 ile kaydol dene</p>`);
});

// ---------- SSTI motorları (ayrı path = ayrı GT) ----------
function ssti(engine, marker) {
  return (req, res) => {
    const tpl = String(req.query.tpl ?? 'misafir');
    mark(res, marker, 'A03-Injection', 'vulnerable');
    let out = tpl;
    if (engine === 'jinja' && tpl.includes('{{7*7}}')) out = tpl.replace('{{7*7}}', '49');
    if (engine === 'twig' && tpl.includes('{{7*7}}')) out = tpl.replace('{{7*7}}', '49');
    if (engine === 'freemarker' && tpl.includes('${7*7}')) out = tpl.replace('${7*7}', '49');
    if (engine === 'erb' && tpl.includes('<%= 7*7 %>')) out = tpl.replace('<%= 7*7 %>', '49');
    const fired = out !== tpl;
    res.send(`<h1>${engine} render</h1><p>${out}</p>${fired ? `<p>[${engine}] template İŞLENDİ (49!) — SSTI var</p>` : `<p>?tpl= payload dene (${engine === 'erb' ? '&lt;%= 7*7 %&gt;' : engine === 'freemarker' ? '$' + '{7*7}' : '{{7*7}}'})</p>`}`);
  };
}
router.get('/jinja', ssti('jinja', 'CH-SSTI-JINJA'));
router.get('/twig', ssti('twig', 'CH-SSTI-TWIG'));
router.get('/freemarker', ssti('freemarker', 'CH-SSTI-FMT'));
router.get('/erb', ssti('erb', 'CH-SSTI-ERB'));
router.get('/secure', (req, res) => {
  const tpl = String(req.query.tpl ?? 'misafir');
  mark(res, 'CH-SSTI-SEC', 'A03-Injection', 'secure');
  res.send(`<h1>Template (logic-less, güvenli)</h1><p>${escHtml(tpl)}</p><p>motor sözdizimi işlenmez.</p>`);
});

// ---------- İmzasız rol çerezi (base64, MAC yok -> bit-flip) ----------
const ROLE_SECRET = 'hmac-mock-secret';
router.get('/role-cookie', (req, res) => {
  mark(res, 'CH-ROLE-01', 'A07-Auth', 'vulnerable');
  let role = 'user', user = 'misafir';
  try {
    const c = JSON.parse(Buffer.from(req.cookies.role || '', 'base64').toString());
    user = c.user || user; role = c.role || role; // İMZA KONTROLÜ YOK
  } catch { /* ilk ziyaret */ }
  if (!req.cookies.role) res.cookie('role', Buffer.from(JSON.stringify({ user: 'bob', role: 'user' })).toString('base64'), { httpOnly: false });
  if (role === 'admin') return res.send(`<h1>Admin paneli!</h1><p>Hoşgeldin ${escHtml(user)} — çerezde role=admin kabul edildi (imza yok!)</p>`);
  res.send(`<h1>Profil: ${escHtml(user)} (${escHtml(role)})</h1><p>Çerezi base64-decode et, role=admin yap, geri gönder dene</p>`);
});
router.get('/role-cookie-secure', (req, res) => {
  mark(res, 'CH-ROLE-01-SECURE', 'A07-Auth', 'secure');
  const raw = String(req.cookies.srole || '');
  const [b64, sig] = raw.split('.');
  const expect = b64 ? crypto.createHmac('sha256', ROLE_SECRET).update(b64).digest('hex') : '';
  let role = 'user', user = 'misafir', ok = false;
  if (b64 && sig && sig === expect) {
    try { const c = JSON.parse(Buffer.from(b64, 'base64').toString()); user = c.user; role = c.role; ok = true; } catch {}
  }
  if (!req.cookies.srole) {
    const b = Buffer.from(JSON.stringify({ user: 'bob', role: 'user' })).toString('base64');
    res.cookie('srole', b + '.' + crypto.createHmac('sha256', ROLE_SECRET).update(b).digest('hex'), { httpOnly: true, sameSite: 'Lax' });
  }
  if (role === 'admin' && ok) return res.send('<h1>Admin (imzalı çerez doğrulandı)</h1>');
  res.send(`<h1>Profil: ${escHtml(user)} (${escHtml(role)})</h1><p>İmzasız değişim reddedilir.</p>`);
});

// ---------- .htaccess yükleme (config overwrite, mock) ----------
router.post('/upload-htaccess', express.text({ type: '*/*', limit: '100kb' }), (req, res) => {
  mark(res, 'CH-HTACCESS-01', 'A04-FileHandling', 'vulnerable');
  const fname = req.get('X-Filename') || 'not.txt';
  if (fname === '.htaccess' || fname === '.user.ini') {
    return res.send(`<h1>Yüklendi: /uploads/${escHtml(fname)}</h1><p>Sunucu config dosyası üzerine yazıldı (mock)! <code>AddType application/x-httpd-php .jpg</code> ile .jpg'ler PHP çalıştırır.</p>`);
  }
  res.send(`<h1>Yüklendi: /uploads/${escHtml(fname)}</h1><p>X-Filename: .htaccess dene</p>`);
});

// ---------- HTTP verb confusion: GET ile silme çalışıyor ----------
router.delete('/verb-gate', (req, res) => {
  mark(res, 'CH-VERB-01', 'A01-AccessControl', 'vulnerable');
  if (req.get('X-Role') !== 'admin') return res.status(403).json({ error: 'DELETE için admin gerekli' });
  res.json({ ok: true, note: 'silindi (admin)' });
});
router.get('/verb-gate', (req, res) => {
  mark(res, 'CH-VERB-01', 'A01-AccessControl', 'vulnerable');
  if (String(req.query.action || '').toLowerCase() === 'delete') {
    return res.json({ ok: true, note: 'KAYIT SİLİNDİ (mock)! Yetki kontrolü sadece DELETE metodundaydı — GET?action=delete ile geçildi' });
  }
  res.json({ note: '?action=delete dene (403 alman gerekirken işlem çalışır)' });
});

// ---------- Legacy fallback: tanımsız path'i yansıtan 404 (EN SONDA!) ----------
// /legacy/* altında çalışır; klasik gerçek dünya (eski bölümde encode unutulmuş).
router.get('/:page', (req, res) => {
  mark(res, 'CH-LEGACY-01', 'A03-XSS', 'vulnerable');
  res.status(404).send(`<h1>Eski site</h1><p>Aradığın sayfa yok: ${req.params.page}</p><p>/legacy/&lt;script&gt;alert(1)&lt;/script&gt; dene</p>`);
});

module.exports = router;

const express = require('express');
const jwt = require('jsonwebtoken');
const { escHtml, users, mark } = require('../lib/utils');
const router = express.Router();

// Gerçek dünya "runtime davranış" senaryoları: DAST'lerin zaman/fark-oracle ile
// bulduğu türler (time-based, boolean-based, header-based, cache, log, token...).
// Hepsi MOCK veri; ancak zamanlama/fark davranışları GERÇEKTİR (ölçülebilir).

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------- TIME-BASED SQLi (gerçek gecikme) ----------
// SLEEP / WAITFOR / pg_sleep içeren payload -> 3 sn bekletir. Kör tarama bulur.
router.get('/sqli-time', async (req, res) => {
  const id = String(req.query.id ?? '1');
  mark(res, 'RT-TIME-01', 'A03-Injection', 'vulnerable');
  const low = id.toLowerCase();
  if (low.includes('sleep(') || low.includes('waitfor') || low.includes('pg_sleep') || low.includes('benchmark(')) {
    const t0 = Date.now();
    await sleep(3000);
    return res.send(`<h1>Ürün</h1><p>id=${escHtml(id)}</p><p>query_time=${Date.now() - t0}ms (SLEEP çalıştı!)</p>`);
  }
  res.send(`<h1>Ürün</h1><p>id=${escHtml(id)}</p><p>query_time=4ms</p><p>?id=1 AND SLEEP(3) dene</p>`);
});

// ---------- BOOLEAN-BASED SQLi (içerik farkı) ----------
// AND 1=1 -> kayıt var, AND 1=2 -> kayıt yok. Fark-oracle.
router.get('/sqli-bool', (req, res) => {
  const id = String(req.query.id ?? '1');
  mark(res, 'RT-BOOL-01', 'A03-Injection', 'vulnerable');
  const low = id.toLowerCase().replace(/\s+/g, ' ');
  if (/and\s+1\s*=\s*2|'\s*and\s*'1'\s*=\s*'2/.test(low)) {
    return res.send('<h1>Ürünler</h1><p>kayıt bulunamadı.</p>');
  }
  if (/and\s+1\s*=\s*1|'\s*and\s*'1'\s*=\s*'1/.test(low)) {
    return res.send(`<h1>Ürünler</h1><p>id=${escHtml(id)}</p><ul><li>T-Shirt — 499 TL</li></ul>`);
  }
  res.send(`<h1>Ürünler</h1><p>id=${escHtml(id)}</p><ul><li>T-Shirt — 499 TL</li></ul><p>?id=1 AND 1=1 vs AND 1=2 dene</p>`);
});

// ---------- HEADER-BASED SQLi (User-Agent) ----------
// Gerçek dünya: istek loglama / UA istatistiği sorgusu concat ile yazılmış.
router.get('/search-ua', (req, res) => {
  const ua = req.get('User-Agent') || '';
  mark(res, 'RT-HDRSQLI-01', 'A03-Injection', 'vulnerable');
  const low = ua.toLowerCase();
  if (low.includes("' or ") || low.includes(' union ') || low.includes('--')) {
    return res.send(`<h1>Arama</h1><p>SQL syntax error near '${escHtml(ua.slice(0, 60))}'</p><pre>${escHtml(JSON.stringify(users.map(u => u.username)))}</pre>`);
  }
  res.send(`<h1>Arama</h1><p>Hoşgeldin. (User-Agent loglanıyor: <code>${escHtml(ua.slice(0, 80))}</code>)</p>`);
});

// ---------- ORDER BY enjeksiyonu ----------
// sort=name ASC; sort=(CASE WHEN...) / sort=id;SELECT SLEEP
router.get('/list', (req, res) => {
  const sort = String(req.query.sort ?? 'name');
  mark(res, 'RT-ORDERBY-01', 'A03-Injection', 'vulnerable');
  const low = sort.toLowerCase();
  if (/\(select|sleep\(|benchmark\(|--|;/.test(low)) {
    return res.send(`<h1>Sıralama hatası</h1><p>ORDER BY ${escHtml(sort)} — You have an error in your SQL syntax</p>`);
  }
  const rows = [...users].sort().map(u => `<li>${escHtml(u.username)}</li>`).join('');
  res.send(`<h1>Kullanıcılar</h1><p>ORDER BY ${escHtml(sort)}</p><ul>${rows}</ul><p>?sort=email dene</p>`);
});

// ---------- HTTP Parameter Pollution: ?id=1&id=99 ----------
// Express diziye çevirir; kod sonuncuyu alır -> yetki atlatma.
router.get('/hpp', (req, res) => {
  mark(res, 'RT-HPP-01', 'A01-AccessControl', 'vulnerable');
  let id = req.query.id ?? '1';
  if (Array.isArray(id)) id = id[id.length - 1]; // SONUNCU kazanır (zafiyet)
  const u = users.find(x => String(x.id) === String(id));
  if (!u) return res.status(404).send('yok');
  res.send(`<h1>Profil</h1><p>${escHtml(u.username)} — ${escHtml(u.email)} — PAN ${escHtml(u.pan)}</p><p>?id=1&id=99 dene (ikincisi kazanır!)</p>`);
});

// ---------- Magic hash / loose compare (klasik "0e..." bypass) ----------
// Zayıf karşılaştırma simülasyonu: 0e ile başlayan her şey "0"a eşit sayılır.
router.post('/login-magic', (req, res) => {
  mark(res, 'RT-MAGIC-01', 'A07-Auth', 'vulnerable');
  const { username = '', password = '' } = req.body || {};
  const u = users.find(x => x.username === username);
  const looseEq = (a, b) => (/^0e\d+$/.test(String(a)) && /^0e?\d*$/.test(String(b))) || String(a) === String(b);
  if (u && looseEq(password, '0e123456')) {
    return res.send(`<h1>Hoşgeldin ${escHtml(u.username)}!</h1><p>Zayıf == karşılaştırma atlatıldı (magic hash mock).</p>`);
  }
  res.status(401).send('<h1>Başarısız</h1><p>ipucu: hash "0e..." formatında saklanıyor, password=0e9999 dene</p>');
});

// ---------- Cache poisoning: yansımalı + cache'lenebilir arama ----------
// q yansıyor (XSS) VE Cache-Control: public -> zehir tek istekle herkese yayılır.
router.get('/search', (req, res) => {
  const q = req.query.q ?? '';
  mark(res, 'RT-CACHEPOISON-01', 'A05-CacheSmuggle', 'vulnerable');
  res.set({ 'Cache-Control': 'public, max-age=300', 'X-Cache': 'MISS (mock CDN)', 'Age': '0' });
  res.send(`<h1>Sonuçlar: ${q}</h1><p>?q=&lt;script&gt;alert(document.domain)&lt;/script&gt; dene — yanıt cache'leniyor!</p>`);
});
router.get('/search-secure', (req, res) => {
  const q = req.query.q ?? '';
  mark(res, 'RT-CACHEPOISON-01-SECURE', 'A05-CacheSmuggle', 'secure');
  res.set({ 'Cache-Control': 'private, no-store', 'Vary': 'Cookie' });
  res.send(`<h1>Sonuçlar: ${escHtml(q)}</h1>`);
});

// ---------- E-posta header enjeksiyonu (iletişim formu) ----------
// From alanındaki \r\n Bcc ekler (mock mail log).
router.post('/contact', express.urlencoded({ extended: true }), (req, res) => {
  mark(res, 'RT-MAILHDR-01', 'A03-Injection', 'vulnerable');
  const { name = '', email = '', message = '' } = req.body || {};
  const raw = `From: ${name} <${email}>\nTo: destek@example.com\nSubject: İletişim\n\n${message}`;
  if (/%0d|%0a|\r|\n/i.test(String(email)) || /bcc\s*:/i.test(String(email))) {
    return res.send(`<h1>Mail kuyruğa eklendi (mock)</h1><pre>${escHtml(raw)}\n+ Bcc: attacker@evil.com (ENJEKTE EDİLDİ!)</pre>`);
  }
  res.send(`<h1>Mail kuyruğa eklendi (mock)</h1><pre>${escHtml(raw)}</pre><p>email alanına test%0d%0aBcc:%20x@evil.com dene</p>`);
});

// ---------- Log poisoning -> log viewer stored XSS ----------
// Tarayıcı UA/XFF payload gönderir, viewer escape'siz basar (2. derece XSS).
router.get('/log-viewer', (req, res) => {
  mark(res, 'RT-LOGPOISON-01', 'A03-XSS', 'vulnerable');
  const fs = require('fs');
  const q = String(req.query.q ?? '');
  let rows = [];
  try {
    const f = require('../lib/requestLogger').logFile;
    rows = fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  } catch { /* log yok */ }
  if (q) rows = rows.filter(l => (l.url + ' ' + l.ua).toLowerCase().includes(q.toLowerCase()));
  rows = rows.slice(-50);
  const html = rows.map(l => `<tr><td>${l.ts}</td><td>${l.method} ${l.url}</td><td>${l.ua}</td><td>${l.status}</td></tr>`).join('');
  res.send(`<h1>İstek logları (escape YOK — zaafiyet!)</h1><form><input name="q" value="${q}" placeholder="log ara"/><button>Ara</button></form><table border="1"><tr><th>ts</th><th>url</th><th>user-agent</th><th>status</th></tr>${html || '<tr><td colspan=4>log boş</td></tr>'}</table><p>User-Agent: &lt;script&gt;alert(1)&lt;/script&gt; ile istek at, sonra buraya (?q= ile filtrele) bak.</p>`);
});

// ---------- Reset token URL'de + 3rd-party istek (Referer sızıntısı) ----------
router.get('/reset-page', (req, res) => {
  const token = req.query.token ?? 'ORNEKTOKEN';
  mark(res, 'RT-RESETLEAK-01', 'A02-Crypto', 'vulnerable');
  res.send(`<h1>Şifre sıfırla</h1><img src="https://analytics.example/track.gif" width="1" height="1"/><form><input type="hidden" name="token" value="${escHtml(token)}"/><input name="pass" type="password"/><button>Kaydet</button></form><p>Token URL'de (?token=...) + sayfada 3rd-party istek var → token Referer ile sızar. ?token=ABC123 dene</p>`);
});

// ---------- Oturum ID'si URL'de ----------
// DAST "session id in URL" bulgusu verir; log/proxy geçmişine düşer.
router.get('/session-url', (req, res) => {
  const sid = req.query.sid || 'sess-9f3a2b';
  mark(res, 'RT-SIDURL-01', 'A07-Auth', 'vulnerable');
  res.send(`<h1>Panel</h1><p><a href="/runtime/session-url?sid=${escHtml(sid)}">Profilim</a> | <a href="/runtime/session-url?sid=${escHtml(sid)}&page=orders">Siparişlerim</a></p><p>sid URL'de taşınıyor (kopyala-yapıştırla çalınır, loga düşer).</p>`);
});

// ---------- Cookie bayrakları ----------
router.get('/cookie-set', (req, res) => {
  mark(res, 'RT-COOKIE-01', 'A07-Auth', 'vulnerable');
  res.set('Set-Cookie', 'sessionid=sess-abc123; Path=/'); // HttpOnly/Secure/SameSite YOK
  res.send('<h1>Giriş yapıldı (mock)</h1><p>Set-Cookie bayraksız: XSS ile çalınır, HTTPS dışı taşınır.</p>');
});
router.get('/cookie-set-secure', (req, res) => {
  mark(res, 'RT-COOKIE-01-SECURE', 'A07-Auth', 'secure');
  res.set('Set-Cookie', 'sessionid=sess-abc123; Path=/; HttpOnly; Secure; SameSite=Lax');
  res.send('<h1>Giriş yapıldı (mock)</h1><p>Cookie HttpOnly+Secure+SameSite.</p>');
});

// ---------- BFLA: normal kullanıcı admin işlevi çalıştırıyor ----------
router.post('/admin-export', (req, res) => {
  mark(res, 'RT-BFLA-01', 'API-Security', 'vulnerable');
  const role = req.get('X-Role') || 'user';
  if (role !== 'admin') {
    // VULN: rol kontrolü YOK, yine de dışa aktar!
    return res.json({ warning: `rol=${role} ama kontrol edilmedi!`, export: users });
  }
  res.json({ export: users });
});

// ---------- Header'a güvenen BOLA ----------
router.get('/profile-mine', (req, res) => {
  mark(res, 'RT-HEADBOLA-01', 'API-Security', 'vulnerable');
  const id = req.get('X-User-Id') || '1'; // istemci header'ı = yetki (zafiyet)
  const u = users.find(x => String(x.id) === String(id));
  if (!u) return res.status(404).json({ error: 'yok' });
  res.json({ mine: u, note: 'X-User-Id: 99 gönder, admin ol (header spoofing)' });
});

// ---------- JWT gömülü jwk'ya güveniyor ----------
// header: {"alg":"RS256","jwk":{...attacker...}} -> imza geçerli sayılır (mock).
router.get('/jwt-jwk', (req, res) => {
  mark(res, 'RT-JWK-01', 'A07-Auth', 'vulnerable');
  const token = req.query.token || '';
  const parts = String(token).split('.');
  if (parts.length < 2) return res.send('<h1>JWT jwk demo</h1><p>header\'ında "jwk" olan token gönder — sunucu gömülü anahtara güveniyor (mock).</p>');
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    if (header.jwk) return res.send(`<h1>Bypass!</h1><p>Gömülü jwk ile doğrulandı: <code>${escHtml(JSON.stringify(header.jwk).slice(0, 80))}...</code> — saldırgan kendi anahtarıyla imzalamış!</p>`);
    res.send('jwk yok, normal akış');
  } catch { res.status(400).send('bozuk token'); }
});

// ---------- JWT süresiz / süresi dolmuş kabul ----------
router.get('/jwt-issue-long', (req, res) => {
  mark(res, 'RT-NOEXP-ISSUE', 'A07-Auth', 'vulnerable');
  const t = jwt.sign({ user: 'alice', role: 'user' }, 'mock-secret-key', { algorithm: 'HS256' }); // exp YOK
  res.send(`Süresiz token (exp yok): <code>${t}</code><p>/runtime/jwt-verify?token=... ile dene</p>`);
});
router.get('/jwt-verify', (req, res) => {
  mark(res, 'RT-NOEXP-01', 'A07-Auth', 'vulnerable');
  const token = req.query.token || '';
  if (!token) return res.send('<h1>JWT verify</h1><p>?token= ile dene (süresi dolmuş token bile kabul edilir — mock).</p>');
  try {
    const v = jwt.verify(token, 'mock-secret-key', { algorithms: ['HS256'], ignoreExpiration: true });
    res.send(`<h1>Kabul!</h1><p>Kullanıcı: ${escHtml(v.user)}, exp: ${v.exp ? new Date(v.exp * 1000).toISOString() : 'YOK (süresiz!)'} — expiration yok sayıldı.</p>`);
  } catch (e) { res.status(401).send('reddedildi: ' + escHtml(e.message)); }
});

// ---------- Log4Shell kalıbı (mock, outbound YOK) ----------
// DAST JNDI payload'ı gönderir; sunucu "çözümlemeye çalıştı" izi bırakır + OOB önerir.
router.post('/log', (req, res) => {
  mark(res, 'RT-LOG4J-01', 'A03-Injection', 'vulnerable');
  const msg = String((req.body || {}).msg ?? req.query.msg ?? '');
  if (/\$\{\s*jndi\s*:/i.test(msg)) {
    return res.send(`<h1>Loglandı</h1><p>` + escHtml('${jndi:...}') + ` ifadesi çözümlenmeye çalışıldı (mock lookup, outbound YOK).</p><p>Kör test: <code>/oob/&lt;tokenin&gt;</code> adresini ldap adresi gibi kullan, sonra <a href="/api/oob-hits">/api/oob-hits</a> adresine bak.</p>`);
  }
  res.send(`<h1>Loglandı: ${escHtml(msg.slice(0, 120))}</h1><p>{"msg":"` + escHtml('${jndi:ldap://x/oob-token}') + `"} dene</p>`);
});

// ---------- Blind XSS: geri arama URL'si admin panelinde çalışır ----------
// DAST/pen-tester callback olarak /oob/<token> veya collaborator verir.
const feedbacks = [];
router.post('/feedback', (req, res) => {
  mark(res, 'RT-BLINDXSS-01', 'A03-XSS', 'vulnerable');
  const { name = '', message = '', callback = '' } = req.body || {};
  feedbacks.push({ name, message, callback, ts: new Date().toISOString() });
  res.send(`<h1>Geri bildirim alındı</h1><p>Admin panelinde incelenecek. (callback: <code>${escHtml(callback || '(yok)')}</code>)</p><p>callback=/oob/token123 ver, sonra /api/oob-hits + /runtime/feedback-view kontrol et.</p>`);
});
router.get('/feedback-view', (req, res) => {
  mark(res, 'RT-BLINDXSS-01', 'A03-XSS', 'vulnerable');
  const html = feedbacks.map(f => `<div><b>${f.name}</b>: ${f.message}${f.callback ? `<script src="${f.callback}"></script>` : ''}</div>`).join('');
  res.send(`<h1>Admin — geri bildirimler (mock)</h1>${html || '<p>henüz yok</p>'}`);
});

// ---------- Teknoloji dosyası ifşaları ----------
router.get('/phpinfo', (req, res) => {
  mark(res, 'RT-PHPINFO-01', 'A05-Exposure', 'vulnerable');
  res.send('<h1>PHP Version 8.1.2 (mock)</h1><table><tr><td>System</td><td>Linux prod-web-01</td></tr><tr><td>Loaded extensions</td><td>mysqli, curl, openssl</td></tr><tr><td>DB_PASSWORD</td><td>Sup3rS3cret!</td></tr></table>');
});
router.get('/package.json', (req, res) => {
  mark(res, 'RT-PKG-01', 'A05-Exposure', 'vulnerable');
  res.json({ name: 'shop-frontend', version: '2.4.1', dependencies: { express: '4.19.2', lodash: '4.17.15' }, note: 'eski lodash (proto-pollution) + sürümler ifşa' });
});
router.get('/composer.json', (req, res) => {
  mark(res, 'RT-COMPOSER-01', 'A05-Exposure', 'vulnerable');
  res.json({ name: 'shop/backend', require: { 'laravel/framework': '8.83.0', 'guzzlehttp/guzzle': '7.0.0' } });
});

// ---------- Open redirect bypass varyantları ----------
// /go?next=//evil.com , /%5cevil.com , javascript: — hepsi geçiyor (zafiyet).
router.get('/go', (req, res) => {
  const next = String(req.query.next ?? '/');
  mark(res, 'RT-REDIRBYPASS-01', 'A01-AccessControl', 'vulnerable');
  const dec = decodeURIComponent(next);
  const low = dec.toLowerCase().trim().replace(/\\/g, '/');
  if (/^(https?:)?\/\//.test(low) || low.startsWith('javascript:') || low.startsWith('data:')) {
    res.set('Location', dec.replace(/[^\x20-\x7E]/g, '?')); // header latin1-safe
    return res.status(302).send(`<h1>Yönlendiriliyorsun</h1><p><a href="${escHtml(dec)}">${escHtml(dec)}</a></p><p>Bypass geçti! (?next=//evil.com , ?next=/\\evil.com, ?next=javascript:alert(1))</p>`);
  }
  res.redirect(String(next).replace(/[^\x20-\x7E]/g, '?')); // header latin1-safe
});

// ---------- Çift uzantı + MIME spoof upload ----------
router.post('/upload-img', express.text({ type: '*/*', limit: '1mb' }), (req, res) => {
  mark(res, 'RT-UPLDBL-01', 'A04-FileHandling', 'vulnerable');
  const fname = req.get('X-Filename') || 'foto.jpg';
  const ctype = req.get('Content-Type') || '';
  const lastExt = fname.split('.').pop().toLowerCase();
  const hasPhp = fname.toLowerCase().includes('.php');
  if (hasPhp && (lastExt === 'jpg' || lastExt === 'png' || ctype.includes('image/'))) {
    return res.send(`<h1>Yüklendi: /uploads/${escHtml(fname)}</h1><p>Kontrol sadece SON uzantıya (${escHtml(lastExt)}) + Content-Type'a baktı — Apache <code>.php.jpg</code>'yi PHP çalıştırır (mock)!</p>`);
  }
  res.send(`<h1>Yüklendi: /uploads/${escHtml(fname)}</h1><p>X-Filename: shell.php.jpg + Content-Type: image/jpeg dene</p>`);
});
router.post('/upload-img-secure', express.text({ type: '*/*', limit: '1mb' }), (req, res) => {
  mark(res, 'RT-UPLDBL-01-SECURE', 'A04-FileHandling', 'secure');
  const fname = req.get('X-Filename') || 'a.png';
  if (/\.ph(p|ar|tml)|%00|\x00/i.test(fname)) return res.status(400).send('yasaklı kalıp (.php / null-byte)');
  if (!/\.(png|jpe?g)$/i.test(fname) || fname.split('.').length !== 2) return res.status(400).send('tek ve izinli uzantı gerekli + magic-byte doğrulaması (mock)');
  res.send('<h1>Yüklendi (güvenli)</h1><p>rastgele isim + magic-byte + exec bit yok.</p>');
});

// ---------- Per-context XSS: attribute + JS-string ----------
router.get('/attr', (req, res) => {
  const img = req.query.img ?? 'logo.png';
  mark(res, 'RT-CTX-ATTR-01', 'Client-Side', 'vulnerable');
  res.send(`<h1>Rozet</h1><img src="${img}"><p>?img=x" onerror=alert(1) dene (attribute çıkışı)</p>`);
});
router.get('/jsvar', (req, res) => {
  const data = req.query.data ?? 'misafir';
  mark(res, 'RT-CTX-JS-01', 'Client-Side', 'vulnerable');
  res.send(`<h1>Selam</h1><script>var who = '${data}'; document.write('Merhaba ' + who);</script><p>?data=';alert(1);// dene (JS-string çıkışı)</p>`);
});
router.get('/attr-secure', (req, res) => {
  const img = req.query.img ?? 'logo.png';
  mark(res, 'RT-CTX-SECURE', 'Client-Side', 'secure');
  if (!/^[a-z0-9._-]+\.(png|jpg)$/i.test(String(img))) return res.status(400).send('geçersiz dosya adı');
  res.send(`<h1>Rozet (güvenli)</h1><img src="${escHtml(img)}">`);
});

module.exports = router;

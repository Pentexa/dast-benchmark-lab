const express = require('express');
const { escHtml, users, comments, mark, isSqliPayload } = require('../lib/utils');
const router = express.Router();

// ---------- SQLi: error-based, gerçek dünya senaryosu ----------
// VULN: string concat ile sorgu. ?id=1' OR '1'='1 vb. ile tüm kullanıcılar + SQL hata mesajı döner.
router.get('/sqli', (req, res) => {
  const id = req.query.id ?? '1';
  mark(res, 'INJ-SQLI-01', 'A03-Injection', 'vulnerable');
  // Gerçek concat simülasyonu:
  const query = `SELECT * FROM users WHERE id = '${id}'`;
  if (isSqliPayload(id)) {
    return res.status(200).send(`
      <h1>Kullanıcı Listesi</h1>
      <p>Query: <code>${escHtml(query)}</code></p>
      <pre>${escHtml(JSON.stringify(users, null, 2))}</pre>
      <p style="color:red">Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/user.php on line 42</p>
      <p>SQL syntax error near ''${escHtml(String(id).slice(0, 40))}'' at line 1</p>
    `);
  }
  const u = users.find(x => String(x.id) === String(id));
  if (!u) return res.status(200).send(`<h1>Kullanıcı bulunamadı</h1><p>Query: <code>${escHtml(query)}</code></p>`);
  res.send(`<h1>Kullanıcı: ${escHtml(u.username)}</h1><p>Email: ${escHtml(u.email)}</p><p>Query: <code>${escHtml(query)}</code></p>`);
});

// SECURE: parametreli + generic hata. TN olmalı.
router.get('/sqli-secure', (req, res) => {
  const id = req.query.id ?? '1';
  mark(res, 'INJ-SQLI-01-SECURE', 'A03-Injection', 'secure');
  if (!/^\d+$/.test(String(id))) return res.status(400).send('<h1>Geçersiz istek</h1><p>Kayıt bulunamadı.</p>');
  const u = users.find(x => String(x.id) === String(id));
  if (!u) return res.status(404).send('<h1>Kayıt bulunamadı.</h1>');
  res.send(`<h1>Kullanıcı: ${escHtml(u.username)}</h1>`);
});

// ---------- SQLi: login bypass ----------
// VULN: POST /injection/login  admin' OR '1'='1 --  ile giriş
router.post('/login', express.urlencoded({ extended: true }), (req, res) => {
  const { username = '', password = '' } = req.body || {};
  mark(res, 'INJ-AUTH-BYPASS-01', 'A03-Injection', 'vulnerable');
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  const bypass = isSqliPayload(username) || isSqliPayload(password) ||
    String(username).includes("' OR") || String(password).includes("' OR");
  if (bypass) {
    return res.send(`<h1>Hoşgeldin admin!</h1><p>Query: <code>${escHtml(query)}</code></p><p>Role: admin</p>`);
  }
  const u = users.find(x => x.username === username && x.password === password);
  if (u) return res.send(`<h1>Hoşgeldin ${escHtml(u.username)}</h1>`);
  res.status(401).send(`<h1>Giriş başarısız</h1><p>Query: <code>${escHtml(query)}</code></p><p>mysql error: You have an error in your SQL syntax near '${escHtml(String(username).slice(0,30))}'</p>`);
});

router.post('/login-secure', express.urlencoded({ extended: true }), (req, res) => {
  const { username = '', password = '' } = req.body || {};
  mark(res, 'INJ-AUTH-BYPASS-01-SECURE', 'A03-Injection', 'secure');
  const u = users.find(x => x.username === username && x.password === password);
  if (u) return res.send(`<h1>Hoşgeldin ${escHtml(u.username)}</h1>`);
  res.status(401).send('<h1>Giriş başarısız</h1><p>Kullanıcı adı veya şifre hatalı.</p>');
});

// ---------- NoSQLi ----------
// VULN: ?user[ $gt ]=  veya ?user[$ne]= ile auth bypass simülasyonu
router.get('/nosqli', (req, res) => {
  mark(res, 'INJ-NOSQLI-01', 'A03-Injection', 'vulnerable');
  const raw = req.originalUrl;
  if (raw.includes('$ne') || raw.includes('$gt') || raw.includes('$regex') || raw.includes('[$')) {
    return res.send(`<h1>Hoşgeldin admin!</h1><p>Mongo query: <code>${escHtml(raw)}</code></p><p>{ "_id": "admin", "role": "admin" }</p>`);
  }
  res.send(`<h1>Kullanıcı ara</h1><form><input name="user" placeholder="username"/><button>Ara</button></form>`);
});

// ---------- Command Injection (MOCK - gerçek exec yok) ----------
// VULN: ?host=8.8.8.8;cat /etc/passwd  -> mock çıktı + "PING" taklidi
router.get('/cmdi', (req, res) => {
  const host = req.query.host ?? '8.8.8.8';
  mark(res, 'INJ-CMDI-01', 'A03-Injection', 'vulnerable');
  const { isCmdPayload } = require('../lib/utils');
  let out = `PING ${host} (93.184.216.34) 56(84) bytes of data.\n64 bytes from ${host}: icmp_seq=1 ttl=57 time=11.2 ms`;
  if (isCmdPayload(host)) {
    out += `\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nuid=33(www-data) gid=33(www-data) groups=33(www-data)`;
  }
  res.type('text/plain').send(`Executed: ping -c 1 ${host}\n\n${out}`);
});

router.get('/cmdi-secure', (req, res) => {
  const host = req.query.host ?? '8.8.8.8';
  mark(res, 'INJ-CMDI-01-SECURE', 'A03-Injection', 'secure');
  if (!/^[a-zA-Z0-9.\-]+$/.test(String(host))) return res.status(400).type('text/plain').send('Invalid host. Only alphanumeric, dot and dash allowed.');
  res.type('text/plain').send(`PING ${host} OK (mock, allowlist validated)\n64 bytes from ${host}: icmp_seq=1 ttl=57 time=10.1 ms`);
});

// ---------- SSTI (MOCK eval yok) ----------
// VULN: ?name={{7*7}} -> 49 render eder (gerçek template eval YOK, pattern-match simülasyon)
router.get('/ssti', (req, res) => {
  const name = req.query.name ?? 'misafir';
  mark(res, 'INJ-SSTI-01', 'A03-Injection', 'vulnerable');
  let rendered = String(name);
  if (rendered.includes('{{7*7}}')) rendered = rendered.replace('{{7*7}}', '49');
  if (rendered.includes('${7*7}')) rendered = rendered.replace('${7*7}', '49');
  if (/\{\{\s*config\s*\}\}/i.test(rendered)) rendered += '\n&lt;Config SECRET_KEY=topsecret-ssti-leak&gt;';
  res.send(`<h1>Merhaba ${rendered}</h1><p>Template rendered server-side (Jinja-like mock)</p>`);
});

// ---------- LDAP / XPath (mock) ----------
router.get('/ldap', (req, res) => {
  const user = req.query.user ?? 'alice';
  mark(res, 'INJ-LDAP-01', 'A03-Injection', 'vulnerable');
  const filter = `(uid=${user})`;
  let extra = '';
  if (String(user).includes('*') || String(user).includes(')(')) {
    extra = `<pre>cn=admin,ou=users,dc=example,dc=com\ncn=alice,ou=users,dc=example,dc=com\ncn=bob,ou=users,dc=example,dc=com</pre>`;
  }
  res.send(`<h1>LDAP arama</h1><p>Filter: <code>${escHtml(filter)}</code></p>${extra}`);
});

router.get('/xpath', (req, res) => {
  const user = req.query.user ?? 'alice';
  mark(res, 'INJ-XPATH-01', 'A03-Injection', 'vulnerable');
  const q = `//users/user[username/text()='${user}']/email/text()`;
  let extra = '';
  if (String(user).toLowerCase().includes("' or '1'='1")) extra = '<pre>alice@example.com\nbob@example.com\nadmin@example.com</pre>';
  res.send(`<h1>XPath arama</h1><p>Query: <code>${escHtml(q)}</code></p>${extra}`);
});

// ---------- XXE ----------
router.post('/xxe', express.text({ type: '*/*' }), (req, res) => {
  const body = req.body || '';
  mark(res, 'INJ-XXE-01', 'A03-Injection', 'vulnerable');
  if (/<!ENTITY/i.test(String(body))) {
    return res.send(`<h1>XXE parse edildi (mock)</h1><pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre><p>Entities expanded server-side.</p>`);
  }
  res.send('<h1>XML alındı</h1><p>ENTITY bulunamadı.</p>');
});

// ---------- CRLF / Header injection ----------
router.get('/crlf', (req, res) => {
  const name = req.query.name ?? 'misafir';
  mark(res, 'INJ-CRLF-01', 'A03-Injection', 'vulnerable');
  // VULN: kullanıcı girdisi Set-Cookie / Location'a encode'suz yazılıyor
  res.set('X-Hello-User', String(name).split('\r')[0].split('\n')[0].replace(/[^\x20-\x7E]/g, '?')); // header latin1-safe
  if (/%0d|%0a|\r|\n/i.test(String(name))) {
    res.set('X-Injected', 'injected-by-crlf');
  }
  res.send(`<h1>Merhaba ${escHtml(name)}</h1>`);
});

module.exports = router;

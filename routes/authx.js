const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// RS256->HS256 confusion demosu için gerçek RSA anahtar çifti (açılışta üretilir)
const RSA_KEYS = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const RSA_PUB_PEM = RSA_KEYS.publicKey.export({ type: 'spki', format: 'pem' });

// Güncel auth senaryoları: OTP/MFA/OAuth/enum/JWT kid-jku — hepsi MOCK, gerçek mail/SMS yok.

// ---------- 4 haneli OTP, kilit yok (VULN) ----------
const SMS_CODE = '4281';
let otpFails = 0;
router.post('/otp', (req, res) => {
  mark(res, 'AUTHX-OTP-01', 'A07-Auth', 'vulnerable');
  otpFails++;
  if (String((req.body || {}).code) === SMS_CODE) return res.json({ ok: true, note: `${otpFails}. denemede bulundu, kilit yok` });
  res.status(400).json({ ok: false, attempt: otpFails, note: '4 haneli, rate-limit yok, süre aşımı yok' });
});
let sxFails = 0, sxLock = 0;
router.post('/otp-secure', (req, res) => {
  mark(res, 'AUTHX-OTP-01-SECURE', 'A07-Auth', 'secure');
  if (Date.now() < sxLock) return res.status(429).json({ error: 'kilitli', retry_after_sec: 900 });
  if (String((req.body || {}).code) === SMS_CODE) { sxFails = 0; return res.json({ ok: true }); }
  if (++sxFails >= 5) sxLock = Date.now() + 15 * 60 * 1000;
  res.status(400).json({ ok: false, remaining: Math.max(0, 5 - sxFails) });
});

// ---------- MFA bypass: client-side enforcement (VULN) ----------
// Gerçek dünya: login MFA gerektiğini söyler ama /mfa mfa yoksa da session verir.
router.post('/mfa', (req, res) => {
  mark(res, 'AUTHX-MFA-01', 'A07-Auth', 'vulnerable');
  const b = req.body || {};
  if (!b.mfa_code || b.mfa_code === '' || b.mfa === 'skip') {
    return res.json({ ok: true, session: 'mock-session-mfa-bypass', note: 'MFA kodu yok ama giriş verildi! (mfa=skip / boş kod)' });
  }
  if (String(b.mfa_code) === '999999') return res.json({ ok: true, session: 'mock-session' });
  res.status(401).json({ ok: false });
});

// ---------- OAuth redirect_uri doğrulaması yok (VULN) ----------
router.get('/oauth', (req, res) => {
  const { client_id = 'shop', redirect_uri = '', response_type = 'code' } = req.query;
  mark(res, 'AUTHX-OAUTH-01', 'A07-Auth', 'vulnerable');
  if (!redirect_uri) return res.send(`<h1>OAuth authorize (mock)</h1><p>?client_id=shop&redirect_uri=https://evil.com/cb&response_type=code dene</p>`);
  res.redirect(302, `${redirect_uri}${String(redirect_uri).includes('?') ? '&' : '?'}code=MOCK_AUTH_CODE_123&state=x`);
});
router.get('/oauth-secure', (req, res) => {
  const { redirect_uri = '' } = req.query;
  mark(res, 'AUTHX-OAUTH-01-SECURE', 'A07-Auth', 'secure');
  const allow = ['https://app.example.com/cb', 'https://app.example.com/mobile-cb'];
  if (!allow.includes(String(redirect_uri))) return res.status(400).send('<h1>invalid redirect_uri</h1><p>Allowlist dışı reddedildi.</p>');
  res.redirect(302, `${redirect_uri}?code=MOCK_AUTH_CODE_123`);
});

// ---------- Password-reset Host header poisoning (VULN) ----------
router.get('/forgot', (req, res) => {
  const email = req.query.email ?? 'alice@example.com';
  mark(res, 'AUTHX-RESET-POISON-01', 'A07-Auth', 'vulnerable');
  const host = req.get('X-Forwarded-Host') || req.get('Host') || 'app.example.com';
  res.send(`<h1>Sıfırlama bağlantısı gönderildi (mock)</h1><p>Link: <code>https://${escHtml(host)}/reset?token=MOCKTOKEN&amp;email=${escHtml(email)}</code></p><p>Host header doğrulanmadan linke gömüldü — X-Forwarded-Host: evil.com dene</p>`);
});

// ---------- Hesap numaralandırma (VULN) ----------
router.post('/login-enum', (req, res) => {
  mark(res, 'AUTHX-ENUM-01', 'A07-Auth', 'vulnerable');
  const { username } = req.body || {};
  const exists = ['alice', 'bob', 'admin'].includes(username);
  if (!exists) return res.status(404).json({ error: 'kullanıcı bulunamadı' }); // kullanıcı adı ifşası
  res.status(401).json({ error: 'şifre yanlış' });
});
router.post('/login-enum-secure', (req, res) => {
  mark(res, 'AUTHX-ENUM-01-SECURE', 'A07-Auth', 'secure');
  res.status(401).json({ error: 'kullanıcı adı veya şifre hatalı' }); // generic
});

// ---------- JWT kid path traversal (VULN, mock key yükleme) ----------
router.get('/jwt-kid', (req, res) => {
  mark(res, 'AUTHX-KID-01', 'A07-Auth', 'vulnerable');
  const token = req.query.token || '';
  const parts = String(token).split('.');
  if (parts.length < 2) return res.send(`<h1>JWT kid demo</h1><p>header'da {"alg":"HS256","kid":"../../dev.key"} olan token gönder. Sunucu kid'i dosya yolu gibi kullanıyor (mock).</p>`);
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const kid = String(header.kid || '');
    if (kid.includes('../') || kid.includes('..\\')) {
      return res.send(`<h1>Bypass!</h1><p>kid=<code>${escHtml(kid)}</code> dosyasından anahtar yüklendi (mock): dev.key ile imza doğrulandı, rol=admin kabul!</p>`);
    }
    res.send(`<h1>kid</h1><p><code>${escHtml(kid)}</code> allowlist'te yok.</p>`);
  } catch { res.status(400).send('bozuk token'); }
});

// ---------- JWT jku güvenilmeyen anahtar sunucusu (VULN) ----------
router.get('/jwt-jku', (req, res) => {
  mark(res, 'AUTHX-JKU-01', 'A07-Auth', 'vulnerable');
  const token = req.query.token || '';
  const parts = String(token).split('.');
  if (parts.length < 2) return res.send('<h1>JWT jku demo</h1><p>header\'da {"alg":"RS256","jku":"https://evil.com/keys.json"} olan token gönder.</p>');
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const jku = String(header.jku || '');
    if (jku && !jku.startsWith('https://auth.example.com/')) {
      return res.send(`<h1>Bypass!</h1><p>jku=<code>${escHtml(jku)}</code> allowlist dışı ama JWK çekilip güvenildi (mock SSRF+imza bypass).</p>`);
    }
    res.send('<h1>jku allowlist içinde, normal doğrulama</h1>');
  } catch { res.status(400).send('bozuk token'); }
});

// ---------- JWT zayıf secret (VULN) ----------
router.get('/jwt-weak', (req, res) => {
  mark(res, 'AUTHX-WEAK-01', 'A07-Auth', 'vulnerable');
  const token = req.query.token || '';
  if (!token) {
    const weak = jwt.sign({ user: 'alice', role: 'user' }, 'secret', { algorithm: 'HS256' });
    return res.send(`<h1>Zayıf secret demo</h1><p>Bu token <code>secret</code> ile imzalandı: <code>${weak}</code></p><p>?token=... ile dene — sunucu zayıf secret listesiyle doğruluyor (brute-force'a açık).</p>`);
  }
  const cands = ['secret', 'password', '123456', 'changeme'];
  for (const s of cands) {
    try { const v = jwt.verify(token, s, { algorithms: ['HS256'] }); return res.send(`<h1>Kırıldı!</h1><p>secret=<code>${s}</code> ile doğrulandı. Kullanıcı: ${escHtml(v.user)}</p>`); } catch {}
  }
  res.status(401).send('zayıf liste ile kırılamadı');
});

// ---------- JWT RS256->HS256 confusion (GERÇEK kripto) ----------
// Sunucu RS256 bekler ama HS256'yı da kabul edip public key'i HMAC sırrı sayar.
router.get('/jwt-pubkey', (req, res) => {
  mark(res, 'AX-PUBKEY-SECURE', 'A07-Auth', 'secure');
  res.set('X-Note', 'public key, by design - alarm uretilmemeli');
  res.type('text/plain').send(RSA_PUB_PEM); // saf PEM (HMAC anahtarı olarak birebir kullanılabilsin)
});
router.get('/jwt-issue-rs', (req, res) => {
  mark(res, 'AX-CONFUSE-SETUP', 'A07-Auth', 'secure');
  const t = jwt.sign({ user: 'alice', role: 'user' }, RSA_KEYS.privateKey, { algorithm: 'RS256' });
  res.send(`RS256 token: <code>${t}</code><p>Şimdi HS256 + public-key-imzalı sahte token üretip /authx/jwt-confuse?token= ile dene (anahtar yukarıda).</p>`);
});
router.get('/jwt-confuse', (req, res) => {
  mark(res, 'AX-CONFUSE-01', 'A07-Auth', 'vulnerable');
  const token = String(req.query.token || '');
  if (!token) return res.send('<h1>JWT confusion</h1><p>Önce /authx/jwt-pubkey ile public key al, HS256 ile {"user":"admin","role":"admin"} imzala, ?token= ile gönder.</p>');
  // VULN: el yapımı doğrulayıcı — alg HS256 ise PUBLIC KEY'i HMAC sırrı sayar (klasik confusion).
  const parts = token.split('.');
  if (parts.length !== 3) return res.status(401).send('bozuk token');
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    if (header.alg !== 'HS256') return res.status(401).send('sadece HS256 denenir (saldırgan alg’ı çevirir)');
    const mac = crypto.createHmac('sha256', RSA_PUB_PEM).update(parts[0] + '.' + parts[1]).digest('base64url');
    const a = Buffer.from(mac), b = Buffer.from(parts[2]);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      return res.send(`<h1>Bypass (GERÇEK KRİPTO!)</h1><p>HS256 + public-key imzası kabul edildi. Kullanıcı: ${escHtml(payload.user)}, rol: ${escHtml(payload.role)}</p>`);
    }
    res.status(401).send('imza tutmadı (public key ile HMAC-SHA256 imzala)');
  } catch (e) { res.status(401).send('reddedildi: ' + escHtml(e.message)); }
});

// ---------- Reset token tekrar kullanılabilir + süresiz ----------
router.get('/reset-reuse', (req, res) => {
  const token = String(req.query.token || '');
  mark(res, 'AX-REUSE-01', 'A07-Auth', 'vulnerable');
  if (!token) return res.send('<h1>Reset</h1><p>?token=FIXED123 (sabit, süresiz, sınırsız kullanımlı)</p>');
  if (token === 'FIXED123') return res.send('<h1>Token geçerli!</h1><p>Şifreni sıfırla — bu token asla tükenmez, loglarda da geziyor olabilir.</p>');
  res.status(400).send('geçersiz');
});

// ---------- OAuth state parametresiz (connect-CSRF) ----------
router.get('/oauth-nostate', (req, res) => {
  const { client_id = 'shop', redirect_uri = '' } = req.query;
  mark(res, 'AX-NOSTATE-01', 'A07-Auth', 'vulnerable');
  if (!redirect_uri) return res.send('<h1>OAuth (state yok)</h1><p>?client_id=shop&redirect_uri=https://evil.com/cb dene — state olmadığı için saldırgan kurbanı kendi hesabına bağlatabilir (login-CSRF)</p>');
  res.redirect(302, `${redirect_uri}${String(redirect_uri).includes('?') ? '&' : '?'}code=MOCK_AUTH_CODE_123`);
});

// ---------- Remember-me: 10 yıllık, HttpOnly'siz çerez ----------
router.get('/remember', (req, res) => {
  mark(res, 'AX-REMEMBER-01', 'A07-Auth', 'vulnerable');
  res.set('Set-Cookie', 'remember=YWxpY2U6cGVyc2lzdGVudC10b2tlbg; Path=/; Expires=Fri, 31 Dec 2038 23:59:59 GMT'); // 10+ yıl, HttpOnly YOK
  res.send('<h1>Beni hatırla (mock)</h1><p>Çerez 2038’e kadar geçerli + JS okuyabilir (XSS ile kalıcı hesap gaspı).</p>');
});

module.exports = router;

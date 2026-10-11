// Benchmark çalışma modu: transparent (varsayılan, öğrenme dostu) / blind (ölçüm modu).
// DAST_MODE=blind iken sunucu ground-truth bilgisini (header, dashboard cevabı, API) gizler.
function isBlind() {
  return String(process.env.DAST_MODE || 'transparent').toLowerCase() === 'blind';
}

function mode() {
  return isBlind() ? 'blind' : 'transparent';
}

module.exports = { isBlind, mode };

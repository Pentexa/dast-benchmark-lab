// Taramalar arası durum sıfırlama kayıt defteri.
// Durum tutan route dosyaları reset fonksiyonlarını buraya kaydeder:
//   const { onReset } = require('../lib/stateReset');
//   onReset(() => { attempts = 0; store.clear(); });
// POST /api/admin/reset hepsi için resetAll() çağırır.
const handlers = [];

function onReset(fn) {
  if (typeof fn === 'function') handlers.push(fn);
}

function resetAll() {
  const errors = [];
  for (const fn of handlers) {
    try { fn(); } catch (e) { errors.push(String(e && e.message || e)); }
  }
  return { reset_handlers: handlers.length, errors };
}

function handlerCount() {
  return handlers.length;
}

module.exports = { onReset, resetAll, handlerCount };

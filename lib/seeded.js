// Tohumlanabilir deterministik PRNG (mulberry32).
// DAST_SEED ortam değişkeni veya /api/admin/reset {seed} ile tohumlanır.
// Yeni senaryolar (P1/P2) üretken değerler için Math.random yerine bunu kullanır.
let state = (Number(process.env.DAST_SEED) || 0x9e3779b9) >>> 0;

function reseed(seed) {
  state = (Number(seed) || 0x9e3779b9) >>> 0;
}

function rand() {
  state |= 0; state = (state + 0x6D2B79F5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}

function randInt(min, max) {
  return min + Math.floor(rand() * (max - min + 1));
}

function pick(arr) {
  return arr[Math.floor(rand() * arr.length)];
}

function token(prefix, n = 6) {
  const abc = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < n; i++) s += abc[Math.floor(rand() * abc.length)];
  return `${prefix}-${s}`;
}

module.exports = { reseed, rand, randInt, pick, token };

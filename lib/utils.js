// Ortak yardımcılar: encode, fake DB, ground-truth header helper
function escHtml(s) {
  if (s === undefined || s === null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Sahte kullanıcı DB (güncel PII: TC Kimlik No + IBAN + telefon — excessive data senaryoları için)
const users = [
  { id: 1, username: 'alice', email: 'alice@example.com', role: 'user', pan: '4111 1111 1111 1111', password: 'alice123', tckn: '10000000146', iban: 'TR330006100519786457841326', phone: '+905321111111', address: 'Caferağa Mah. Moda Cad. No:1 Kadıköy/İstanbul' },
  { id: 2, username: 'bob', email: 'bob@example.com', role: 'user', pan: '5500 0000 0000 0004', password: 'bob123', tckn: '10000000214', iban: 'TR320010100000000002345678', phone: '+905322222222', address: 'Alsancak Mah. Kordon Boyu No:5 İzmir' },
  { id: 99, username: 'admin', email: 'admin@example.com', role: 'admin', pan: '3400 000000 00009', password: 'admin123', tckn: '10000009982', iban: 'TR120006200000100000123456', phone: '+905339999999', address: 'Çankaya Mah. Atatürk Bulvarı No:99 Ankara' }
];

// Sunucu tarafı fiyat kataloğu (client-side price tampering kontrolü için hakem)
const catalog = {
  'tshirt': { name: 'T-Shirt', price: 499 },
  'ayakkabi': { name: 'Ayakkabı', price: 2499 },
  'kuponlu-urun': { name: 'Kuponlu Ürün', price: 1000 }
};

const comments = [{ author: 'alice', text: 'Merhaba dünya!' }];

// Zafiyet marker header'ı ekle (değerlendirme ve debug için, DAST davranışını etkilemez)
function mark(res, id, category, truth) {
  res.set('X-Vuln-Id', id);
  res.set('X-Vuln-Category', category);
  res.set('X-Ground-Truth', truth); // vulnerable | secure | fp-trap
}

function isSqliPayload(v) {
  if (!v) return false;
  const s = String(v).toLowerCase();
  return (
    s.includes("' or '1'='1") || s.includes("' or 1=1") || s.includes('" or "1"="1') ||
    s.includes(' union ') || s.includes('--') || s.includes(';--') ||
    s.includes(' or sleep(') || s.includes(' waitfor ') || s.includes('benchmark(') ||
    s.includes("' and '1'='1") || /^'\s*or\s+/i.test(String(v)) || /^\d+\s+or\s+1=1/i.test(String(v))
  );
}

function isXssPayload(v) {
  if (!v) return false;
  const s = String(v).toLowerCase();
  return s.includes('<script') || s.includes('onerror=') || s.includes('onload=') ||
    s.includes('javascript:') || s.includes('<img') || s.includes('<svg');
}

function isTraversalPayload(v) {
  if (!v) return false;
  const s = String(v);
  return s.includes('../') || s.includes('..\\') || s.includes('%2e%2e') || s.includes('%252e') ||
    s.toLowerCase().includes('/etc/passwd') || s.toLowerCase().includes('boot.ini');
}

function isCmdPayload(v) {
  if (!v) return false;
  const s = String(v);
  return s.includes(';') || s.includes('|') || s.includes('&&') || s.includes('`') ||
    s.includes('$(') || s.toLowerCase().includes('whoami') || s.toLowerCase().includes('cat /etc');
}

function isSstiPayload(v) {
  if (!v) return false;
  const s = String(v);
  return (s.includes('{{') && s.includes('}}')) || (s.includes('${') && s.includes('}')) ||
    s.includes('{%') || s.includes('*#');
}

module.exports = { escHtml, users, comments, catalog, mark, isSqliPayload, isXssPayload, isTraversalPayload, isCmdPayload, isSstiPayload };

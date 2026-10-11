const express = require('express');
const fs = require('fs');
const path = require('path');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P2 — False-Positive Hell: 100+ güvenli decoy (manifest-kökenli).
// Tek kaynak: routes/fphell-manifest.json (evaluation/extend_gt_p2.py üretir).
// Her decoy statik tuzak metni + güvenli notu döner; çalıştırılabilir davranış YOK.

let items = [];
try {
  items = JSON.parse(fs.readFileSync(path.join(__dirname, 'fphell-manifest.json'), 'utf8'));
} catch (e) {
  console.log('[!] fphell manifest yok:', e.message);
}

for (const d of items) {
  router.get('/' + d.slug, (req, res) => {
    mark(res, d.id, 'FP-Trap', 'fp-trap');
    let extra = '';
    if (d.reflect) {
      const nick = String(req.query.nick || '');
      // nötralize yansıtma: ham girdi ASLA yansımaz (decoy kanıtı)
      extra = `<p>yansıma (kaçışlı): ${escHtml(nick)}</p>`;
    }
    res.send(`<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>${escHtml(d.title)}</title></head><body>
    <h1>${escHtml(d.title)}</h1>
    <p class="trap">${escHtml(d.trap)}</p>
    <p class="guard">${escHtml(d.guard)}</p>${extra}</body></html>`);
  });
}

module.exports = router;
module.exports.decoyCount = items.length;

const express = require('express');
const { escHtml, mark } = require('../lib/utils');
const router = express.Router();

// P1.14 — Gerçek-zamanlı protokoller: WebSocket (ws), SSE, gRPC-Web (mock).
// Tehlikeli davranış YOK: echo/yansıma kontrollü metinle sınırlı, dış bağlantı yok.

// ---------- SSE: olay akışına ham yansıma ----------
// VULN: ?msg kaçışsız event-data içinde
router.get('/sse', (req, res) => {
  mark(res, 'REALTIME-SSE-01', 'Client-Side', 'vulnerable');
  const msg = String(req.query.msg || 'merhaba');
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.write(`event: notice\ndata: ${msg}\n\n`);
  res.end();
});
// SECURE: escape'li SSE
router.get('/sse-secure', (req, res) => {
  mark(res, 'REALTIME-SSE-01-SECURE', 'Client-Side', 'secure');
  const msg = String(req.query.msg || 'merhaba').replace(/[<>&\n\r]/g, '');
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.write(`event: notice\ndata: ${msg}\n\n`);
  res.end();
});

// ---------- gRPC-Web mock: ayrıntılı hata ifşası ----------
// VULN: bozuk frame'e stack döken yanıt
router.post('/grpc', express.raw({ type: '*/*' }), (req, res) => {
  mark(res, 'REALTIME-GRPC-01', 'API-GraphQL', 'vulnerable');
  const frame = (req.body || Buffer.alloc(0)).toString('utf8', 0, 64);
  res.set('Content-Type', 'application/grpc-web+proto');
  res.status(500).send(`grpc-status: 13\ngrpc-message: frame parse failed at Object.parseFrame (/srv/grpc/codec.js:88:15)\ninput[0:64]=${escHtml(frame)}\ninternal: authsvc:5432, trace=db-query-users`);
});
// SECURE: minimal hata
router.post('/grpc-secure', express.raw({ type: '*/*' }), (req, res) => {
  mark(res, 'REALTIME-GRPC-01-SECURE', 'API-GraphQL', 'secure');
  res.set('Content-Type', 'application/grpc-web+proto');
  res.status(400).send('grpc-status: 3\ngrpc-message: invalid frame');
});

// ---------- WebSocket: attach(server) ile canlanır ----------
// VULN /realtime/ws: Origin kontrolsüz echo (tarayıcılar arası hırsızlık zemini)
// SECURE /realtime/ws-secure: yabancı Origin 403
// NOT: tek noServer instance + manuel path routing — aynı HTTP server'da iki
// WebSocketServer path-çakışması soketi 400 ile öldürür, o yüzden bu desen şart.
let attached = false;
function attach(server) {
  if (attached) return;
  attached = true;
  const { WebSocketServer } = require('ws');
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    const path = String(req.url || '').split('?')[0];
    if (path !== '/realtime/ws' && path !== '/realtime/ws-secure') return; // bizim değil
    if (path === '/realtime/ws-secure') {
      const origin = req.headers.origin || '';
      if (origin && !/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
        socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.send(path === '/realtime/ws' ? 'WS-ECHO-READY (origin sorulmadı!)' : 'WS-SECURE-READY');
      ws.on('message', (m) => ws.send('echo: ' + (path === '/realtime/ws' ? String(m) : escHtml(String(m))).slice(0, 200)));
    });
  });
}

module.exports = router;
module.exports.attach = attach;

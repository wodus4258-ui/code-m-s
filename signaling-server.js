// Talkie signaling server
// Implements exactly the protocol documented in the client:
//   C->S  {type:'join', room:'lobby', password:<string>}
//   S->C  {type:'welcome', id, peers:[{id}, ...]}   -- only if password is correct
//   S->C  {type:'auth-error'}                        -- if password is wrong, then closes
//   S->C  {type:'peer-joined', id}
//   S->C  {type:'peer-left', id}
//   C->S  {type:'signal', to:<peerId>, kind:'offer'|'answer'|'ice', payload}
//   S->C  {type:'signal', from:<peerId>, kind:'offer'|'answer'|'ice', payload}
//
// The password is checked here, server-side, so no client can ever bypass it
// by editing/inspecting the page. Prefer setting it via the TALKIE_PASSWORD
// environment variable in your host's dashboard (e.g. Render > Environment)
// rather than relying on the fallback below — if this file lives in a public
// GitHub repo, a hardcoded password here is just as exposed as it was in the
// old client-side check.

const http = require('http');
const { WebSocketServer } = require('ws');

const PASSWORD = process.env.TALKIE_PASSWORD || '051627#';
const PORT = process.env.PORT || 10000;

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Talkie signaling server OK');
});

const wss = new WebSocketServer({ server });

let nextId = 1;
const clients = new Map(); // id -> ws

function send(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch (e) {}
}

function broadcastExcept(id, obj) {
  clients.forEach((client, cid) => {
    if (cid !== id) send(client, obj);
  });
}

wss.on('connection', (ws) => {
  let authed = false;
  let myId = null;

  ws.on('message', (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch (e) { return; }

    if (!authed) {
      if (data.type !== 'join') return;
      if (data.password !== PASSWORD) {
        send(ws, { type: 'auth-error' });
        ws.close();
        return;
      }
      authed = true;
      myId = String(nextId++);
      clients.set(myId, ws);

      const peers = [];
      clients.forEach((c, cid) => { if (cid !== myId) peers.push({ id: cid }); });
      send(ws, { type: 'welcome', id: myId, peers });
      broadcastExcept(myId, { type: 'peer-joined', id: myId });
      return;
    }

    if (data.type === 'signal' && data.to) {
      const target = clients.get(data.to);
      if (target) send(target, { type: 'signal', from: myId, kind: data.kind, payload: data.payload });
      return;
    }

    if (data.type === 'ping') {
      // App-level heartbeat: keeps traffic flowing so idle-timeout proxies
      // (Render, etc.) don't kill the socket, and lets the client confirm
      // the connection is actually alive (not just "not yet closed").
      send(ws, { type: 'pong' });
      return;
    }
  });

  ws.on('close', () => {
    if (myId && clients.has(myId)) {
      clients.delete(myId);
      broadcastExcept(myId, { type: 'peer-left', id: myId });
    }
  });

  ws.on('error', () => {});
});

server.listen(PORT, () => {
  console.log('Talkie signaling server listening on', PORT);
});

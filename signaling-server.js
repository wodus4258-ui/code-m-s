// talkie-talkie signaling server
// ------------------------------------------------------------------
// Implements the protocol expected by talkie-talkie.html:
//
//   C->S  {type:'join', room:'global'}
//   S->C  {type:'welcome', id, label, peers:[{id,label}, ...]}
//   S->C  {type:'peer-joined', id, label}
//   S->C  {type:'peer-left', id}
//   S->C  {type:'room-full'}
//   C->S  {type:'signal', to:<peerId>, kind:'offer'|'answer'|'ice', payload}
//   S->C  {type:'signal', from:<peerId>, kind:'offer'|'answer'|'ice', payload}
//
// The server does NOT relay chat messages or files at all -- those travel
// directly peer-to-peer over WebRTC data channels once connected. This
// server only introduces peers to each other and assigns each one a
// unique label from the 13-card pool (A,2-10,J,Q,K), max 13 members.
// ------------------------------------------------------------------

const http = require('http');
const crypto = require('crypto');
const WebSocket = require('ws');

const PORT = process.env.PORT || 10000;
const LABEL_POOL = ['A','2','3','4','5','6','7','8','9','10','J','Q','K'];
const MAX_PEERS = LABEL_POOL.length;
const HEARTBEAT_MS = 30000;

// single global room: id -> { ws, label }
const clients = new Map();

function randomId(){
  return crypto.randomBytes(8).toString('hex');
}

function pickLabel(){
  const used = new Set([...clients.values()].map(c => c.label));
  return LABEL_POOL.find(l => !used.has(l)) || null;
}

function send(ws, obj){
  if(ws.readyState === WebSocket.OPEN){
    ws.send(JSON.stringify(obj));
  }
}

function broadcast(obj, exceptId){
  clients.forEach((c, id) => {
    if(id !== exceptId) send(c.ws, obj);
  });
}

function removeClient(id){
  const c = clients.get(id);
  if(!c) return;
  clients.delete(id);
  broadcast({ type: 'peer-left', id }, null);
  console.log(`[leave] ${id} (${c.label}) — ${clients.size} online`);
}

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('talkie-talkie signaling server is running.\n');
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  let myId = null;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let data;
    try{ data = JSON.parse(raw); }catch(e){ return; }

    if(data.type === 'join'){
      if(myId) return; // already joined
      if(clients.size >= MAX_PEERS){
        send(ws, { type: 'room-full' });
        return;
      }
      const label = pickLabel();
      if(!label){
        send(ws, { type: 'room-full' });
        return;
      }
      myId = randomId();
      clients.set(myId, { ws, label });

      const peers = [...clients.entries()]
        .filter(([id]) => id !== myId)
        .map(([id, c]) => ({ id, label: c.label }));

      send(ws, { type: 'welcome', id: myId, label, peers });
      broadcast({ type: 'peer-joined', id: myId, label }, myId);
      console.log(`[join] ${myId} (${label}) — ${clients.size} online`);
      return;
    }

    if(data.type === 'signal'){
      if(!myId) return;
      const target = clients.get(data.to);
      if(!target) return;
      send(target.ws, {
        type: 'signal',
        from: myId,
        kind: data.kind,
        payload: data.payload
      });
      return;
    }
  });

  ws.on('close', () => { if(myId) removeClient(myId); });
  ws.on('error', () => { if(myId) removeClient(myId); });
});

// heartbeat: drop dead sockets (helps on hosts that idle-timeout connections)
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if(ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_MS);

wss.on('close', () => clearInterval(heartbeat));

server.listen(PORT, () => {
  console.log(`talkie-talkie signaling server listening on :${PORT}`);
});

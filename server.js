// Talkie signaling server
// Implements exactly the protocol documented in the client:
//   C->S  {type:'join', password:<string>}
//   S->C  {type:'welcome', id, role:'user'|'operator'} -- only if password is correct
//   S->C  {type:'auth-error'}                          -- if password is wrong, then closes
//   C->S  {type:'enter-channel', channel:<id>, ch10Password?:<string>}
//   S->C  {type:'channel-welcome', channel, id, peers:[{id}, ...]}  -- peers already in that channel
//   S->C  {type:'channel-full', channel}
//   S->C  {type:'channel-auth-error', channel}         -- CH10 only, wrong/missing ch10Password
//   C->S  {type:'leave-channel'}
//   S->C  {type:'peer-joined', channel, id}            -- only to others already in that same channel
//   S->C  {type:'peer-left', channel, id}              -- only to others in that same channel
//   C->S  {type:'signal', to:<peerId>, kind:'offer'|'answer'|'ice', payload}
//   S->C  {type:'signal', from:<peerId>, kind:'offer'|'answer'|'ice', payload}
//   C->S  {type:'set-channel-info', channel, desc, cap}
//   S->C  {type:'stats', total, channels:{<id>:{count,desc,cap}, ...}}
//
// This server deliberately knows almost nothing about a channel's contents:
// it only relays WebRTC signaling (offer/answer/ICE) between clients that
// are BOTH currently members of the same channel, and it never relays or
// notifies across channels — each channel is a fully isolated P2P mesh, so
// one channel's load never grows with the whole app's user count.
//
// The one thing this server DOES track authoritatively is the small set of
// numbers the channel-select screen needs before a client has joined any
// mesh at all: each channel's description, its capacity, its current
// member count, and the system-wide total of connected clients. That's
// pushed to every authenticated client (in or out of a channel) any time it
// changes, as {type:'stats'}. Everything else about a channel — chat text,
// files, nicknames, the talkie-talkie radio — is exchanged purely peer-to-
// peer inside that channel's mesh and never touches this server.
//
// All three passwords below are checked here, server-side, so no client can
// ever bypass them by editing/inspecting the page. Prefer setting all of
// them via environment variables in your host's dashboard (e.g. Render >
// Environment) rather than relying on the fallbacks below — if this file
// lives in a public GitHub repo, a hardcoded password here is just as
// exposed as it was in the old client-side check.
//
//   TALKIE_PASSWORD          general join password (existing)
//   TALKIE_OPERATOR_PASSWORD alternate join password that additionally
//                             grants the 'operator' role, which is the only
//                             role allowed to take the "운영자" nickname
//                             client-side. A join with either password
//                             succeeds; only the role differs.
//   TALKIE_CH10_PASSWORD     separate password required to enter the fixed
//                             CH10 channel (비상 관리채널). Independent of
//                             both passwords above — entering CH10 has
//                             nothing to do with which password was used to
//                             join in the first place.

const http = require('http');
const { WebSocketServer } = require('ws');

const PASSWORD = process.env.TALKIE_PASSWORD || '051627#';
const OPERATOR_PASSWORD = process.env.TALKIE_OPERATOR_PASSWORD || '051627*';
const CH10_PASSWORD = process.env.TALKIE_CH10_PASSWORD || '051627@';
// The one fixed channel id that requires CH10_PASSWORD to enter. Matches the
// literal id the client sends for its "CH10" row (see CHANNELS in talkie.html).
const OPERATOR_CHANNEL_ID = 'CH10';
const PORT = process.env.PORT || 10000;
const DEFAULT_CHANNEL_CAP = 10;
const MIN_CHANNEL_CAP = 1;
const MAX_CHANNEL_CAP = 15;
// A '변동채널' (frequency-matched channel) is just a channel whose id the
// client derives from a 6-digit frequency instead of a fixed CH01~CH10 id
// (see talkie.html). No protocol change was needed for that — any string
// is a valid channel id here already — but those channels should NOT
// persist once empty (unlike the fixed channels, which always exist).
// The client always prefixes such ids with FREQ_CHANNEL_PREFIX so we can
// tell them apart and clean them up.
const FREQ_CHANNEL_PREFIX = 'FQ_';
function isFreqChannel(ch) { return typeof ch === 'string' && ch.indexOf(FREQ_CHANNEL_PREFIX) === 0; }

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Talkie signaling server OK');
});

const wss = new WebSocketServer({ server });

let nextId = 1;
const clients = new Map();     // id -> {ws, channel: string|null}
const channelMeta = new Map(); // channelId -> {desc: string|null, cap: number}

function send(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch (e) {}
}

function getChannelMeta(ch) {
  if (!channelMeta.has(ch)) channelMeta.set(ch, { desc: null, cap: DEFAULT_CHANNEL_CAP });
  return channelMeta.get(ch);
}

function channelMemberIds(ch) {
  const ids = [];
  clients.forEach((c, id) => { if (c.channel === ch) ids.push(id); });
  return ids;
}

function broadcastToChannelExcept(ch, exceptId, obj) {
  const msg = JSON.stringify(obj);
  clients.forEach((c, id) => {
    if (id !== exceptId && c.channel === ch) { try { c.ws.send(msg); } catch (e) {} }
  });
}

function broadcastStats() {
  const channelsOut = {};
  channelMeta.forEach((meta, ch) => {
    channelsOut[ch] = { desc: meta.desc, cap: meta.cap, count: channelMemberIds(ch).length };
  });
  const msg = JSON.stringify({ type: 'stats', total: clients.size, channels: channelsOut });
  clients.forEach((c) => { try { c.ws.send(msg); } catch (e) {} });
}

// Removes a client from whatever channel it's in (if any) and tells the
// other members of that channel it's gone. Does not touch the socket and
// does not broadcast stats itself — callers do that once, after any other
// state changes they're making in the same operation.
function leaveChannel(id) {
  const c = clients.get(id);
  if (!c || !c.channel) return;
  const ch = c.channel;
  c.channel = null;
  broadcastToChannelExcept(ch, id, { type: 'peer-left', channel: ch, id });
  // 변동채널: once the last member leaves, the room ceases to exist — drop
  // its meta entirely so it doesn't linger in memory or in future stats
  // broadcasts. Fixed channels (CH01~CH10) are left alone, on purpose.
  if (isFreqChannel(ch) && channelMemberIds(ch).length === 0) {
    channelMeta.delete(ch);
  }
}

wss.on('connection', (ws) => {
  let authed = false;
  let myId = null;

  ws.on('message', (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch (e) { return; }

    if (!authed) {
      if (data.type !== 'join') return;
      // Either password authenticates; the operator password additionally
      // grants the 'operator' role (checked entirely server-side — the
      // client only ever learns its own role back via 'welcome').
      let role = null;
      if (data.password === PASSWORD) role = 'user';
      else if (OPERATOR_PASSWORD && data.password === OPERATOR_PASSWORD) role = 'operator';
      // TEMP DEBUG — remove after confirming the mismatch. Does not print
      // the actual password values, only their lengths, so it's safe to
      // leave visible in Render's log viewer while you diagnose this.
      console.log('[join attempt]',
        'received length:', data.password ? data.password.length : 0,
        'PASSWORD length:', PASSWORD.length,
        'OPERATOR_PASSWORD set?', !!OPERATOR_PASSWORD,
        'OPERATOR_PASSWORD length:', OPERATOR_PASSWORD ? OPERATOR_PASSWORD.length : 0,
        'matched role:', role);
      if (!role) {
        send(ws, { type: 'auth-error' });
        ws.close();
        return;
      }
      authed = true;
      myId = String(nextId++);
      clients.set(myId, { ws, channel: null, role });
      send(ws, { type: 'welcome', id: myId, role });
      broadcastStats();
      return;
    }

    const me = clients.get(myId);
    if (!me) return;

    if (data.type === 'enter-channel' && typeof data.channel === 'string' && data.channel) {
      const ch = data.channel;
      // CH10 (비상 관리채널) requires its own dedicated password on every
      // entry attempt — independent of both the general and operator join
      // passwords, and independent of the client's role. Checked here so a
      // client can't get in just by knowing (or forging) a channel id.
      if (ch === OPERATOR_CHANNEL_ID) {
        if (!CH10_PASSWORD || data.ch10Password !== CH10_PASSWORD) {
          send(ws, { type: 'channel-auth-error', channel: ch });
          return;
        }
      }
      if (me.channel === ch) {
        // Already in it (e.g. a resend after a brief reconnect) — just
        // re-send the current member list, nothing else changes.
        const peers = channelMemberIds(ch).filter((id) => id !== myId).map((id) => ({ id }));
        send(ws, { type: 'channel-welcome', channel: ch, id: myId, peers });
        return;
      }
      const meta = getChannelMeta(ch);
      const existing = channelMemberIds(ch);
      if (existing.length >= meta.cap) {
        send(ws, { type: 'channel-full', channel: ch });
        return;
      }
      if (me.channel) leaveChannel(myId);
      me.channel = ch;
      const peers = existing.map((id) => ({ id }));
      send(ws, { type: 'channel-welcome', channel: ch, id: myId, peers });
      broadcastToChannelExcept(ch, myId, { type: 'peer-joined', channel: ch, id: myId });
      broadcastStats();
      return;
    }

    if (data.type === 'leave-channel') {
      if (me.channel) { leaveChannel(myId); broadcastStats(); }
      return;
    }

    if (data.type === 'set-channel-info' && typeof data.channel === 'string') {
      // Only the channel you're currently in can have its description/cap
      // changed, and only by someone actually inside it.
      if (me.channel !== data.channel) return;
      const meta = getChannelMeta(data.channel);
      if (typeof data.desc !== 'undefined') {
        meta.desc = (typeof data.desc === 'string' && data.desc) ? data.desc.slice(0, 10) : null;
      }
      if (typeof data.cap === 'number' && !isNaN(data.cap)) {
        meta.cap = Math.max(MIN_CHANNEL_CAP, Math.min(MAX_CHANNEL_CAP, Math.round(data.cap)));
      }
      broadcastStats();
      return;
    }

    if (data.type === 'signal' && data.to) {
      const target = clients.get(data.to);
      // Only relay within the same channel room — this is what makes the
      // isolation actually enforced server-side, not just client etiquette.
      if (target && me.channel && target.channel === me.channel) {
        send(target.ws, { type: 'signal', from: myId, kind: data.kind, payload: data.payload });
      }
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
      const me = clients.get(myId);
      if (me.channel) leaveChannel(myId);
      clients.delete(myId);
      broadcastStats();
    }
  });

  ws.on('error', () => {});
});

server.listen(PORT, () => {
  console.log('Talkie signaling server listening on', PORT);
});

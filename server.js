// Talkie signaling server
// Implements exactly the protocol documented in the client:
//   C->S  {type:'join', password:<string>}
//   S->C  {type:'welcome', id, role:'user'|'operator'} -- only if password is correct
//   S->C  {type:'auth-error'}                          -- if password is wrong, then closes
//   C->S  {type:'set-nickname', nickname:<string>}     -- informational only, for admin panel
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
//   S->C  {type:'kicked'}                              -- admin forced this client off; client
//                                                          must drop straight to the password screen
//   S->C  {type:'server-locked'}                       -- sent instead of 'welcome'/'auth-error' when
//                                                          a 'join' arrives while ALL KILL is active;
//                                                          client must NOT retry, just show 접속중지
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
// files, the talkie-talkie radio — is exchanged purely peer-to-peer inside
// that channel's mesh and never touches this server. The one exception is
// the nickname: the client also reports it here (via 'set-nickname'), purely
// so the admin panel (talkie-ad.html) can show who's connected — it is
// never used for any access-control decision server-side.
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
//
// Country/region/city in the admin panel come from the bundled geoip-lite
// package (offline IP database, no per-request network calls) — run
// `npm install` after pulling this change so that dependency is present.

const http = require('http');
const { WebSocketServer } = require('ws');
// Offline IP->country/region/city lookup (bundled database, no network
// calls per-request). Wrapped in try/catch so a missing `npm install`
// degrades to '-' fields instead of crashing the whole server.
let geoip = null;
try { geoip = require('geoip-lite'); } catch (e) { geoip = null; }

const PASSWORD = process.env.TALKIE_PASSWORD || '051627#';
const OPERATOR_PASSWORD = process.env.TALKIE_OPERATOR_PASSWORD || '051627*';
const CH10_PASSWORD = process.env.TALKIE_CH10_PASSWORD || '051627@';
// Key required to manage the announcement banner and read the admin status
// endpoint (talkie-ad.html). This is a separate, server-verified secret —
// unrelated to the "4258" screen-lock PIN typed into talkie-ad.html itself,
// which is only a client-side gate on that page's UI. Set this via Render's
// Environment tab like the passwords above.
//   TALKIE_ADMIN_KEY         required by talkie-ad.html to read/write the
//                             notice banner, view live connection stats
//                             (including each client's nickname/IP/channel),
//                             and to forcibly disconnect ("KICK") a client.
//                             Keep it out of source control.
const ADMIN_KEY = process.env.TALKIE_ADMIN_KEY || 'talkie-admin-key-change-me';
// TALKIE_ADMIN_KEY also guards two new admin actions used by talkie-ad.html's
// [서버 관리] panel:
//   POST /kick-all   { key }            -- "ALL KICK": force-disconnect every
//                                           currently connected client at once
//                                           (same as /kick, but everyone).
//                                           Anyone can immediately type the
//                                           password again and reconnect.
//   POST /all-kill    { key, active }   -- "ALL KILL" ↔ "RES": active:true
//                                           does an ALL KICK *and* flips the
//                                           server into a locked state where
//                                           every subsequent 'join' (right
//                                           password or not, from anyone) is
//                                           refused with {type:'server-locked'}
//                                           until active:false is sent.
//   GET  /lock-status                    -- public (no key): { locked } — lets
//                                           a client still sitting on the
//                                           password screen (i.e. before it
//                                           has attempted to join at all) know
//                                           to hide the password box and show
//                                           "접속중지" instead of letting
//                                           someone type a password that would
//                                           just be refused.
//   GET  /log         ?key=...           -- admin-only: the full rolling
//                                           event log (login/logout/
//                                           channel-enter/kick) for
//                                           talkie-ad.html's [LOG] view.
//   POST /auto-kick    { key, kind, country?, region?, ip?, device?, label? }
//                                        -- admin-only: add an AUTO KICK
//                                           rule (kind: 'country'|'region'|
//                                           'ip'|'specific'); kicks any
//                                           currently-connected match right
//                                           away and blocks that condition
//                                           from joining from then on.
//   GET  /auto-kick-list ?key=...        -- admin-only: list active AUTO
//                                           KICK rules (for [AUTO KICK 해제]).
//   POST /auto-kick-remove { key, id }   -- admin-only: remove one AUTO KICK
//                                           rule by id.
//   POST /kick-channel { key, channel }  -- admin-only: KICK everyone
//                                           currently in one channel.
//   POST /auto-kick-channel { key, channel }
//                                        -- admin-only: AUTO KICK everyone
//                                           currently in one channel, each
//                                           by their own 'specific' (country+
//                                           region+ip+device) condition.
// The one fixed channel id that requires CH10_PASSWORD to enter. Matches the
// literal id the client sends for its "CH10" row (see CHANNELS in talkie.html).
const OPERATOR_CHANNEL_ID = 'CH10';
const PORT = process.env.PORT || 10000;
const DEFAULT_CHANNEL_CAP = 10;
// Fixed channels (CH01~CH10) and 변동채널(frequency channels) allow different
// minimum caps — fixed channels are meant to stay reasonably large (10~15),
// while a 변동채널 can be as small as a 1:1 conversation plus one more (2~15).
// Both share the same upper bound.
const MIN_FIXED_CHANNEL_CAP = 10;
const MIN_FREQ_CHANNEL_CAP = 2;
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
// Used only to pre-list all ten fixed channels in the /status admin
// endpoint (with a 0 count) even before anyone has ever entered one —
// channelMeta itself is only populated lazily, on first entry.
const FIXED_CHANNEL_IDS = ['CH01','CH02','CH03','CH04','CH05','CH06','CH07','CH08','CH09','CH10'];

// Two independent server-wide announcements, kept in memory only (reset on
// server restart), one per banner: 'pw' drives the banner under the
// password screen, 'ch' drives the banner on the channel-select screen.
// They're published/edited separately from talkie-ad.html and pushed to
// clients together (see noticePayload) so each client-side banner just
// reads the slot it cares about.
let notices = {
  pw: { text: '', imageUrl: '', updatedAt: 0 },
  ch: { text: '', imageUrl: '', updatedAt: 0 },
};
const NOTICE_TARGETS = ['pw', 'ch'];

// ALL KILL state. In-memory only (like everything else here) — resets to
// unlocked on server restart. While true, no 'join' (from anyone, correct
// password or not) succeeds; see the join handler below.
let serverLocked = false;

// 국경 봉쇄 ("country block") state. In-memory only, resets on restart.
// While true, any 'join' from a client whose geoip-lite country is known
// and is NOT 'KR' is refused exactly like ALL KILL (reuses the same
// {type:'server-locked'} message so talkie.html needs no changes to
// recognize it — it already shows "접속중지" for that message). A client
// whose country can't be determined (private/dev IP, geoip miss — reported
// as '-') is NOT blocked, so this never accidentally locks everyone out
// just because geoip-lite failed to resolve an IP.
let countryBlockActive = false;
const COUNTRY_BLOCK_ALLOW = 'KR';

// AUTO KICK 규칙. 관리자가 talkie-ad.html의 [AUTO KICK] 팝업(국가/지역/IP/
// 특정) 또는 채널 팝업의 [채널 AUTO KICK]에서 만든, "이 조건에 맞으면 이후
// 접속도 계속 차단한다"는 규칙 목록. In-memory only, like everything else
// here — resets on restart.
//   kind:'country'  — country 코드가 일치하면 차단
//   kind:'region'   — country + region이 모두 일치해야 차단 (region 코드는
//                      국가마다 겹칠 수 있어 country를 함께 본다)
//   kind:'ip'       — ip가 정확히 일치하면 차단
//   kind:'specific' — country + region + ip + device가 전부 일치하는
//                      "교집합"일 때만 차단 (가장 좁은 범위, 팝업의 [특정])
// 규칙은 join 시점에 이미 계산해둔 geoip/UA 값과 대조해 로그인 자체를 막고,
// 새 규칙이 추가되는 순간에는 이미 접속 중인 클라이언트 중 일치하는 사람도
// 즉시 KICK한다(kickClientsMatchingRule).
const autoKickRules = [];
let nextRuleId = 1;

function ruleMatchesCandidate(rule, cand) {
  switch (rule.kind) {
    case 'country':
      return !!rule.country && rule.country !== '-' && cand.country === rule.country;
    case 'region':
      return !!rule.country && rule.country !== '-' && !!rule.region && rule.region !== '-' &&
        cand.country === rule.country && cand.region === rule.region;
    case 'ip':
      return !!rule.ip && cand.ip === rule.ip;
    case 'specific':
      return !!rule.ip && cand.ip === rule.ip &&
        cand.country === rule.country && cand.region === rule.region && cand.device === rule.device;
    default:
      return false;
  }
}

function isAutoKickBlocked(cand) {
  return autoKickRules.some((r) => ruleMatchesCandidate(r, cand));
}

// Rolling event log for talkie-ad.html's [LOG] view — login / logout /
// channel-enter / kick, each with a snapshot of who/where/what-device at
// that moment. In-memory only, so "언제부터 추적 가능한가" is simply "since
// this server process last started" (same lifetime as every other piece of
// state here). Capped so a long-running server doesn't grow this forever.
const eventLog = [];
const MAX_LOG_ENTRIES = 5000;
function logEvent(type, id, c, extra) {
  const entry = Object.assign({
    type,
    id,
    ts: Date.now(),
    nickname: c ? (c.nickname || null) : null,
    ip: c ? (c.ip || null) : null,
    country: c ? (c.country || null) : null,
    region: c ? (c.region || null) : null,
    city: c ? (c.city || null) : null,
    device: c ? (c.device || null) : null,
  }, extra || {});
  eventLog.push(entry);
  if (eventLog.length > MAX_LOG_ENTRIES) eventLog.splice(0, eventLog.length - MAX_LOG_ENTRIES);
}

function readBody(req, cb) {
  let body = '';
  let tooBig = false;
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > 3 * 1024 * 1024) { tooBig = true; req.destroy(); }
  });
  req.on('end', () => { if (!tooBig) cb(body); });
}

function sendJson(res, status, obj) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(JSON.stringify(obj));
}

function noticePayload() {
  return { type: 'notice', pw: notices.pw, ch: notices.ch };
}

const server = http.createServer((req, res) => {
  const path = (req.url || '').split('?')[0];

  // CORS preflight for talkie-ad.html, which may be opened from a
  // different origin (a local file, or a separate static host) than this
  // signaling server.
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  // Public: anyone (including a client still sitting on the password
  // screen, before it has authenticated over the websocket at all) can
  // read the current notices. Returns both slots at once — this is what
  // lets the password-screen banner and the channel-select banner each
  // show their own text/image before (and independent of) login.
  if (path === '/notice' && req.method === 'GET') {
    sendJson(res, 200, { pw: notices.pw, ch: notices.ch });
    return;
  }

  // Admin-only: publish/replace one of the two notice slots. Requires
  // TALKIE_ADMIN_KEY plus a target of 'pw' (password screen) or 'ch'
  // (channel-select screen) — the two are edited independently, so this
  // never touches the other slot.
  if (path === '/notice' && req.method === 'POST') {
    readBody(req, (body) => {
      let data;
      try { data = JSON.parse(body || '{}'); } catch (e) { sendJson(res, 400, { error: 'invalid json' }); return; }
      if (!ADMIN_KEY || data.key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
      const target = NOTICE_TARGETS.indexOf(data.target) !== -1 ? data.target : null;
      if (!target) { sendJson(res, 400, { error: 'invalid target' }); return; }
      notices[target] = {
        text: typeof data.text === 'string' ? data.text.slice(0, 500) : '',
        imageUrl: typeof data.imageUrl === 'string' ? data.imageUrl.slice(0, 4000) : '',
        updatedAt: Date.now(),
      };
      broadcastNotice();
      sendJson(res, 200, { ok: true, target, notice: notices[target], notices });
    });
    return;
  }

  // Admin-only: live connection status (total + per-channel counts,
  // including 변동채널 with their raw FQ_-prefixed ids) for talkie-ad.html's
  // status panel, PLUS a flat per-client list (id, nickname, channel, IP,
  // connect time) for its 접속자 관리 panel. Requires TALKIE_ADMIN_KEY as a
  // query param.
  if (path === '/status' && req.method === 'GET') {
    let key = null;
    try { key = new URL(req.url, 'http://x').searchParams.get('key'); } catch (e) {}
    if (!ADMIN_KEY || key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
    const channelsOut = {};
    FIXED_CHANNEL_IDS.forEach((ch) => { channelsOut[ch] = { desc: null, cap: DEFAULT_CHANNEL_CAP, count: 0 }; });
    channelMeta.forEach((meta, ch) => {
      channelsOut[ch] = { desc: meta.desc, cap: meta.cap, count: channelMemberIds(ch).length };
    });
    const clientsOut = [];
    clients.forEach((c, id) => {
      clientsOut.push({
        id,
        nickname: c.nickname || null,
        // null == still on the channel-select screen (hasn't entered a
        // channel yet, or just left one) — the client-side admin panel
        // renders that case as "채널선택".
        channel: c.channel,
        connectedAt: c.connectedAt,
        ip: c.ip || null,
        country: c.country || null,
        region: c.region || null,
        city: c.city || null,
        device: c.device || null,
      });
    });
    sendJson(res, 200, { total: clients.size, channels: channelsOut, clients: clientsOut, locked: serverLocked, countryBlocked: countryBlockActive });
    return;
  }

  // Admin-only: the full rolling event log (login/logout/channel-enter/kick)
  // for talkie-ad.html's [LOG] view. See eventLog/logEvent above for what's
  // tracked and since when.
  if (path === '/log' && req.method === 'GET') {
    let key = null;
    try { key = new URL(req.url, 'http://x').searchParams.get('key'); } catch (e) {}
    if (!ADMIN_KEY || key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
    sendJson(res, 200, { log: eventLog });
    return;
  }

  // Admin-only: forcibly disconnect one client by its server-assigned id
  // (never by IP — see the comment on getClientIp for why). Tells the
  // client {type:'kicked'} first so it can drop itself straight back to the
  // password screen, then closes the socket from this end regardless, so a
  // client that's stuck or ignores the message still gets cut off.
  if (path === '/kick' && req.method === 'POST') {
    readBody(req, (body) => {
      let data;
      try { data = JSON.parse(body || '{}'); } catch (e) { sendJson(res, 400, { error: 'invalid json' }); return; }
      if (!ADMIN_KEY || data.key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
      const target = clients.get(String(data.id));
      if (!target) { sendJson(res, 404, { error: 'not found' }); return; }
      target.wasKicked = true;
      logEvent('kick', String(data.id), target);
      send(target.ws, { type: 'kicked' });
      // Small delay so the 'kicked' frame has a moment to actually reach the
      // client before the socket goes away — the client's own close handler
      // will still clean everything up server-side even if this never
      // arrives (e.g. the client was already gone).
      setTimeout(() => { try { target.ws.close(); } catch (e) {} }, 150);
      sendJson(res, 200, { ok: true });
    });
    return;
  }

  // Admin-only: "ALL KICK" — force-disconnect every currently connected
  // client in one shot. Unlike /all-kill below, this never touches
  // serverLocked, so anyone kicked this way can retype the password and be
  // straight back in.
  if (path === '/kick-all' && req.method === 'POST') {
    readBody(req, (body) => {
      let data;
      try { data = JSON.parse(body || '{}'); } catch (e) { sendJson(res, 400, { error: 'invalid json' }); return; }
      if (!ADMIN_KEY || data.key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
      kickAllClients();
      sendJson(res, 200, { ok: true });
    });
    return;
  }

  // Admin-only: "ALL KILL" (active:true) / "RES" (active:false). Turning it
  // on does an ALL KICK and then keeps every future 'join' attempt locked
  // out (see the join handler below) until this is called again with
  // active:false. Turning it off never needs to kick anyone — nobody could
  // have logged in while it was on.
  if (path === '/all-kill' && req.method === 'POST') {
    readBody(req, (body) => {
      let data;
      try { data = JSON.parse(body || '{}'); } catch (e) { sendJson(res, 400, { error: 'invalid json' }); return; }
      if (!ADMIN_KEY || data.key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
      serverLocked = !!data.active;
      if (serverLocked) kickAllClients();
      sendJson(res, 200, { ok: true, locked: serverLocked });
    });
    return;
  }

  // Admin-only: "국경 봉쇄" (active:true) / 해제 (active:false). Turning it
  // on immediately kicks every currently-connected client whose geoip
  // country is known and isn't 'KR', and from then on refuses every future
  // 'join' from a non-KR IP (see the join handler) until turned off again.
  // Unlike ALL KILL, KR clients are never affected either way.
  if (path === '/country-block' && req.method === 'POST') {
    readBody(req, (body) => {
      let data;
      try { data = JSON.parse(body || '{}'); } catch (e) { sendJson(res, 400, { error: 'invalid json' }); return; }
      if (!ADMIN_KEY || data.key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
      countryBlockActive = !!data.active;
      if (countryBlockActive) kickNonKoreaClients();
      sendJson(res, 200, { ok: true, countryBlocked: countryBlockActive });
    });
    return;
  }

  // Admin-only: "AUTO KICK" 규칙 추가. kind별로 필요한 필드가 다르다(위
  // autoKickRules 선언부 주석 참고). 규칙을 추가하는 즉시 현재 접속 중인
  // 클라이언트 중 일치하는 사람도 함께 KICK한다.
  if (path === '/auto-kick' && req.method === 'POST') {
    readBody(req, (body) => {
      let data;
      try { data = JSON.parse(body || '{}'); } catch (e) { sendJson(res, 400, { error: 'invalid json' }); return; }
      if (!ADMIN_KEY || data.key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
      const kind = ['country', 'region', 'ip', 'specific'].indexOf(data.kind) !== -1 ? data.kind : null;
      if (!kind) { sendJson(res, 400, { error: 'invalid kind' }); return; }
      const rule = {
        id: String(nextRuleId++),
        kind,
        country: (typeof data.country === 'string' && data.country) ? data.country.slice(0, 8) : null,
        region: (typeof data.region === 'string' && data.region) ? data.region.slice(0, 40) : null,
        ip: (typeof data.ip === 'string' && data.ip) ? data.ip.slice(0, 64) : null,
        device: (typeof data.device === 'string' && data.device) ? data.device.slice(0, 60) : null,
        label: typeof data.label === 'string' ? data.label.slice(0, 80) : null,
        createdAt: Date.now(),
      };
      if (kind === 'country' && (!rule.country || rule.country === '-')) { sendJson(res, 400, { error: 'country required' }); return; }
      if (kind === 'region' && (!rule.country || rule.country === '-' || !rule.region || rule.region === '-')) { sendJson(res, 400, { error: 'country/region required' }); return; }
      if ((kind === 'ip' || kind === 'specific') && !rule.ip) { sendJson(res, 400, { error: 'ip required' }); return; }
      autoKickRules.push(rule);
      logEvent('auto-kick-add', null, null, { rule });
      kickClientsMatchingRule(rule);
      sendJson(res, 200, { ok: true, rule });
    });
    return;
  }

  // Admin-only: 현재 활성화된 AUTO KICK 규칙 목록 — talkie-ad.html의
  // [AUTO KICK 해제] 팝업이 사용한다.
  if (path === '/auto-kick-list' && req.method === 'GET') {
    let key = null;
    try { key = new URL(req.url, 'http://x').searchParams.get('key'); } catch (e) {}
    if (!ADMIN_KEY || key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
    sendJson(res, 200, { rules: autoKickRules });
    return;
  }

  // Admin-only: AUTO KICK 규칙 해제(삭제). 이미 KICK된 세션을 되돌리지는
  // 않는다 — 해제 이후의 접속부터 다시 허용될 뿐이다.
  if (path === '/auto-kick-remove' && req.method === 'POST') {
    readBody(req, (body) => {
      let data;
      try { data = JSON.parse(body || '{}'); } catch (e) { sendJson(res, 400, { error: 'invalid json' }); return; }
      if (!ADMIN_KEY || data.key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
      const idx = autoKickRules.findIndex((r) => r.id === String(data.id));
      if (idx === -1) { sendJson(res, 404, { error: 'not found' }); return; }
      const removed = autoKickRules.splice(idx, 1)[0];
      logEvent('auto-kick-remove', null, null, { rule: removed });
      sendJson(res, 200, { ok: true });
    });
    return;
  }

  // Admin-only: "채널 KICK" — 지정한 채널에 현재 참여 중인 전원을 KICK한다
  // (AUTO KICK 규칙은 만들지 않으므로 재접속/재입장은 그대로 가능).
  if (path === '/kick-channel' && req.method === 'POST') {
    readBody(req, (body) => {
      let data;
      try { data = JSON.parse(body || '{}'); } catch (e) { sendJson(res, 400, { error: 'invalid json' }); return; }
      if (!ADMIN_KEY || data.key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
      const ch = (typeof data.channel === 'string' && data.channel) ? data.channel : null;
      if (!ch) { sendJson(res, 400, { error: 'invalid channel' }); return; }
      const count = kickChannelClients(ch);
      sendJson(res, 200, { ok: true, count });
    });
    return;
  }

  // Admin-only: "채널 AUTO KICK" — 지정한 채널에 현재 참여 중인 전원을 각자
  // 본인 조건("특정")으로 AUTO KICK한다.
  if (path === '/auto-kick-channel' && req.method === 'POST') {
    readBody(req, (body) => {
      let data;
      try { data = JSON.parse(body || '{}'); } catch (e) { sendJson(res, 400, { error: 'invalid json' }); return; }
      if (!ADMIN_KEY || data.key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
      const ch = (typeof data.channel === 'string' && data.channel) ? data.channel : null;
      if (!ch) { sendJson(res, 400, { error: 'invalid channel' }); return; }
      const rules = autoKickChannelClients(ch);
      sendJson(res, 200, { ok: true, rules });
    });
    return;
  }

  // Public: lets a client still sitting on the password screen (before it
  // has ever sent 'join' over the websocket) know whether the server is
  // currently under ALL KILL lockdown, so it can hide the password box and
  // show "접속중지" instead of letting someone type a password that would
  // just be refused. No admin key needed — this leaks nothing but a
  // boolean, same trust level as the password screen itself.
  if (path === '/lock-status' && req.method === 'GET') {
    sendJson(res, 200, { locked: serverLocked });
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Talkie signaling server OK');
});

const wss = new WebSocketServer({ server });

let nextId = 1;
// id -> {ws, channel: string|null, role, ip, connectedAt, nickname: string|null}
const clients = new Map();
const channelMeta = new Map(); // channelId -> {desc: string|null, cap: number}
// Every currently-open websocket, authenticated or not — used only to push
// {type:'notice'} updates immediately to everyone, including someone who's
// still sitting on the password screen (see wss.on('connection') below).
const rawSockets = new Set();

function send(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch (e) {}
}

// The socket only ever sees Render's proxy IP directly, so the real client
// IP has to be read off X-Forwarded-For (Render puts the real client IP
// first in that list — see Render's own docs/support on this header).
// This is purely informational (shown in talkie-ad.html so an admin has
// something to go on if a kicked user reconnects) — it is NEVER used to
// identify who to KICK, since a shared IP (same wifi, same carrier NAT)
// would otherwise let one KICK hit innocent bystanders on that IP too.
function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || '';
}

// Best-effort country/region/city for an IP, using the bundled geoip-lite
// database (no external requests). Private/local IPs (dev, or a host that
// doesn't forward a real client IP) simply come back as '-' fields — this
// is purely informational for the admin panel, never used for any
// access-control decision.
function getGeoInfo(ip) {
  if (!geoip || !ip) return { country: '-', region: '-', city: '-' };
  let g = null;
  try { g = geoip.lookup(ip); } catch (e) { g = null; }
  if (!g) return { country: '-', region: '-', city: '-' };
  return {
    country: g.country || '-',
    region: g.region || '-',
    city: g.city || '-',
  };
}

// Coarse device/browser label parsed from the User-Agent header the browser
// sends on the websocket upgrade request. This is a self-reported string a
// client could fake, and modern browsers increasingly freeze/generalize it
// for privacy — treat it as a rough hint for the admin panel, not a hard
// device fingerprint.
function parseDeviceLabel(ua) {
  if (!ua) return '-';
  const s = String(ua);
  let os = 'Unknown';
  if (/iPad/i.test(s)) os = 'iPad';
  else if (/iPhone/i.test(s)) os = 'iPhone';
  else if (/Android/i.test(s)) os = 'Android';
  else if (/Macintosh|Mac OS X/i.test(s)) os = 'Mac';
  else if (/Windows/i.test(s)) os = 'Windows';
  else if (/CrOS/i.test(s)) os = 'ChromeOS';
  else if (/Linux/i.test(s)) os = 'Linux';
  let browser = '';
  if (/EdgA?\//i.test(s)) browser = 'Edge';
  else if (/CriOS/i.test(s)) browser = 'Chrome';
  else if (/FxiOS/i.test(s)) browser = 'Firefox';
  else if (/Firefox\//i.test(s)) browser = 'Firefox';
  else if (/Chrome\//i.test(s) && !/Chromium/i.test(s)) browser = 'Chrome';
  else if (/Safari\//i.test(s) && !/Chrome/i.test(s)) browser = 'Safari';
  return browser ? (os + ' · ' + browser) : os;
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

function broadcastNotice() {
  const msg = JSON.stringify(noticePayload());
  rawSockets.forEach((s) => { try { s.send(msg); } catch (e) {} });
}

function broadcastStats() {
  const channelsOut = {};
  channelMeta.forEach((meta, ch) => {
    channelsOut[ch] = { desc: meta.desc, cap: meta.cap, count: channelMemberIds(ch).length };
  });
  const msg = JSON.stringify({ type: 'stats', total: clients.size, channels: channelsOut });
  clients.forEach((c) => { try { c.ws.send(msg); } catch (e) {} });
}

// "ALL KICK": force off every currently connected (authenticated) client at
// once. Tells each one {type:'kicked'} first (same as the single-client
// /kick path) so it can drop itself straight back to the password screen,
// then closes every socket shortly after so a client that's stuck or
// ignores the message still gets cut off. Does not touch serverLocked —
// callers decide separately whether logins stay open afterward.
function kickAllClients() {
  const sockets = [];
  clients.forEach((c, id) => {
    c.wasKicked = true;
    logEvent('kick', id, c);
    send(c.ws, { type: 'kicked' });
    sockets.push(c.ws);
  });
  setTimeout(() => {
    sockets.forEach((ws) => { try { ws.close(); } catch (e) {} });
  }, 150);
}

// "국경 봉쇄": force off every currently connected client whose geoip
// country is known and isn't 'KR'. A client whose country is unresolved
// ('-') is left alone — see the countryBlockActive comment above for why.
function kickNonKoreaClients() {
  const sockets = [];
  clients.forEach((c, id) => {
    if (c.country && c.country !== '-' && c.country !== COUNTRY_BLOCK_ALLOW) {
      c.wasKicked = true;
      logEvent('kick', id, c, { reason: 'country-block' });
      send(c.ws, { type: 'kicked' });
      sockets.push(c.ws);
    }
  });
  setTimeout(() => {
    sockets.forEach((ws) => { try { ws.close(); } catch (e) {} });
  }, 150);
}

// AUTO KICK 규칙에 걸리는, 현재 접속 중인 클라이언트를 즉시 KICK. 규칙이
// 새로 추가된 직후 한 번 호출해 "이미 들어와 있던 사람"도 놓치지 않는다.
function kickClientsMatchingRule(rule) {
  const sockets = [];
  clients.forEach((c, id) => {
    if (ruleMatchesCandidate(rule, c)) {
      c.wasKicked = true;
      logEvent('kick', id, c, { reason: 'auto-kick', ruleId: rule.id, ruleKind: rule.kind });
      send(c.ws, { type: 'kicked' });
      sockets.push(c.ws);
    }
  });
  setTimeout(() => { sockets.forEach((ws) => { try { ws.close(); } catch (e) {} }); }, 150);
}

// "채널 KICK": 특정 채널에 현재 참여 중인 전원을 KICK한다. AUTO KICK 규칙은
// 만들지 않으므로 재접속/재입장은 그대로 가능하다.
function kickChannelClients(ch) {
  const sockets = [];
  clients.forEach((c, id) => {
    if (c.channel === ch) {
      c.wasKicked = true;
      logEvent('kick', id, c, { reason: 'channel-kick', channel: ch });
      send(c.ws, { type: 'kicked' });
      sockets.push(c.ws);
    }
  });
  setTimeout(() => { sockets.forEach((ws) => { try { ws.close(); } catch (e) {} }); }, 150);
  return sockets.length;
}

// "채널 AUTO KICK": 특정 채널에 현재 참여 중인 전원을, 각자 본인의
// country+region+ip+device 교집합("특정" 조건)으로 AUTO KICK 규칙을 만들면서
// KICK한다. 채널 전체를 국가/지역/IP 단위로 뭉뚱그려 막으면 그 채널과 무관한
// 다른 사용자까지 함께 막힐 수 있으므로, 일부러 가장 좁은 "특정" 조건만
// 사용한다.
function autoKickChannelClients(ch) {
  const addedRules = [];
  const sockets = [];
  clients.forEach((c, id) => {
    if (c.channel !== ch) return;
    if (c.ip) {
      const rule = {
        id: String(nextRuleId++),
        kind: 'specific',
        country: c.country || null,
        region: c.region || null,
        ip: c.ip,
        device: c.device || null,
        label: '채널 AUTO KICK (' + ch + ')',
        createdAt: Date.now(),
      };
      autoKickRules.push(rule);
      addedRules.push(rule);
      logEvent('auto-kick-add', id, c, { rule, channel: ch });
    }
    c.wasKicked = true;
    logEvent('kick', id, c, { reason: 'channel-auto-kick', channel: ch });
    send(c.ws, { type: 'kicked' });
    sockets.push(c.ws);
  });
  setTimeout(() => { sockets.forEach((ws) => { try { ws.close(); } catch (e) {} }); }, 150);
  return addedRules;
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

wss.on('connection', (ws, req) => {
  let authed = false;
  let myId = null;
  const ip = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  const geo = getGeoInfo(ip);
  const device = parseDeviceLabel(ua);

  // Track this socket for notice broadcasts and push the current notice
  // right away — this works even before 'join', so the password screen's
  // banner has something to show as soon as the app opens a socket.
  rawSockets.add(ws);
  send(ws, noticePayload());

  ws.on('message', (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch (e) { return; }

    if (!authed) {
      if (data.type !== 'join') return;
      // ALL KILL: refuse every join outright, correct password or not, and
      // don't even look at data.password. The client must not treat this as
      // a wrong-password case (no retry prompt) — see 'server-locked' in the
      // client's handleServerMessage.
      if (serverLocked) {
        send(ws, { type: 'server-locked' });
        ws.close();
        return;
      }
      // 국경 봉쇄: 국가가 확인되었고 'KR'이 아니면 즉시 거부. 국가 판별이
      // 안 된('-') 경우는 차단하지 않는다(geoip 실패로 전원 차단되는 사고
      // 방지). ALL KILL과 동일한 메시지({type:'server-locked'})를 재사용해
      // 클라이언트(talkie.html) 쪽 변경 없이도 곧바로 "접속중지" 화면이
      // 뜨도록 한다.
      if (countryBlockActive && geo.country && geo.country !== '-' && geo.country !== COUNTRY_BLOCK_ALLOW) {
        send(ws, { type: 'server-locked' });
        ws.close();
        return;
      }
      // AUTO KICK 규칙에 걸리는 접속도 국경 봉쇄와 동일하게 처리 —
      // 클라이언트(talkie.html) 쪽 변경 없이도 곧바로 "접속중지" 화면이
      // 뜨도록 {type:'server-locked'}를 그대로 재사용한다.
      if (isAutoKickBlocked({ country: geo.country, region: geo.region, ip, device })) {
        send(ws, { type: 'server-locked' });
        ws.close();
        return;
      }
      // Either password authenticates; the operator password additionally
      // grants the 'operator' role (checked entirely server-side — the
      // client only ever learns its own role back via 'welcome').
      let role = null;
      if (data.password === PASSWORD) role = 'user';
      else if (OPERATOR_PASSWORD && data.password === OPERATOR_PASSWORD) role = 'operator';
      if (!role) {
        send(ws, { type: 'auth-error' });
        ws.close();
        return;
      }
      authed = true;
      myId = String(nextId++);
      clients.set(myId, {
        ws, channel: null, role, ip, connectedAt: Date.now(), nickname: null,
        country: geo.country, region: geo.region, city: geo.city, device,
        wasKicked: false,
      });
      send(ws, { type: 'welcome', id: myId, role });
      logEvent('login', myId, clients.get(myId));
      broadcastStats();
      return;
    }

    const me = clients.get(myId);
    if (!me) return;

    if (data.type === 'set-nickname' && typeof data.nickname === 'string') {
      // Informational only (see the protocol comment at the top of this
      // file) — purely so talkie-ad.html's 접속자 관리 panel has something
      // to show. Never used for auth or any access-control decision.
      me.nickname = data.nickname.slice(0, 20) || null;
      return;
    }

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
      logEvent('channel-enter', myId, me, { channel: ch });
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
        const minCap = isFreqChannel(data.channel) ? MIN_FREQ_CHANNEL_CAP : MIN_FIXED_CHANNEL_CAP;
        meta.cap = Math.max(minCap, Math.min(MAX_CHANNEL_CAP, Math.round(data.cap)));
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
    rawSockets.delete(ws);
    if (myId && clients.has(myId)) {
      const me = clients.get(myId);
      // Don't double-log: a kick already recorded its own 'kick' entry
      // (and the client never gets a chance to reconnect/logout normally
      // in that same session), so a plain 'logout' entry here would just
      // be noise on top of it.
      if (!me.wasKicked) logEvent('logout', myId, me);
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

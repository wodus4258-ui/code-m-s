// Talkie signaling server
// Implements exactly the protocol documented in the client:
//   C->S  {type:'join', password:<string>}             -- 시작 비밀번호(일반/운영자). 서버에서 검증.
//   S->C  {type:'welcome', id, role:'user'|'operator'} -- 비밀번호 일치 시
//   S->C  {type:'auth-error'}                          -- 비밀번호 불일치 → 소켓 즉시 닫힘
//   C->S  {type:'operator-auth', password:<string>}    -- "운영자" 닉네임 선택 시 별도 인증
//   S->C  {type:'operator-auth-ok'} | {type:'operator-auth-error'}
//   C->S  {type:'set-nickname', nickname:<string>}
//   C->S  {type:'enter-channel', channel:<id>, ch10Password?:<string>}
//   S->C  {type:'channel-welcome', channel, id, peers:[{id}, ...]}
//   S->C  {type:'channel-full', channel}
//   S->C  {type:'channel-auth-error', channel}         -- CH10 only
//   C->S  {type:'leave-channel'}
//   S->C  {type:'peer-joined', channel, id}
//   S->C  {type:'peer-left', channel, id}
//   C->S  {type:'signal', to:<peerId>, kind, payload}
//   S->C  {type:'signal', from:<peerId>, kind, payload}
//   C->S  {type:'set-channel-info', channel, desc, cap}
//   S->C  {type:'stats', total, channels:{...}}
//   S->C  {type:'kicked'}                              -- 관리자 KICK
//   S->C  {type:'server-locked'}                       -- ALL KILL / 국경봉쇄 / AUTO KICK

const http = require('http');
const { WebSocketServer } = require('ws');
let geoip = null;
try { geoip = require('geoip-lite'); } catch (e) { geoip = null; }

// ============================================================================
// 필수 환경변수 강제
// ----------------------------------------------------------------------------
// 이전 버전은 `process.env.X || '하드코딩_기본값'` 형태였기 때문에, 배포 시
// env 등록을 잊어도 서버가 조용히 뜨면서 소스에 노출된 기본 비밀번호로
// 서비스되는 심각한 보안 문제가 있었다. 이제 값이 없으면 기동을 거부한다.
// ============================================================================
function requireEnv(name, description){
  const v = process.env[name];
  if(!v){
    console.error('[FATAL] 필수 환경변수 누락: ' + name + (description ? ' ' + description : ''));
    console.error('        Render 대시보드 Environment 탭에 값을 등록한 뒤 다시 배포하세요.');
    process.exit(1);
  }
  return v;
}
const PASSWORD          = requireEnv('TALKIE_PASSWORD',          '(일반 접속 비밀번호)');
const OPERATOR_PASSWORD = requireEnv('TALKIE_OPERATOR_PASSWORD', '(운영자 인증 비밀번호)');
const CH10_PASSWORD     = requireEnv('TALKIE_CH10_PASSWORD',     '(CH10 관리채널 입장 비밀번호)');
const ADMIN_KEY         = requireEnv('TALKIE_ADMIN_KEY',         '(관리자 페이지 ADMIN_KEY)');

const OPERATOR_CHANNEL_ID = 'CH10';
const PORT = process.env.PORT || 10000;
const DEFAULT_CHANNEL_CAP = 10;
const MIN_FIXED_CHANNEL_CAP = 10;
const MIN_FREQ_CHANNEL_CAP = 2;
const MAX_CHANNEL_CAP = 15;
const FREQ_CHANNEL_PREFIX = 'FQ_';
const SECRET_FREQ_CHANNEL_PREFIX = 'SFQ_';

// TALKIE_DECOY: 'o' (또는 미설정) → 위장(디코이) 시작 화면 표시
//               'x'                → 디코이 건너뛰고 곧바로 로고 화면
const DECOY_ENABLED = (process.env.TALKIE_DECOY || 'o').toString().toLowerCase() !== 'x';

// 비밀번호 우회 모드:
// TALKIE_PASSWORD가 정확히 "0000#"인 경우, 클라이언트는 비밀번호 입력창을
// 띄우지 않고 로고 클릭과 동시에 빈 비밀번호로 join을 시도한다.
const PASSWORD_BYPASS = (PASSWORD === '0000#');

function isFreqChannel(ch) {
  return typeof ch === 'string' &&
    (ch.indexOf(FREQ_CHANNEL_PREFIX) === 0 || ch.indexOf(SECRET_FREQ_CHANNEL_PREFIX) === 0);
}
const FREQ_ATTEMPT_LIMIT = Number(process.env.TALKIE_FREQ_ATTEMPT_LIMIT) || 20;
const FREQ_ATTEMPT_WINDOW_MS = Number(process.env.TALKIE_FREQ_ATTEMPT_WINDOW_MS) || 60 * 60 * 1000;
const FIXED_CHANNEL_IDS = ['CH01','CH02','CH03','CH04','CH05','CH06','CH07','CH08','CH09','CH10'];

let notices = {
  pw: { text: '', imageUrl: '', updatedAt: 0 },
  ch: { text: '', imageUrl: '', updatedAt: 0 },
};
const NOTICE_TARGETS = ['pw', 'ch'];

let serverLocked = false;
let countryBlockActive = false;
const COUNTRY_BLOCK_ALLOW = 'KR';

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

// ============================================================================
// 이벤트 로그 — 24시간 자동 만료
// ----------------------------------------------------------------------------
// eventLog는 서버 메모리에만 존재하는 링버퍼다(서버 재시작 시 소멸). 여기에
// 더해 24시간이 지난 항목은 자동으로 잘라내 개인정보(IP/지역/기기) 보존
// 기간을 제한한다. 로그는 push 순서대로 시간 오름차순이므로 앞에서부터
// 잘라내면 된다.
// ============================================================================
const eventLog = [];
const MAX_LOG_ENTRIES = 5000;
const LOG_MAX_AGE_MS = 24 * 60 * 60 * 1000;

function pruneEventLog(now){
  const cutoff = (now || Date.now()) - LOG_MAX_AGE_MS;
  let i = 0;
  while(i < eventLog.length && eventLog[i].ts < cutoff) i++;
  if(i > 0) eventLog.splice(0, i);
}
function logEvent(type, id, c, extra) {
  pruneEventLog();
  const entry = Object.assign({
    type, id, ts: Date.now(),
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
// 로그 이벤트가 한동안 없어도 만료된 항목이 계속 남아있지 않도록 주기 스윕.
setInterval(() => pruneEventLog(), 60 * 60 * 1000);

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

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  if (path === '/notice' && req.method === 'GET') {
    sendJson(res, 200, { pw: notices.pw, ch: notices.ch });
    return;
  }

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

  if (path === '/log' && req.method === 'GET') {
    let key = null;
    try { key = new URL(req.url, 'http://x').searchParams.get('key'); } catch (e) {}
    if (!ADMIN_KEY || key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
    pruneEventLog(); // 조회 시점에도 한 번 더 잘라내 최신 상태를 반영
    sendJson(res, 200, { log: eventLog });
    return;
  }

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
      setTimeout(() => { try { target.ws.close(); } catch (e) {} }, 150);
      sendJson(res, 200, { ok: true });
    });
    return;
  }

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

  if (path === '/auto-kick-list' && req.method === 'GET') {
    let key = null;
    try { key = new URL(req.url, 'http://x').searchParams.get('key'); } catch (e) {}
    if (!ADMIN_KEY || key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
    sendJson(res, 200, { rules: autoKickRules });
    return;
  }

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

  if (path === '/lock-status' && req.method === 'GET') {
    sendJson(res, 200, {
      locked: serverLocked,
      passwordBypass: PASSWORD_BYPASS,
      decoy: DECOY_ENABLED,
    });
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Talkie signaling server OK');
});

// ============================================================================
// WebSocket 서버 — maxPayload 상한
// ----------------------------------------------------------------------------
// 시그널링 서버는 SDP offer/answer(ICE candidates 포함)와 소량의 제어
// 메시지만 주고받으므로 정상 페이로드는 수 KB 수준이다. 256KB면 매우
// 넉넉한 상한이며, 악의적 클라이언트가 거대한 메시지로 서버 메모리를
// 소진시키는 것을 ws 라이브러리 수준에서 자동 차단한다
// (초과 시 1009 'Message too big'으로 소켓 종료).
// ============================================================================
const wss = new WebSocketServer({ server, maxPayload: 256 * 1024 });

let nextId = 1;
const clients = new Map();
const channelMeta = new Map();
const rawSockets = new Set();

function send(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch (e) {}
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || '';
}

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
  const fullChannels = {};
  const publicChannels = {};
  channelMeta.forEach((meta, ch) => {
    const entry = { desc: meta.desc, cap: meta.cap, count: channelMemberIds(ch).length };
    fullChannels[ch] = entry;
    if (!isFreqChannel(ch)) publicChannels[ch] = entry;
  });
  const fullMsg = JSON.stringify({ type: 'stats', total: clients.size, channels: fullChannels });
  const publicMsg = JSON.stringify({ type: 'stats', total: clients.size, channels: publicChannels });
  clients.forEach((c) => {
    try { c.ws.send(c.channel === OPERATOR_CHANNEL_ID ? fullMsg : publicMsg); } catch (e) {}
  });
}

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

function kickClient(id, c, reason) {
  c.wasKicked = true;
  logEvent('kick', id, c, reason ? { reason } : undefined);
  send(c.ws, { type: 'kicked' });
  setTimeout(() => { try { c.ws.close(); } catch (e) {} }, 150);
}

function checkFreqBruteForce(id, c) {
  const now = Date.now();
  c.freqAttempts.push(now);
  const cutoff = now - FREQ_ATTEMPT_WINDOW_MS;
  while (c.freqAttempts.length && c.freqAttempts[0] < cutoff) c.freqAttempts.shift();
  if (c.freqAttempts.length > FREQ_ATTEMPT_LIMIT) {
    kickClient(id, c, 'freq-bruteforce');
    return true;
  }
  return false;
}

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

function leaveChannel(id) {
  const c = clients.get(id);
  if (!c || !c.channel) return;
  const ch = c.channel;
  c.channel = null;
  broadcastToChannelExcept(ch, id, { type: 'peer-left', channel: ch, id });
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

  rawSockets.add(ws);
  send(ws, noticePayload());

  ws.on('message', (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch (e) { return; }

    if (!authed) {
      if (data.type !== 'join') return;

      // ALL KILL / 국경봉쇄 / AUTO KICK 판정은 비밀번호 검사보다 먼저
      if (serverLocked) {
        send(ws, { type: 'server-locked' });
        ws.close();
        return;
      }
      if (countryBlockActive && geo.country && geo.country !== '-' && geo.country !== COUNTRY_BLOCK_ALLOW) {
        send(ws, { type: 'server-locked' });
        ws.close();
        return;
      }
      if (isAutoKickBlocked({ country: geo.country, region: geo.region, ip, device })) {
        send(ws, { type: 'server-locked' });
        ws.close();
        return;
      }

      // ---- 시작 비밀번호 검증 ----
      // TALKIE_PASSWORD          → role 'user'
      // TALKIE_OPERATOR_PASSWORD → role 'operator'
      // TALKIE_PASSWORD === '0000#' 인 bypass 모드에서는 빈 비밀번호도 'user'로 인정.
      let role = null;
      if (PASSWORD_BYPASS && (!data.password || data.password === '')) {
        role = 'user';
      } else if (PASSWORD && data.password === PASSWORD) {
        role = 'user';
      } else if (OPERATOR_PASSWORD && data.password === OPERATOR_PASSWORD) {
        role = 'operator';
      }
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
        wasKicked: false, freqAttempts: [],
      });
      send(ws, { type: 'welcome', id: myId, role });
      logEvent('login', myId, clients.get(myId));
      broadcastStats();
      return;
    }

    const me = clients.get(myId);
    if (!me) return;

    if (data.type === 'operator-auth') {
      if (OPERATOR_PASSWORD && data.password === OPERATOR_PASSWORD) {
        me.role = 'operator';
        send(ws, { type: 'operator-auth-ok' });
      } else {
        send(ws, { type: 'operator-auth-error' });
      }
      return;
    }

    if (data.type === 'set-nickname' && typeof data.nickname === 'string') {
      me.nickname = data.nickname.slice(0, 20) || null;
      return;
    }

    if (data.type === 'enter-channel' && typeof data.channel === 'string' && data.channel) {
      const ch = data.channel;
      if (isFreqChannel(ch) && checkFreqBruteForce(myId, me)) return;
      if (ch === OPERATOR_CHANNEL_ID) {
        if (!CH10_PASSWORD || data.ch10Password !== CH10_PASSWORD) {
          send(ws, { type: 'channel-auth-error', channel: ch });
          return;
        }
      }
      if (me.channel === ch) {
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
      if (target && me.channel && target.channel === me.channel) {
        send(target.ws, { type: 'signal', from: myId, kind: data.kind, payload: data.payload });
      }
      return;
    }

    if (data.type === 'ping') {
      send(ws, { type: 'pong' });
      return;
    }
  });

  ws.on('close', () => {
    rawSockets.delete(ws);
    if (myId && clients.has(myId)) {
      const me = clients.get(myId);
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
  console.log('  TALKIE_DECOY      =', process.env.TALKIE_DECOY || '(unset → decoy ON)');
  console.log('  passwordBypass    =', PASSWORD_BYPASS, '(TALKIE_PASSWORD === "0000#")');
  console.log('  maxPayload        = 256KB');
  console.log('  log retention     = 24h');
});
// Talkie signaling server
// Implements exactly the protocol documented in the client:
//   C->S  {type:'join', password:<string>, jwt?:<string>}  -- 비회원: password / 회원: jwt
//   S->C  {type:'welcome', id, role, publicIp, ipHash, memberUserId}
//   S->C  {type:'auth-error'}
//   C->S  {type:'operator-auth', password:<string>}
//   S->C  {type:'operator-auth-ok'} | {type:'operator-auth-error'}
//   C->S  {type:'set-nickname', nickname:<string>}
//   C->S  {type:'enter-channel', channel:<id>, ch10Password?:<string>}
//   S->C  {type:'channel-welcome', channel, id, peers:[{id}, ...]}
//   S->C  {type:'channel-full', channel}
//   S->C  {type:'channel-auth-error', channel, reason?}
//   C->S  {type:'leave-channel'}
//   S->C  {type:'peer-joined', channel, id}
//   S->C  {type:'peer-left', channel, id}
//   C->S  {type:'signal', to:<peerId>, kind, payload}
//   S->C  {type:'signal', from:<peerId>, kind, payload}
//   C->S  {type:'set-channel-info', channel, desc, cap}
//   S->C  {type:'stats', total, channels:{...}}
//   S->C  {type:'kicked'}
//   S->C  {type:'server-locked'}
//
// 회원 로그인 (JWT)
// -----------------
// 클라이언트가 Supabase Auth로 로그인한 뒤 받은 access_token(JWT)을 join 시
// 함께 보내면, 서버가 SUPABASE_JWT_SECRET으로 서명을 검증한다. 통과하면
// role='user' + memberUserId(UUID)로 세션을 열고, welcome 메시지에 UUID를
// 실어 보낸다. JWT가 없거나 검증 실패면 기존 비밀번호 경로로 폴백하므로
// 비회원 흐름은 전혀 영향받지 않는다.

const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
let geoip = null;
try { geoip = require('geoip-lite'); } catch (e) { geoip = null; }

// ============================================================================
// 필수 환경변수 강제
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

// 회원 JWT 검증용. 없으면 회원 로그인만 비활성화되고 비회원 흐름은 정상.
const SUPABASE_JWT_SECRET = process.env.SUPABASE_JWT_SECRET || null;
const SUPABASE_URL = process.env.SUPABASE_URL || null;

let supabaseJwks = null;
let supabaseJwksFetchedAt = 0;
async function fetchSupabaseJwks(force){
  if(!SUPABASE_URL) return null;
  const now = Date.now();
  if(!force && supabaseJwks && (now - supabaseJwksFetchedAt < 3600000)) return supabaseJwks;
  try{
    const url = SUPABASE_URL.replace(/\/$/, '') + '/auth/v1/.well-known/jwks.json';
    const res = await fetch(url);
    if(!res.ok) return null;
    const data = await res.json();
    supabaseJwks = data;
    supabaseJwksFetchedAt = now;
    return data;
  }catch(e){
    return null;
  }
}

const OPERATOR_CHANNEL_ID = 'CH10';
const PORT = process.env.PORT || 10000;
const DEFAULT_CHANNEL_CAP = 10;
const MIN_FIXED_CHANNEL_CAP = 10;
const MIN_FREQ_CHANNEL_CAP = 2;
const MAX_CHANNEL_CAP = 15;
const FREQ_CHANNEL_PREFIX = 'FQ_';
const SECRET_FREQ_CHANNEL_PREFIX = 'SFQ_';

const DECOY_ENABLED = (process.env.TALKIE_DECOY || 'o').toString().toLowerCase() !== 'x';
const PASSWORD_BYPASS = (PASSWORD === '0000#');

// ============================================================================
// 채널 종류 판별 + LOCAL 유틸
// ============================================================================
function isFreqChannel(ch) {
  return typeof ch === 'string' &&
    (ch.indexOf(FREQ_CHANNEL_PREFIX) === 0 || ch.indexOf(SECRET_FREQ_CHANNEL_PREFIX) === 0);
}
function hashIp(ip){
  if(!ip) return '00000000';
  return crypto.createHash('sha256').update(String(ip)).digest('hex').slice(0, 8);
}
function parseLocalChannel(ch){
  if(typeof ch !== 'string' || ch.indexOf('LOCAL_') !== 0) return null;
  const rest = ch.slice(6);
  const m = rest.match(/^([0-9a-f]{8})(?:_([0-9]{6}))?$/);
  if(!m) return null;
  return { hash: m[1], pin: m[2] || null };
}
function isLocalChannel(ch){ return !!parseLocalChannel(ch); }

// ============================================================================
// Supabase JWT 검증 (HS256)
// ============================================================================
function base64UrlDecode(str){
  str = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while(str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}
async function verifySupabaseJWT(token){
  try{
    if(!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if(parts.length !== 3) return null;
    const headerB64 = parts[0], payloadB64 = parts[1], signatureB64 = parts[2];
    let header, payload;
    try{
      header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
      payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
    }catch(e){ return null; }
    if(payload.exp && (payload.exp * 1000) < Date.now()) return null;
    if(payload.aud !== 'authenticated') return null;
    if(!payload.sub) return null;
    const signatureInput = headerB64 + '.' + payloadB64;
    const signature = base64UrlDecode(signatureB64);
    if(header.alg === 'HS256'){
      if(!SUPABASE_JWT_SECRET) return null;
      const expected = crypto.createHmac('sha256', SUPABASE_JWT_SECRET).update(signatureInput).digest();
      if(expected.length !== signature.length) return null;
      if(!crypto.timingSafeEqual(expected, signature)) return null;
      return payload;
    }
    if(header.alg === 'ES256' || header.alg === 'RS256'){
      let jwks = await fetchSupabaseJwks(false);
      let keys = (jwks && jwks.keys) || [];
      let jwk = header.kid ? keys.find(k => k.kid === header.kid) : null;
      if(!jwk && keys.length === 1) jwk = keys[0];
      if(!jwk){
        jwks = await fetchSupabaseJwks(true);
        keys = (jwks && jwks.keys) || [];
        jwk = header.kid ? keys.find(k => k.kid === header.kid) : null;
        if(!jwk && keys.length === 1) jwk = keys[0];
      }
      if(!jwk) return null;
      const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      const data = Buffer.from(signatureInput, 'utf8');
      let ok = false;
      if(header.alg === 'ES256'){
        ok = crypto.verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
      } else {
        ok = crypto.verify('sha256', data, publicKey, signature);
      }
      if(!ok) return null;
      return payload;
    }
    return null;
  }catch(e){
    return null;
  }
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
        isMember: !!c.memberUserId,
      });
    });
    sendJson(res, 200, { total: clients.size, channels: channelsOut, clients: clientsOut, locked: serverLocked, countryBlocked: countryBlockActive });
    return;
  }

  if (path === '/log' && req.method === 'GET') {
    let key = null;
    try { key = new URL(req.url, 'http://x').searchParams.get('key'); } catch (e) {}
    if (!ADMIN_KEY || key !== ADMIN_KEY) { sendJson(res, 401, { error: 'unauthorized' }); return; }
    pruneEventLog();
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
// WebSocket 서버 — maxPayload 상한 (256KB)
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
    if (!isFreqChannel(ch) && !isLocalChannel(ch)) publicChannels[ch] = entry;
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
  if ((isFreqChannel(ch) || isLocalChannel(ch)) && channelMemberIds(ch).length === 0) {
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

  ws.on('message', async (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch (e) { return; }

    if (!authed) {
      if (data.type !== 'join') return;

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

      let role = null;
      let memberUserId = null; // 회원이면 Supabase user UUID, 비회원이면 null

      // 1) 회원 경로: JWT가 있으면 서명 검증
      if (data.jwt) {
        const payload = await verifySupabaseJWT(data.jwt);
        if (payload) {
          role = 'user';
          memberUserId = payload.sub;
        }
      }

      // 2) 비회원 경로: JWT 없거나 검증 실패 시 기존 비밀번호 검증으로 폴백
      if (!role) {
        if (PASSWORD_BYPASS && (!data.password || data.password === '')) {
          role = 'user';
        } else if (PASSWORD && data.password === PASSWORD) {
          role = 'user';
        } else if (OPERATOR_PASSWORD && data.password === OPERATOR_PASSWORD) {
          role = 'operator';
        }
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
        memberUserId,
      });
      send(ws, {
        type: 'welcome',
        id: myId,
        role,
        publicIp: ip,
        ipHash: hashIp(ip),
        memberUserId,
      });
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

      const localInfo = parseLocalChannel(ch);
      if (localInfo) {
        if (hashIp(me.ip) !== localInfo.hash) {
          send(ws, { type: 'channel-auth-error', channel: ch, reason: 'not-same-network' });
          return;
        }
      }

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
      if (!localInfo && existing.length >= meta.cap) {
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
      if (isLocalChannel(data.channel)) return;
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
  console.log('  LOCAL channels    = enabled (hash-based, IP-scoped)');
  console.log('  member JWT auth   =', SUPABASE_JWT_SECRET ? 'enabled' : 'disabled (no SUPABASE_JWT_SECRET)');
  console.log(' SUPABASE_URL =', SUPABASE_URL || '(unset → JWKS 검증 불가)');
});
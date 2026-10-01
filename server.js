'use strict';
// 수다방 서버: 외부 패키지 없이 Node.js(18 이상)만으로 동작합니다.
// 실행: node server.js   →  http://localhost:3000
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;           // 대화 저장 폴더
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const ACCESS_CODE = process.env.ACCESS_CODE || '';             // 비우면 링크를 아는 누구나 입장
const ADMIN_KEY = process.env.ADMIN_KEY || '';                 // 전체 삭제용 관리자 키
const MAX_MESSAGES = 1000;
const MAX_IMG = 300000;                                        // 사진 1장 최대 글자 수(약 220KB)
const MAX_BODY = 450000;
const MAX_USERS = 300;

let db = { users: {}, messages: [] };
try {
  db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  db.users = db.users || {};
  db.messages = db.messages || [];
} catch (e) { /* 처음 실행이면 파일이 없어요 */ }

const bySecret = new Map(Object.values(db.users).map((u) => [u.secret, u.id]));
const conns = new Map(); // userId -> Set(res)  (실시간 연결)
const recent = new Map(); // userId -> [timestamps]  (도배 방지)

/* ---------- 저장 ---------- */
let saveTimer = null;
function writeNow() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DATA_FILE);
  } catch (e) { console.error('저장 실패:', e.message); }
}
function save() { clearTimeout(saveTimer); saveTimer = setTimeout(writeNow, 300); }
function flushAndExit() { clearTimeout(saveTimer); writeNow(); process.exit(0); }
process.on('SIGTERM', flushAndExit);
process.on('SIGINT', flushAndExit);

/* ---------- 도우미 ---------- */
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('too_big'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch (e) { reject(Object.assign(new Error('bad_json'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
function userBySecret(secret) {
  const id = typeof secret === 'string' ? bySecret.get(secret) : null;
  return id ? db.users[id] : null;
}
function cleanName(s) {
  return String(s || '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 20);
}
function visible(m, uid) { return m.to === 'all' || m.uid === uid || m.to === uid; }
function publicUsers() {
  return Object.values(db.users).map((u) => ({ id: u.id, name: u.name, online: !!(conns.get(u.id) && conns.get(u.id).size) }));
}
function pushEvent(res, event, data) { res.write('event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n'); }
function emit(event, data, pred) {
  for (const [uid, set] of conns) {
    if (pred && !pred(uid)) continue;
    for (const res of set) pushEvent(res, event, data);
  }
}
function same(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function tooFast(uid) {
  const now = Date.now();
  const list = (recent.get(uid) || []).filter((t) => now - t < 10000);
  list.push(now); recent.set(uid, list);
  return list.length > 20;
}

/* ---------- API ---------- */
const IMG_RE = /^data:image\/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$/;

async function handleApi(req, res, pathname, url) {
  if (req.method === 'GET' && pathname === '/api/config') {
    return sendJson(res, 200, { needsCode: !!ACCESS_CODE });
  }
  if (req.method === 'GET' && pathname === '/api/state') {
    const u = userBySecret(url.searchParams.get('secret'));
    if (!u) return sendJson(res, 401, { error: 'unauthorized' });
    const messages = db.messages.filter((m) => visible(m, u.id)).slice(-400);
    return sendJson(res, 200, { me: { id: u.id, name: u.name }, users: publicUsers(), messages });
  }
  if (req.method !== 'POST') return sendJson(res, 404, { error: 'not_found' });

  const body = await readJson(req);

  if (pathname === '/api/join') {
    if (ACCESS_CODE && !same(body.code || '', ACCESS_CODE)) return sendJson(res, 403, { error: 'code' });
    const name = cleanName(body.name);
    if (!name) return sendJson(res, 400, { error: 'name' });
    if (Object.keys(db.users).length >= MAX_USERS) return sendJson(res, 403, { error: 'full' });
    const user = {
      id: 'u_' + crypto.randomBytes(6).toString('hex'),
      name,
      secret: crypto.randomBytes(24).toString('base64url'),
      joinedAt: Date.now(),
    };
    db.users[user.id] = user; bySecret.set(user.secret, user.id); save();
    emit('users', publicUsers());
    return sendJson(res, 200, { id: user.id, name: user.name, secret: user.secret });
  }

  const u = userBySecret(body.secret);
  if (!u) return sendJson(res, 401, { error: 'unauthorized' });

  if (pathname === '/api/send') {
    if (tooFast(u.id)) return sendJson(res, 429, { error: 'slow_down' });
    const to = body.to === 'all' ? 'all' : (db.users[body.to] && body.to !== u.id ? body.to : null);
    if (!to) return sendJson(res, 400, { error: 'to' });
    const text = typeof body.text === 'string' ? body.text.trim().slice(0, 1000) : '';
    const m = { id: crypto.randomUUID(), uid: u.id, to, text, ts: Date.now() };
    if (typeof body.img === 'string' && body.img) {
      if (body.img.length > MAX_IMG || !IMG_RE.test(body.img)) return sendJson(res, 400, { error: 'img' });
      m.img = body.img;
      const w = Math.round(Number(body.w)), h = Math.round(Number(body.h));
      if (w >= 1 && w <= 4000 && h >= 1 && h <= 4000) { m.w = w; m.h = h; }
    }
    if (!m.text && !m.img) return sendJson(res, 400, { error: 'empty' });
    db.messages.push(m);
    if (db.messages.length > MAX_MESSAGES) db.messages.splice(0, db.messages.length - MAX_MESSAGES);
    save();
    emit('msg', m, (uid) => visible(m, uid));
    return sendJson(res, 200, { message: m });
  }

  if (pathname === '/api/delete') {
    const i = db.messages.findIndex((m) => m.id === body.id && m.uid === u.id);
    if (i < 0) return sendJson(res, 404, { error: 'not_found' });
    const [m] = db.messages.splice(i, 1); save();
    emit('del', { ids: [m.id] }, (uid) => visible(m, uid));
    return sendJson(res, 200, { ok: true });
  }

  if (pathname === '/api/clear-mine') {
    const to = body.to;
    const gone = db.messages.filter((m) => m.uid === u.id && (to === 'all' ? m.to === 'all' : m.to === to));
    if (!gone.length) return sendJson(res, 200, { ids: [] });
    const set = new Set(gone.map((m) => m.id));
    db.messages = db.messages.filter((m) => !set.has(m.id)); save();
    emit('del', { ids: [...set] }, (uid) => uid === u.id || to === 'all' || uid === to);
    return sendJson(res, 200, { ids: [...set] });
  }

  return sendJson(res, 404, { error: 'not_found' });
}

async function handleAdmin(req, res) {
  const body = await readJson(req);
  if (!ADMIN_KEY || !same(body.key || '', ADMIN_KEY)) return sendJson(res, 403, { error: 'forbidden' });
  db.messages = []; save();
  emit('reset', {});
  sendJson(res, 200, { ok: true });
}

/* ---------- 실시간(SSE) ---------- */
function handleEvents(req, res, url) {
  const u = userBySecret(url.searchParams.get('secret'));
  if (!u) return sendJson(res, 401, { error: 'unauthorized' });
  req.socket.setTimeout(0);
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 3000\n\n');
  const set = conns.get(u.id) || new Set();
  conns.set(u.id, set); set.add(res);
  pushEvent(res, 'users', publicUsers());
  if (set.size === 1) emit('users', publicUsers());
  const beat = setInterval(() => res.write(': ping\n\n'), 20000);
  req.on('close', () => {
    clearInterval(beat); set.delete(res);
    if (!set.size) { conns.delete(u.id); emit('users', publicUsers()); }
  });
}

/* ---------- 서버 ---------- */
const INDEX = path.join(__dirname, 'public', 'index.html');
const HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
};

const server = http.createServer(async (req, res) => {
  for (const k of Object.keys(HEADERS)) res.setHeader(k, HEADERS[k]);
  try {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    if (p === '/healthz') return sendJson(res, 200, { ok: true });
    if (p === '/events' && req.method === 'GET') return handleEvents(req, res, url);
    if (p === '/api/admin/clear' && req.method === 'POST') return await handleAdmin(req, res);
    if (p.startsWith('/api/')) return await handleApi(req, res, p, url);
    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(fs.readFileSync(INDEX));
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('찾을 수 없어요');
  } catch (e) {
    if (!res.headersSent) sendJson(res, e.status || 500, { error: e.message || 'server_error' });
    else res.end();
  }
});

server.listen(PORT, () => {
  console.log('수다방이 열렸어요: http://localhost:' + PORT);
  if (ACCESS_CODE) console.log('초대 코드가 설정되어 있어요.');
  if (!ADMIN_KEY) console.log('ADMIN_KEY가 없어서 "전체 삭제"는 꺼져 있어요.');
});

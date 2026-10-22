'use strict';
/*
 * ScreenFlow — نظام إدارة شاشات الإعلانات عن بُعد
 * يعمل بـ Node.js فقط (الإصدار 18 أو أحدث) بدون أي مكتبات خارجية.
 * التشغيل:  node server.js
 */
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const store = require('./db');
const { createWSServer, OPEN } = require('./lib/websocket');

const PORT = Number(process.env.PORT || 3000);
const ALLOW_REGISTER = process.env.ALLOW_REGISTER !== 'false';
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 500);
const PAIR_CODE_TTL = 10 * 60 * 1000; // صلاحية رمز الربط: 10 دقائق
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = store.data;
const newId = () => crypto.randomBytes(8).toString('hex');
const newToken = () => crypto.randomBytes(24).toString('hex');

/* ====================== كلمات المرور ====================== */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return 'scrypt$' + salt + '$' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPassword(pw, stored) {
  const [, salt, hash] = String(stored).split('$');
  if (!salt || !hash) return false;
  const a = crypto.scryptSync(pw, salt, 64), b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ====================== أدوات HTTP ====================== */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.webp': 'image/webp', '.gif': 'image/gif', '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime'
};
const UPLOAD_TYPES = {
  'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif',
  'video/mp4': '.mp4', 'video/webm': '.webm', 'video/quicktime': '.mov'
};

function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store' });
  res.end(body);
}
const fail = (res, status, error) => json(res, status, { error });

function readJSON(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > 1024 * 1024) { reject(new Error('الطلب كبير جدًا')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new Error('بيانات غير صالحة')); }
    });
    req.on('error', reject);
  });
}

// إرسال ملف مع دعم Range (ضروري لتشغيل الفيديو على التلفزيون)
function serveFile(req, res, file, cacheControl) {
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return fail(res, 404, 'غير موجود');
    const headers = {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Accept-Ranges': 'bytes', 'Cache-Control': cacheControl, 'Last-Modified': st.mtime.toUTCString()
    };
    const range = req.headers.range;
    let start = 0, end = st.size - 1, status = 200;
    if (range) {
      const m = /bytes=(\d*)-(\d*)/.exec(range);
      if (m) {
        if (m[1] === '' && m[2] !== '') { start = Math.max(0, st.size - Number(m[2])); }
        else {
          start = Number(m[1] || 0);
          if (m[2] !== '') end = Math.min(Number(m[2]), st.size - 1);
        }
        if (start > end || start >= st.size) {
          res.writeHead(416, { 'Content-Range': `bytes */${st.size}` });
          return res.end();
        }
        status = 206;
        headers['Content-Range'] = `bytes ${start}-${end}/${st.size}`;
      }
    }
    headers['Content-Length'] = end - start + 1;
    res.writeHead(status, headers);
    if (req.method === 'HEAD' || st.size === 0) return res.end();
    const stream = fs.createReadStream(file, { start, end });
    stream.on('error', () => res.destroy());
    res.on('close', () => stream.destroy());
    stream.pipe(res);
  });
}

function serveStatic(req, res, baseDir, relPath, cacheControl) {
  let rel;
  try { rel = decodeURIComponent(relPath); } catch (e) { return fail(res, 400, 'رابط غير صالح'); }
  const full = path.resolve(baseDir, '.' + path.sep + rel);
  if (full !== baseDir && !full.startsWith(baseDir + path.sep)) return fail(res, 403, 'ممنوع');
  if (rel === '' || rel.endsWith('/')) return serveFile(req, res, path.join(full, 'index.html'), 'no-cache');
  serveFile(req, res, full, cacheControl);
}

/* ====================== المصادقة ====================== */
function getUser(req) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  const s = t && db.sessions.find(x => x.token === t);
  const user = s && db.users.find(u => u.id === s.userId);
  if (user) req.sessionToken = t;
  return user || null;
}

// حماية بسيطة من تخمين كلمة المرور
const loginFails = new Map();
function tooManyAttempts(ip) {
  const r = loginFails.get(ip);
  return r && r.count >= 10 && Date.now() - r.first < 15 * 60 * 1000;
}
function noteFail(ip) {
  const r = loginFails.get(ip);
  if (!r || Date.now() - r.first > 15 * 60 * 1000) loginFails.set(ip, { count: 1, first: Date.now() });
  else r.count++;
}

/* ====================== عرض البيانات ====================== */
function mediaView(m) {
  if (!m) return null;
  return { id: m.id, name: m.name, type: m.type, mime: m.mime, size: m.size, url: '/media/' + m.file, createdAt: m.createdAt };
}

function screenView(s) {
  return {
    id: s.id, name: s.name, settings: s.settings,
    online: isOnline(s.id), lastSeen: s.lastSeen, nowPlaying: s.nowPlaying || null, createdAt: s.createdAt,
    playlist: s.playlist
      .map(it => ({ ...it, media: mediaView(db.media.find(m => m.id === it.mediaId)) }))
      .filter(it => it.media)
  };
}

function tvPayload(s) {
  const items = s.playlist.map(it => {
    const m = db.media.find(x => x.id === it.mediaId);
    if (!m) return null;
    return {
      id: it.id, type: m.type, url: '/media/' + m.file, name: m.name, duration: it.duration || 10,
      startAt: it.startAt || null, endAt: it.endAt || null,
      days: it.days || null, timeFrom: it.timeFrom || null, timeTo: it.timeTo || null
    };
  }).filter(Boolean);
  return { type: 'playlist', name: s.name, settings: s.settings, items, version: s.version, serverTime: Date.now() };
}

const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
function cleanItem(raw, userId) {
  const m = db.media.find(x => x.id === raw.mediaId && x.userId === userId);
  if (!m) return null;
  const num = v => (v === null || v === undefined || v === '' ? null : Number(v));
  const startAt = num(raw.startAt), endAt = num(raw.endAt);
  let duration = parseInt(raw.duration, 10);
  if (!Number.isFinite(duration) || duration < 1) duration = 10;
  duration = Math.min(duration, 3600);
  let days = Array.isArray(raw.days) ? [...new Set(raw.days.map(Number).filter(d => Number.isInteger(d) && d >= 0 && d <= 6))] : null;
  if (days && (days.length === 0 || days.length === 7)) days = null;
  return {
    id: typeof raw.id === 'string' && /^[a-f0-9]{1,32}$/.test(raw.id) ? raw.id : newId(),
    mediaId: m.id, duration,
    startAt: Number.isFinite(startAt) ? startAt : null,
    endAt: Number.isFinite(endAt) ? endAt : null,
    days,
    timeFrom: TIME_RE.test(raw.timeFrom || '') ? raw.timeFrom : null,
    timeTo: TIME_RE.test(raw.timeTo || '') ? raw.timeTo : null
  };
}

function updatePlaylist(s, items) {
  s.playlist = items;
  s.version = (s.version || 0) + 1;
  store.save();
  pushPlaylist(s);
}

function ownedScreen(user, id) { return db.screens.find(x => x.id === id && x.userId === user.id); }

/* ====================== واجهة API ====================== */
const routes = [];
const route = (method, pattern, auth, handler) => routes.push({ method, pattern, auth, handler });

route('GET', /^\/api\/health$/, false, (req, res) => json(res, 200, { ok: true, time: Date.now() }));

route('POST', /^\/api\/auth\/register$/, false, async (req, res) => {
  if (!ALLOW_REGISTER && db.users.length > 0) return fail(res, 403, 'التسجيل مغلق');
  const b = await readJSON(req);
  const email = String(b.email || '').trim().toLowerCase();
  const name = String(b.name || '').trim().slice(0, 60);
  const password = String(b.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email)) return fail(res, 400, 'البريد الإلكتروني غير صحيح');
  if (password.length < 6) return fail(res, 400, 'كلمة المرور يجب أن تكون 6 أحرف على الأقل');
  if (db.users.some(u => u.email === email)) return fail(res, 409, 'هذا البريد مسجل مسبقًا');
  const user = { id: newId(), email, name: name || email.split('@')[0], hash: hashPassword(password), createdAt: Date.now() };
  db.users.push(user);
  const token = newToken();
  db.sessions.push({ token, userId: user.id, createdAt: Date.now() });
  store.save();
  json(res, 200, { token, user: { id: user.id, name: user.name, email: user.email } });
});

route('POST', /^\/api\/auth\/login$/, false, async (req, res) => {
  const ip = req.socket.remoteAddress;
  if (tooManyAttempts(ip)) return fail(res, 429, 'محاولات كثيرة، حاول بعد 15 دقيقة');
  const b = await readJSON(req);
  const email = String(b.email || '').trim().toLowerCase();
  const user = db.users.find(u => u.email === email);
  if (!user || !checkPassword(String(b.password || ''), user.hash)) {
    noteFail(ip);
    return fail(res, 401, 'البريد أو كلمة المرور غير صحيحة');
  }
  loginFails.delete(ip);
  const token = newToken();
  db.sessions.push({ token, userId: user.id, createdAt: Date.now() });
  store.save();
  json(res, 200, { token, user: { id: user.id, name: user.name, email: user.email } });
});

route('POST', /^\/api\/auth\/logout$/, true, (req, res) => {
  const i = db.sessions.findIndex(s => s.token === req.sessionToken);
  if (i >= 0) db.sessions.splice(i, 1);
  store.save();
  json(res, 200, { ok: true });
});

route('GET', /^\/api\/me$/, true, (req, res) => {
  json(res, 200, { id: req.user.id, name: req.user.name, email: req.user.email });
});

// ----- الشاشات -----
route('GET', /^\/api\/screens$/, true, (req, res) => {
  json(res, 200, db.screens.filter(s => s.userId === req.user.id).map(screenView));
});

route('POST', /^\/api\/screens\/pair$/, true, async (req, res) => {
  const b = await readJSON(req);
  const code = String(b.code || '').replace(/\D/g, '');
  const name = String(b.name || '').trim().slice(0, 60) || 'شاشة جديدة';
  const p = pending.get(code);
  if (!p || p.expires < Date.now() || p.ws.readyState !== OPEN) return fail(res, 404, 'رمز الربط غير صحيح أو انتهت صلاحيته');
  pending.delete(code);
  p.ws.pairCode = null;
  const s = {
    id: newId(), userId: req.user.id, name, token: newToken(), playlist: [],
    settings: { fit: 'contain', rotate: 0, muted: true },
    version: 1, createdAt: Date.now(), lastSeen: Date.now(), nowPlaying: null
  };
  db.screens.push(s);
  store.save();
  send(p.ws, { type: 'paired', token: s.token });
  attach(p.ws, s);
  json(res, 200, screenView(s));
});

route('PATCH', /^\/api\/screens\/([a-f0-9]+)$/, true, async (req, res, id) => {
  const s = ownedScreen(req.user, id); if (!s) return fail(res, 404, 'الشاشة غير موجودة');
  const b = await readJSON(req);
  if (typeof b.name === 'string' && b.name.trim()) s.name = b.name.trim().slice(0, 60);
  const st = b.settings || {};
  if (['contain', 'cover', 'fill'].includes(st.fit)) s.settings.fit = st.fit;
  if ([0, 90, 180, 270].includes(Number(st.rotate))) s.settings.rotate = Number(st.rotate);
  if (typeof st.muted === 'boolean') s.settings.muted = st.muted;
  s.version = (s.version || 0) + 1;
  store.save();
  pushPlaylist(s);
  json(res, 200, screenView(s));
});

route('DELETE', /^\/api\/screens\/([a-f0-9]+)$/, true, (req, res, id) => {
  const s = ownedScreen(req.user, id); if (!s) return fail(res, 404, 'الشاشة غير موجودة');
  pushToScreen(s.id, { type: 'unpaired' });
  const set = conns.get(s.id);
  if (set) { set.forEach(ws => { ws.screenId = null; }); conns.delete(s.id); }
  db.screens.splice(db.screens.indexOf(s), 1);
  store.save();
  json(res, 200, { ok: true });
});

route('PUT', /^\/api\/screens\/([a-f0-9]+)\/playlist$/, true, async (req, res, id) => {
  const s = ownedScreen(req.user, id); if (!s) return fail(res, 404, 'الشاشة غير موجودة');
  const b = await readJSON(req);
  const raw = Array.isArray(b.items) ? b.items.slice(0, 200) : [];
  updatePlaylist(s, raw.map(r => cleanItem(r || {}, req.user.id)).filter(Boolean));
  json(res, 200, screenView(s));
});

route('POST', /^\/api\/screens\/([a-f0-9]+)\/command$/, true, async (req, res, id) => {
  const s = ownedScreen(req.user, id); if (!s) return fail(res, 404, 'الشاشة غير موجودة');
  const b = await readJSON(req);
  if (!['reload', 'identify'].includes(b.command)) return fail(res, 400, 'أمر غير معروف');
  pushToScreen(s.id, { type: 'command', command: b.command, name: s.name });
  json(res, 200, { ok: true, delivered: isOnline(s.id) });
});

// نشر سريع: إعلان واحد على عدة شاشات
route('POST', /^\/api\/publish$/, true, async (req, res) => {
  const b = await readJSON(req);
  const media = db.media.find(m => m.id === b.mediaId && m.userId === req.user.id);
  if (!media) return fail(res, 404, 'الإعلان غير موجود');
  const ids = Array.isArray(b.screenIds) ? b.screenIds : [];
  const screens = db.screens.filter(s => s.userId === req.user.id && ids.includes(s.id));
  if (!screens.length) return fail(res, 400, 'اختر شاشة واحدة على الأقل');
  const mode = b.mode === 'append' ? 'append' : 'replace';
  for (const s of screens) {
    const item = cleanItem({ mediaId: media.id, duration: b.duration }, req.user.id);
    updatePlaylist(s, mode === 'replace' ? [item] : [...s.playlist, item]);
  }
  json(res, 200, { ok: true, screens: screens.map(screenView) });
});

// ----- الإعلانات -----
route('GET', /^\/api\/media$/, true, (req, res) => {
  json(res, 200, db.media.filter(m => m.userId === req.user.id).sort((a, b) => b.createdAt - a.createdAt).map(mediaView));
});

// الرفع: الملف يُرسل كجسم الطلب مباشرة (يُكتب على القرص تدريجيًا بدون تحميله في الذاكرة)
route('POST', /^\/api\/media$/, true, (req, res) => {
  const mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  const ext = UPLOAD_TYPES[mime];
  if (!ext) { req.resume(); return fail(res, 400, 'نوع الملف غير مدعوم. المسموح: صور JPG/PNG/WEBP/GIF وفيديو MP4/WEBM/MOV'); }
  const max = MAX_UPLOAD_MB * 1024 * 1024;
  const declared = Number(req.headers['content-length'] || 0);
  if (declared > max) { req.resume(); return fail(res, 413, `حجم الملف أكبر من ${MAX_UPLOAD_MB} ميجابايت`); }
  let name = 'إعلان' + ext;
  try { name = decodeURIComponent(String(req.headers['x-file-name'] || '')) || name; } catch (e) {}
  name = name.replace(/[\u0000-\u001f]/g, '').slice(0, 120);

  const file = newId() + newId() + ext;
  const full = path.join(UPLOAD_DIR, file);
  const out = fs.createWriteStream(full);
  let size = 0, aborted = false;
  const abort = (status, msg) => {
    if (aborted) return; aborted = true;
    out.destroy(); fs.unlink(full, () => {});
    if (status && !res.headersSent) fail(res, status, msg);
  };
  req.on('data', c => { size += c.length; if (size > max) { abort(413, `حجم الملف أكبر من ${MAX_UPLOAD_MB} ميجابايت`); req.destroy(); } });
  req.on('aborted', () => abort());
  req.on('error', () => abort());
  out.on('error', () => abort(500, 'تعذر حفظ الملف'));
  out.on('finish', () => {
    if (aborted) return;
    if (!size) { fs.unlink(full, () => {}); return fail(res, 400, 'الملف فارغ'); }
    const m = {
      id: newId(), userId: req.user.id, name, file,
      type: mime.startsWith('video/') ? 'video' : 'image', mime, size, createdAt: Date.now()
    };
    db.media.push(m);
    store.save();
    json(res, 200, mediaView(m));
  });
  req.pipe(out);
});

route('DELETE', /^\/api\/media\/([a-f0-9]+)$/, true, (req, res, id) => {
  const m = db.media.find(x => x.id === id && x.userId === req.user.id);
  if (!m) return fail(res, 404, 'الإعلان غير موجود');
  db.media.splice(db.media.indexOf(m), 1);
  fs.unlink(path.join(UPLOAD_DIR, m.file), () => {});
  for (const s of db.screens.filter(x => x.userId === req.user.id)) {
    if (s.playlist.some(it => it.mediaId === m.id)) updatePlaylist(s, s.playlist.filter(it => it.mediaId !== m.id));
  }
  store.save();
  json(res, 200, { ok: true });
});

/* ====================== الخادم ====================== */
const server = http.createServer(async (req, res) => {
  const url = (req.url || '/').split('?')[0];
  res.setHeader('X-Content-Type-Options', 'nosniff');

  try {
    if (url.startsWith('/api/')) {
      for (const r of routes) {
        if (r.method !== req.method) continue;
        const m = r.pattern.exec(url);
        if (!m) continue;
        if (r.auth) {
          req.user = getUser(req);
          if (!req.user) { req.resume(); return fail(res, 401, 'يجب تسجيل الدخول'); }
        }
        return await r.handler(req, res, ...m.slice(1));
      }
      return fail(res, 404, 'غير موجود');
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') return fail(res, 405, 'غير مسموح');
    if (url === '/') { res.writeHead(302, { Location: '/admin/' }); return res.end(); }
    if (url === '/admin' || url === '/tv') { res.writeHead(301, { Location: url + '/' }); return res.end(); }
    if (url.startsWith('/media/')) return serveStatic(req, res, UPLOAD_DIR, url.slice(7), 'public, max-age=2592000, immutable');
    if (url.startsWith('/admin/') || url.startsWith('/tv/')) return serveStatic(req, res, PUBLIC_DIR, url.slice(1), 'no-cache');
    fail(res, 404, 'غير موجود');
  } catch (err) {
    console.error(err);
    if (!res.headersSent) fail(res, 400, err.message || 'خطأ');
  }
});

/* ====================== WebSocket: اتصال الشاشات ====================== */
const conns = new Map();   // screenId -> Set<ws>
const pending = new Map(); // رمز الربط -> { ws, expires }

function send(ws, obj) { if (ws.readyState === OPEN) ws.send(JSON.stringify(obj)); }
function isOnline(id) { const set = conns.get(id); return !!(set && set.size); }
function pushToScreen(id, obj) { const set = conns.get(id); if (set) set.forEach(ws => send(ws, obj)); }
function pushPlaylist(s) { pushToScreen(s.id, tvPayload(s)); }

function attach(ws, s) {
  detach(ws);
  ws.screenId = s.id;
  if (!conns.has(s.id)) conns.set(s.id, new Set());
  conns.get(s.id).add(ws);
  s.lastSeen = Date.now();
  store.save();
  send(ws, tvPayload(s));
}
function detach(ws) {
  if (!ws.screenId) return;
  const set = conns.get(ws.screenId);
  if (set) { set.delete(ws); if (!set.size) conns.delete(ws.screenId); }
  const s = db.screens.find(x => x.id === ws.screenId);
  if (s) { s.lastSeen = Date.now(); store.save(); }
  ws.screenId = null;
}

function issueCode(ws) {
  if (ws.pairCode) pending.delete(ws.pairCode);
  let code;
  do { code = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); } while (pending.has(code));
  pending.set(code, { ws, expires: Date.now() + PAIR_CODE_TTL });
  ws.pairCode = code;
  send(ws, { type: 'pair-code', code, expiresIn: PAIR_CODE_TTL / 1000 });
}

const wss = createWSServer(server, '/ws', ws => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('message', raw => {
    ws.isAlive = true;
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }
    switch (msg.type) {
      case 'auth': {
        const s = db.screens.find(x => x.token === msg.token);
        if (!s) return send(ws, { type: 'unpaired' });
        attach(ws, s);
        break;
      }
      case 'pair-request':
        if (!ws.screenId) issueCode(ws);
        break;
      case 'ping':
        send(ws, { type: 'pong', serverTime: Date.now() });
        break;
      case 'status': {
        const s = ws.screenId && db.screens.find(x => x.id === ws.screenId);
        if (s) {
          s.nowPlaying = msg.nowPlaying ? String(msg.nowPlaying).slice(0, 200) : null;
          s.lastSeen = Date.now();
          store.save();
        }
        break;
      }
    }
  });
  ws.on('close', () => {
    detach(ws);
    const p = ws.pairCode && pending.get(ws.pairCode);
    if (p && p.ws === ws) pending.delete(ws.pairCode);
  });
});

// فحص دوري: فصل الاتصالات الميتة وحذف الرموز المنتهية
setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
  const now = Date.now();
  for (const [code, p] of pending) if (p.expires < now) pending.delete(code);
}, 30000);

server.requestTimeout = 0; // السماح برفع فيديوهات كبيرة على اتصال بطيء
server.listen(PORT, () => {
  console.log(`\n  ScreenFlow يعمل على المنفذ ${PORT}`);
  console.log(`  لوحة التحكم (الجوال):   http://localhost:${PORT}/admin/`);
  console.log(`  مشغّل الشاشة (التلفزيون): http://localhost:${PORT}/tv/\n`);
});

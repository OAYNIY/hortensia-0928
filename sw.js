/* 解密层：页面请求 assets/* 时，这里取对应密文、解密后返回（密文本身不落地） */
const SCOPE = new URL(self.registration.scope).pathname;   // 形如 /hortensia-0928/
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
  '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ttf': 'font/ttf', '.otf': 'font/otf',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.mp4': 'video/mp4', '.webm': 'video/webm',
  '.txt': 'text/plain; charset=utf-8',
};
const ext = (p) => { const i = p.lastIndexOf('.'); return i < 0 ? '' : p.slice(i).toLowerCase(); };

let KEY = null, MAP = null;
const MEM = new Map();          // 已解密的资源缓存在内存里，避免反复解密（关掉标签页即释放）

function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('gate', 1);
    r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains('k')) r.result.createObjectStore('k'); };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function idbGet() {
  try {
    const db = await idb();
    return await new Promise((res) => {
      const q = db.transaction('k').objectStore('k').get('k');
      q.onsuccess = () => res(q.result); q.onerror = () => res(null);
    });
  } catch (e) { return null; }
}
async function idbPut(v) { try { const db = await idb(); db.transaction('k', 'readwrite').objectStore('k').put(v, 'k'); } catch (e) {} }

async function ensure() {
  if (KEY && MAP) return true;
  const st = await idbGet();
  if (st && st.raw && st.map) {
    KEY = await crypto.subtle.importKey('raw', st.raw, { name: 'AES-GCM' }, false, ['decrypt']);
    MAP = st.map;
    return true;
  }
  return false;
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('message', (e) => {
  const d = e.data || {};
  if (d.type === 'unlock') {
    e.waitUntil((async () => {
      KEY = await crypto.subtle.importKey('raw', d.raw, { name: 'AES-GCM' }, false, ['decrypt']);
      MAP = d.map;
      MEM.clear();
      await idbPut({ raw: d.raw, map: d.map });
      if (e.ports && e.ports[0]) e.ports[0].postMessage('ok');
    })());
  }
  if (d.type === 'lock') { KEY = null; MAP = null; e.waitUntil(idbPut({})); }
});

async function serveEnc(encRel, mime) {
  const r = await fetch(new URL(encRel, self.registration.scope).href, { cache: 'no-store' });
  if (!r.ok) return new Response('missing ' + encRel, { status: 404 });
  const buf = await r.arrayBuffer();
  const iv = buf.slice(0, 12);
  const data = buf.slice(12);
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, KEY, data);
    return { buf: plain, mime: mime };
  } catch (err) {
    return null;
  }
}

async function respondWith(rel, encRel, mime) {
  const hit = MEM.get(rel);
  if (hit) return new Response(hit, { headers: { 'Content-Type': mime } });
  const got = await serveEnc(encRel, mime);
  if (!got) return new Response('decrypt failed', { status: 500 });
  MEM.set(rel, got.buf);
  return new Response(got.buf, { headers: { 'Content-Type': mime } });
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.indexOf(SCOPE) !== 0) return;
  let rel = url.pathname.slice(SCOPE.length);
  try { rel = decodeURIComponent(rel); } catch (err) {}   // 中文路径在请求里是百分号编码
  rel = rel.replace(/^\/+/, '').replace(/\/+/g, '/');
  if (rel.indexOf('site/') === 0) return;        // 密文本身直接走网络
  if (rel === 'sw.js' || rel.indexOf('index.html') === 0) return;

  event.respondWith((async () => {
    if (!(await ensure())) return new Response('locked', { status: 423 });
    if (rel === 'app.html') return respondWith('app.html', 'site/app.html.enc', MIME['.html']);
    // 兼容旧版图片压缩产物：先按原路径查，再尝试同名 WebP。
    let enc = MAP[rel];
    if (!enc && /\.png$/i.test(rel)) enc = MAP[rel.replace(/\.png$/i, '.webp')];
    if (!enc && /\.webp$/i.test(rel)) enc = MAP[rel.replace(/\.webp$/i, '.png')];
    if (!enc) return fetch(req);
    return respondWith(rel, enc, MIME[ext(rel)] || 'application/octet-stream');
  })());
});

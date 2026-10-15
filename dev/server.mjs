/* خادم محلي يحاكي Netlify: يخدم public/ ويوجّه /api/* إلى منطق الخادم نفسه مع تخزين في ملفات (أو الذاكرة).
   node dev/server.mjs [port] [dataDir|:memory:]   — للتجربة على هذا الجهاز فقط. */
import http from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/core.mjs';
import { fileStore } from '../src/store-file.mjs';
import { memoryStore } from '../src/store-memory.mjs';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const port = +(process.argv[2] || 8899), data = process.argv[3] || path.join(ROOT, '.data');
const store = data === ':memory:' ? memoryStore() : fileStore(data);
const offset = +(process.env.CLOCK_OFFSET_MS || 0);
const app = createApp({ store, now: () => Date.now() + offset, log: (...a) => console.error(...a) });
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
// نفس الرؤوس المعرّفة في netlify.toml
const toml = await fs.readFile(path.join(ROOT, 'netlify.toml'), 'utf8');
const SEC = {}; for (const m of toml.matchAll(/^\s*([A-Za-z-]+)\s*=\s*"([^"]*)"\s*$/gm)) if (/^[A-Z]/.test(m[1])) SEC[m[1]] = m[2];
let n = 0;
http.createServer(async (rq, rs) => {
  try {
    const url = new URL(rq.url, `http://${rq.headers.host}`);
    if (url.pathname.startsWith('/api/')) {
      const chunks = []; for await (const c of rq) chunks.push(c);
      const body = chunks.length ? Buffer.concat(chunks) : undefined;
      const req = new Request(url, { method: rq.method, headers: rq.headers, body: ['GET', 'HEAD'].includes(rq.method) ? undefined : body });
      const ip = (process.env.DEV_TRUST_TEST_IP && rq.headers['x-test-ip']) || rq.socket.remoteAddress;
      const r = await app(req, { ip }); n++;
      rs.writeHead(r.status, Object.fromEntries(r.headers)); rs.end(Buffer.from(await r.arrayBuffer())); return;
    }
    let p = decodeURIComponent(url.pathname); if (p.endsWith('/')) p += 'index.html';
    const f = path.join(ROOT, 'public', path.normalize(p).replace(/^(\.\.[/\\])+/, ''));
    const buf = await fs.readFile(f);
    rs.writeHead(200, { 'content-type': TYPES[path.extname(f)] || 'application/octet-stream', ...SEC }); rs.end(buf);
  } catch (e) { rs.writeHead(404, { 'content-type': 'text/plain' }); rs.end('404'); }
}).listen(port, () => console.log(`remote-quiz dev on http://localhost:${port} (data: ${data})`));

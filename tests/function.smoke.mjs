/* دخان للدالة كما ستعمل على Netlify: netlify/functions/api.mjs + الحزمة + Blobs (خادم Blobs المحلي الرسمي). RQ_TOOLS=<مجلد فيه @netlify/blobs> node tests/function.smoke.mjs */
import { createRequire } from 'node:module'; import fs from 'node:fs';
const { BlobsServer } = createRequire((process.env.RQ_TOOLS || process.cwd()) + '/x.js')('@netlify/blobs/server');
const srv = new BlobsServer({ directory: fs.mkdtempSync('/tmp/rqf-'), token: 't' }); const { port } = await srv.start(); const u = 'http://localhost:' + port;
process.env.NETLIFY_BLOBS_CONTEXT = Buffer.from(JSON.stringify({ edgeURL: u, uncachedEdgeURL: u, siteID: 's', token: 't' })).toString('base64');
const fn = await import('../netlify/functions/api.mjs');
const call = async (m, p, b, h = {}) => { const r = await fn.default(new Request('https://x.netlify.app/api' + p, { method: m, headers: { 'content-type': 'application/json', ...h }, body: b && JSON.stringify(b) }), { ip: '1.2.3.4' }); return [r.status, await r.text()]; };
console.log('config', fn.config);
console.log(await call('GET', '/t/status'));
console.log(await call('POST', '/t/claim', { key: 'function-smoke-secret' }));
console.log(await call('GET', '/t/ping', null, { 'x-teacher-key': 'function-smoke-secret' }));
console.log(await call('POST', '/login', { q: 'nope', code: 'AAAA-AAAA' }));
const t0 = performance.now(); for (let i = 0; i < 20; i++) await call('GET', '/t/ping', null, { 'x-teacher-key': 'function-smoke-secret' }); console.log('20 pings ms', Math.round(performance.now() - t0), 'rss MB', Math.round(process.memoryUsage().rss / 1e6));
process.exit(0);

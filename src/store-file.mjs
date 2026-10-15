/* مُحوِّل تخزين في ملفات (للتطوير المحلي فقط: عملية واحدة). */
import { promises as fs } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
export function fileStore(dir) {
  const f = k => path.join(dir, encodeURIComponent(k)); const tag = v => '"' + createHash('sha1').update(v).digest('hex') + '"';
  let chain = Promise.resolve(); const lock = fn => (chain = chain.then(fn, fn));   // كتابة متسلسلة = ذرّية onlyIfNew/onlyIfMatch
  const read = async k => { try { return await fs.readFile(f(k), 'utf8'); } catch (e) { return null; } };
  return {
    async get(k) { const v = await read(k); return v == null ? null : JSON.parse(v); },
    async getWithEtag(k) { const v = await read(k); return v == null ? null : { data: JSON.parse(v), etag: tag(v) }; },
    set(k, val, o = {}) { return lock(async () => { await fs.mkdir(dir, { recursive: true }); const cur = await read(k);
      if (o.onlyIfNew && cur != null) return { modified: false };
      if (o.onlyIfMatch && (cur == null || tag(cur) !== o.onlyIfMatch)) return { modified: false };
      const tmp = f(k) + '.' + process.pid + '.tmp'; await fs.writeFile(tmp, JSON.stringify(val)); await fs.rename(tmp, f(k)); return { modified: true }; }); },
    del(k) { return lock(async () => { try { await fs.unlink(f(k)); } catch (e) { } }); },
    async list(p) { let names = []; try { names = await fs.readdir(dir); } catch (e) { } return names.filter(n => !n.endsWith('.tmp')).map(decodeURIComponent).filter(k => k.startsWith(p)).sort(); },
  };
}

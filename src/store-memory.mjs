/* مُحوِّل تخزين في الذاكرة (للاختبارات). */
import { createHash } from 'node:crypto';
export function memoryStore() {
  const m = new Map(); const tag = v => '"' + createHash('sha1').update(v).digest('hex') + '"';
  return {
    async get(k) { const v = m.get(k); return v == null ? null : JSON.parse(v); },
    async getWithEtag(k) { const v = m.get(k); return v == null ? null : { data: JSON.parse(v), etag: tag(v) }; },
    async set(k, val, o = {}) { const cur = m.get(k);
      if (o.onlyIfNew && cur != null) return { modified: false };
      if (o.onlyIfMatch && (cur == null || tag(cur) !== o.onlyIfMatch)) return { modified: false };
      m.set(k, JSON.stringify(val)); return { modified: true }; },
    async del(k) { m.delete(k); },
    async list(p) { return [...m.keys()].filter(k => k.startsWith(p)).sort(); },
  };
}

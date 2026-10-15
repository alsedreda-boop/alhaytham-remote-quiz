/* «مسابقة عن بعد» — منطق الخادم (مستقل عن المزوّد).
   handle(Request, {ip}) → Response. التخزين عبر مُحوِّل قابل للاستبدال (store) بالواجهة:
     get(key) → JSON|null · getWithEtag(key) → {data, etag}|null · set(key, value, {onlyIfNew, onlyIfMatch}) → {modified}
     del(key) · list(prefix) → [keys]
   المحوّلات الجاهزة: store-blobs.mjs (Netlify Blobs) · store-file.mjs (تطوير محلي) · store-memory.mjs (اختبارات).
   الخصوصية: الأسماء تُخزَّن هنا فقط للفصول التي يرفعها المعلم. الحسابات: رقم السجل بصمة HMAC فقط (+ نسخة مشفّرة بمفتاح مشتق من سرّ المعلم)، والرقم السري مُملَّح ومُجزّأ (scrypt). */
import { createHmac, scryptSync, randomBytes, randomInt, createCipheriv, createDecipheriv, timingSafeEqual, createHash } from 'node:crypto';

const MAX_Q = 60, MAX_CH = 6, MAX_HTML = 24000, MAX_CLASSES = 60, MAX_STU = 200;
const LOGIN_FAILS = 15, LOGIN_WIN = 10 * 60e3, TEACH_FAILS = 6, GRACE = 5e3, TOKEN_DAYS = 30;
const ACC_FAILS = 10, ACC_LOCK = 5 * 60e3, FORGOT_MAX = 10, REJECT_COOL = 30 * 60e3;   // حماية خفيفة: تمنع التخمين الآلي فقط

const sha = s => createHash('sha256').update(s).digest('hex');
const b64u = b => Buffer.from(b).toString('base64url');
const rid = (n = 10) => Array.from({ length: n }, () => 'abcdefghjkmnpqrstuvwxyz23456789'[randomInt(31)]).join('');
const toAsciiDigits = s => String(s == null ? '' : s).replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d)).replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d));
export const normRec = s => { const d = toAsciiDigits(s).replace(/\D/g, ''); return d.length >= 4 && d.length <= 15 ? d : ''; };
export const normPin = s => { const d = toAsciiDigits(s).replace(/\s/g, ''); return /^\d{4}$/.test(d) ? d : ''; };
const normName = s => String(s || '').replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, 80);
const clampInt = (v, a, b, d) => { v = Math.round(+v); return Number.isFinite(v) ? Math.min(b, Math.max(a, v)) : d; };
/* تنقية HTML القادم من مولّدات المختبر (احتياط: المصدر هو المعلم نفسه) */
export function sanitize(h) {
  h = String(h || '').slice(0, MAX_HTML);
  return h.replace(/<\s*(script|style|iframe|object|embed|link|meta|base|form|input|textarea|select|button)\b[\s\S]*?(<\s*\/\s*\1\s*>|$)/gi, '')
    .replace(/<\s*\/?\s*(script|style|iframe|object|embed|link|meta|base|form|input|textarea|select|button)\b[^>]*>/gi, '')
    .replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/(href|xlink:href|src|action)\s*=\s*("|')?\s*(javascript|data|vbscript):[^"'\s>]*\2?/gi, '');
}
function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }
const range = n => Array.from({ length: n }, (_, i) => i);

export function createApp({ store, now = () => Date.now(), log = () => { } }) {
  const mem = { server: null, teacher: null, okKeys: new Map(), boards: new Map(), qlist: null };

  /* ---------- مفاتيح الخادم ---------- */
  async function serverKey() {
    if (mem.server) return mem.server;
    let c = await store.get('cfg/server');
    if (!c) { await store.set('cfg/server', { k: randomBytes(32).toString('hex'), t: now() }, { onlyIfNew: true }); c = await store.get('cfg/server'); }
    mem.server = Buffer.from(c.k, 'hex'); return mem.server;
  }
  async function sign(payload) { const p = b64u(JSON.stringify(payload)); return p + '.' + createHmac('sha256', await serverKey()).update('tok:' + p).digest('base64url'); }
  async function verify(tok) {
    if (!tok || typeof tok !== 'string' || tok.length > 600) return null;
    const [p, s] = tok.split('.'); if (!p || !s) return null;
    const exp = createHmac('sha256', await serverKey()).update('tok:' + p).digest('base64url');
    const a = Buffer.from(s), b = Buffer.from(exp); if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
    try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.e > now() ? o : null; } catch (e) { return null; }
  }

  /* ---------- سرّ المعلم ---------- */
  async function teacherCfg() { if (!mem.teacher) mem.teacher = await store.get('cfg/teacher'); return mem.teacher; }
  function encKey(secret, cfg) { return scryptSync(secret, Buffer.from(cfg.es, 'hex'), 32, { N: 16384, r: 8, p: 1 }); }
  async function teacherAuth(req, ip) {
    const key = req.headers.get('x-teacher-key') || '';
    const cfg = await teacherCfg(); if (!cfg || !key || key.length > 200) return null;
    const fp = sha('t:' + key), hit = mem.okKeys.get(fp);
    if (hit && hit.exp > now()) return hit.ek;
    if (await limited('rl/t/' + sha(ip).slice(0, 16), TEACH_FAILS)) throw new HttpErr(429, 'محاولات كثيرة. انتظر عشر دقائق.');
    const h = scryptSync(key, Buffer.from(cfg.salt, 'hex'), 32, { N: 16384, r: 8, p: 1 });
    if (!timingSafeEqual(h, Buffer.from(cfg.hash, 'hex'))) { await fail('rl/t/' + sha(ip).slice(0, 16)); return null; }
    const ek = encKey(key, cfg); mem.okKeys.set(fp, { ek, exp: now() + 10 * 60e3 }); return ek;
  }
  const enc = (ek, txt) => { const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', ek, iv); const ct = Buffer.concat([c.update(txt, 'utf8'), c.final()]); return b64u(Buffer.concat([iv, c.getAuthTag(), ct])); };
  const dec = (ek, s) => { try { const b = Buffer.from(s, 'base64url'), d = createDecipheriv('aes-256-gcm', ek, b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'); } catch (e) { return null; } };

  /* ---------- تحديد المعدّل ---------- */
  async function limited(key, max) { const r = await store.get(key); const t = now(); return !!r && (r.f || []).filter(x => t - x < LOGIN_WIN).length >= max; }
  async function fail(key) { const r = (await store.get(key)) || { f: [] }; const t = now(); r.f = r.f.filter(x => t - x < LOGIN_WIN).concat(t).slice(-30); await store.set(key, r); return r.f.length; }

  /* ---------- أدوات ---------- */
  const pubQuiz = q => ({ id: q.id, title: q.title, unit: { title: q.unit.title, chapter: q.unit.chapter }, lessons: q.lessons, n: q.questions.length, opensAt: q.opensAt, closesAt: q.closesAt, limitSec: q.limitSec, attempts: q.attempts, digits: q.digits, reveal: !!q.reveal, closed: !!q.closedAt });
  const qStatus = q => { const t = now(); return q.closedAt || t > q.closesAt ? 'closed' : t < q.opensAt ? 'soon' : 'open'; };
  const tryDone = (q, tr) => tr.done || tr.ans.length >= tr.order.length || now() > tr.deadline + GRACE;
  const tryScore = tr => tr.ans.filter(a => a.ok).length;
  function viewQ(q, tr, i) {
    const Q = q.questions[tr.order[i]];
    return { i, n: tr.order.length, lesson: Q.lesson, prompt: Q.prompt, ctx: Q.ctx || '', small: !!Q.small, choices: tr.ch[i].map(k => Q.choices[k].html) };
  }
  function attSummary(q, att) {
    if (!att || !att.tries.length) return null;
    const cur = att.tries[att.tries.length - 1], done = tryDone(q, cur);
    const best = att.tries.reduce((m, tr) => Math.max(m, tryScore(tr)), 0);
    return { tries: att.tries.length, done, answered: cur.ans.length, score: tryScore(cur), best, n: cur.order.length, deadline: cur.deadline, start: cur.start, end: cur.end || (done ? Math.min(now(), cur.deadline) : null) };
  }
  async function loadAtt(qid, sid) { return store.getWithEtag(`att/${qid}/${sid}`); }
  async function saveAtt(qid, sid, att, etag) { const r = await store.set(`att/${qid}/${sid}`, att, etag ? { onlyIfMatch: etag } : { onlyIfNew: true }); return r.modified; }

  async function board(q) {
    const c = mem.boards.get(q.id); if (c && now() - c.t < 3000) return c.rows;
    const keys = await store.list(`att/${q.id}/`);
    const atts = (await Promise.all(keys.map(k => store.get(k)))).filter(Boolean);
    const rows = atts.map(a => { const s = attSummary(q, a); const cur = a.tries[a.tries.length - 1]; const last = cur.ans.length ? cur.ans[cur.ans.length - 1].t : cur.start;
      return { sid: a.sid, name: a.name, cls: a.clsLabel, score: s.done ? s.best : Math.max(s.best, s.score), answered: s.answered, n: s.n, done: s.done, el: last - cur.start }; })
      .sort((a, b) => b.score - a.score || (b.done - a.done) || b.answered - a.answered || a.el - b.el);
    mem.boards.set(q.id, { t: now(), rows }); return rows;
  }

  /* ---------- المسارات ---------- */
  const routes = [];
  const on = (m, re, fn, teacher = false) => routes.push({ m, re, fn, teacher });

  // الطالب
  /* ---------- حسابات الطلاب: رقم السجل + رقم سري من ٤ أرقام ----------
     acct/{ah}: ah = HMAC(رقم السجل) فلا يُخزَّن الرقم نصًّا (نسخة مشفّرة بمفتاح المعلم re لعرضها له فقط).
     {sid, cid, name, cls, re, ps, ph, must, tmp?, zero?, tv, first?, last?, set?, rjAt?}
     rl/a/{ah}: محاولات خاطئة وقفل مؤقت (تُحسب حتى لأرقام غير موجودة؛ فلا تكشف الاستجابة وجود الرقم). rreq/{ah}: طلب «نسيت الرقم السري». */
  const accKey = async rec => createHmac('sha256', await serverKey()).update('rec:' + rec).digest('hex').slice(0, 32);
  const pinHash = (pin, ah, salt) => scryptSync(pin + ':' + ah, salt, 32, { N: 8192, r: 8, p: 1 });
  function setPin(a, pin, ah) { const s = randomBytes(16); a.ps = s.toString('hex'); a.ph = pinHash(pin, ah, s).toString('hex'); }
  const newPin = () => { let p; do { p = String(randomInt(10000)).padStart(4, '0'); } while (p === '0000'); return p; };
  const BAD_LOGIN = 'رقم السجل أو الرقم السري غير صحيح.';
  const LOCK_MSG = 'محاولات خاطئة كثيرة. حاول بعد خمس دقائق، أو اطلب من المعلم فتح الحساب.';
  async function lockOf(ah) { const r = await store.get('rl/a/' + ah); return r && r.lock > now() ? r.lock : 0; }
  async function accFail(ah) {
    const r = (await store.get('rl/a/' + ah)) || { f: [] }, t = now();
    r.f = r.f.filter(x => t - x < LOGIN_WIN).concat(t).slice(-20);
    if (r.f.length >= ACC_FAILS) { r.lock = t + ACC_LOCK; r.f = []; }
    await store.set('rl/a/' + ah, r); return r.lock > t;
  }
  on('POST', /^\/login$/, async ({ body, ip }) => {
    const rk = 'rl/l/' + sha(ip).slice(0, 16);
    const ipBad = async () => { if (await fail(rk) >= LOGIN_FAILS) throw new HttpErr(429, 'محاولات خاطئة كثيرة من هذا الجهاز. حاول بعد عشر دقائق.'); };
    if (await limited(rk, LOGIN_FAILS)) throw new HttpErr(429, 'محاولات خاطئة كثيرة من هذا الجهاز. حاول بعد عشر دقائق.');
    const rec = normRec(body.rec), pin = normPin(body.pin);
    if (!rec || !pin) { await ipBad(); throw new HttpErr(401, BAD_LOGIN); }
    const ah = await accKey(rec);
    if (await lockOf(ah)) throw new HttpErr(429, LOCK_MSG);
    const r = await store.getWithEtag('acct/' + ah), a = r && r.data;
    const h = pinHash(pin, ah, Buffer.from(a ? a.ps : '00'.repeat(16), 'hex'));   // حساب وهمي عند عدم الوجود: الزمن نفسه تقريبًا
    if (!a || !timingSafeEqual(h, Buffer.from(a.ph, 'hex'))) {
      await ipBad(); if (await accFail(ah)) throw new HttpErr(429, LOCK_MSG);
      throw new HttpErr(401, BAD_LOGIN);
    }
    await store.del('rl/a/' + ah);
    a.first = a.first || now(); a.last = now(); await store.set('acct/' + ah, a);
    return { token: await sign({ a: ah, v: a.tv || 0, e: now() + TOKEN_DAYS * 864e5 }), must: !!a.must, name: a.name, cls: a.cls };
  });
  // «نسيت الرقم السري»: الاستجابة نفسها دائمًا؛ طلب واحد معلّق لكل حساب، ومهلة بعد الرفض
  on('POST', /^\/forgot$/, async ({ body, ip }) => {
    const rk = 'rl/f/' + sha(ip).slice(0, 16), done = { ok: true };
    if (await limited(rk, FORGOT_MAX)) throw new HttpErr(429, 'طلبات كثيرة. حاول لاحقًا.');
    await fail(rk);
    const rec = normRec(body.rec); if (!rec) return done;
    const ah = await accKey(rec), a = await store.get('acct/' + ah);
    if (!a || (a.rjAt && now() - a.rjAt < REJECT_COOL) || (await store.get('rreq/' + ah))) return done;
    if ((await store.list('rreq/')).length >= 300) return done;
    await store.set('rreq/' + ah, { t: now() }, { onlyIfNew: true }); return done;
  });
  async function account(req, allowMust = false) {
    const tok = await verify((req.headers.get('authorization') || '').replace(/^Bearer\s+/i, ''));
    if (!tok || !tok.a) throw new HttpErr(401, 'انتهت الجلسة. سجّل الدخول مرة أخرى.');
    const r = await store.getWithEtag('acct/' + tok.a), a = r && r.data;
    if (!a || (a.tv || 0) !== tok.v) throw new HttpErr(401, 'انتهت الجلسة. سجّل الدخول مرة أخرى.');
    if (a.must && !allowMust) throw new HttpErr(403, 'غيّر الرقم السري أولًا.', { must: true });
    return { ah: tok.a, a, etag: r.etag };
  }
  on('POST', /^\/pin$/, async ({ req, body }) => {
    const { ah, a } = await account(req, true), pin = normPin(body.pin);
    if (!pin || pin === '0000') throw new HttpErr(400, 'اختر ٤ أرقام غير ٠٠٠٠.');
    if (!a.must) { const old = normPin(body.old); if (!old || !timingSafeEqual(pinHash(old, ah, Buffer.from(a.ps, 'hex')), Buffer.from(a.ph, 'hex'))) throw new HttpErr(401, 'الرقم السري الحالي غير صحيح.'); }
    else if (timingSafeEqual(pinHash(pin, ah, Buffer.from(a.ps, 'hex')), Buffer.from(a.ph, 'hex'))) throw new HttpErr(400, 'اختر رقمًا جديدًا غير الرقم المؤقت.');
    setPin(a, pin, ah); a.must = false; delete a.tmp; delete a.zero; a.set = now(); a.tv = (a.tv || 0) + 1;
    await store.set('acct/' + ah, a); await store.del('rreq/' + ah);
    return { token: await sign({ a: ah, v: a.tv, e: now() + TOKEN_DAYS * 864e5 }), must: false, name: a.name, cls: a.cls };
  });
  // مسابقات فصل الطالب (لا استطلاع: تُطلب عند الدخول/الرجوع فقط). القائمة تُخبَّأ ٥ ثوانٍ لكل نسخة خادم (دخول فصل كامل معًا)
  async function allQuizzes() { const c = mem.qlist; if (c && now() - c.t < 5000) return c.qs; const qs = (await Promise.all((await store.list('quiz/')).map(k => store.get(k)))).filter(Boolean); mem.qlist = { t: now(), qs }; return qs; }
  on('GET', /^\/quizzes$/, async ({ req }) => {
    const { a } = await account(req);
    const qs = (await allQuizzes()).filter(q => q.classes.includes(a.cid));
    const out = await Promise.all(qs.filter(q => qStatus(q) !== 'closed' || now() - (q.closedAt || q.closesAt) < 14 * 864e5).map(async q => {
      const att = await store.get(`att/${q.id}/${a.sid}`); const s = attSummary(q, att);
      return { ...pubQuiz(q), status: qStatus(q), mine: s ? { done: s.done, best: s.best, answered: s.answered, n: s.n } : null };
    }));
    const rank = { open: 0, soon: 1, closed: 2 };
    return { me: { name: a.name, cls: a.cls }, quizzes: out.sort((x, y) => rank[x.status] - rank[y.status] || x.closesAt - y.closesAt), now: now() };
  });
  const student = async (req, qid) => {
    const { a } = await account(req);
    const q = await store.get('quiz/' + qid); if (!q) throw new HttpErr(404, 'المسابقة غير موجودة أو حُذفت.');
    if (!q.classes.includes(a.cid)) throw new HttpErr(403, 'هذه المسابقة ليست لفصلك.');
    return { q, s: { sid: a.sid, name: a.name }, cls: { id: a.cid, label: a.cls } };
  };
  async function stateOf(q, s, cls) {
    const r = await loadAtt(q.id, s.sid); const att = r && r.data; const sum = attSummary(q, att);
    const out = { me: { name: s.name, cls: cls.label }, quiz: pubQuiz(q), status: qStatus(q), now: now(), att: sum };
    if (sum && !sum.done && qStatus(q) !== 'closed') out.q = viewQ(q, att.tries[att.tries.length - 1], sum.answered);
    if (sum && sum.done) out.review = review(q, att.tries[att.tries.length - 1]);
    out.canStart = qStatus(q) === 'open' && (!sum || (sum.done && sum.tries < q.attempts));
    return out;
  }
  function review(q, tr) {
    const m = {}; tr.ans.forEach(a => { if (!a.ok && a.m) m[a.m] = (m[a.m] || 0) + 1; });
    return { mis: Object.entries(m).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ k, n, name: (q.mis[k] || {}).name || k, hint: (q.mis[k] || {}).hint || '' })) };
  }
  on('GET', /^\/q\/([a-z0-9]+)\/me$/, async ({ req, m }) => { const { q, s, cls } = await student(req, m[1]); return stateOf(q, s, cls); });
  on('POST', /^\/q\/([a-z0-9]+)\/start$/, async ({ req, m }) => {
    const { q, s, cls } = await student(req, m[1]);
    if (qStatus(q) === 'soon') throw new HttpErr(403, 'لم تبدأ المسابقة بعد.');
    if (qStatus(q) === 'closed') throw new HttpErr(403, 'انتهى وقت المسابقة.');
    for (let k = 0; k < 4; k++) {
      const r = await loadAtt(q.id, s.sid); const att = r ? r.data : { sid: s.sid, cid: cls.id, name: s.name, clsLabel: cls.label, tries: [] };
      const cur = att.tries[att.tries.length - 1];
      if (cur && !tryDone(q, cur)) return stateOf(q, s, cls);
      if (att.tries.length >= q.attempts) throw new HttpErr(403, 'استنفدت المحاولات المسموحة.');
      if (cur && !cur.done) { cur.done = true; cur.end = Math.min(now(), cur.deadline); }
      const n = q.questions.length, t = now();
      att.name = s.name; att.clsLabel = cls.label; att.cid = cls.id;
      att.tries.push({ start: t, deadline: Math.min(q.limitSec ? t + q.limitSec * 1000 : Infinity, q.closesAt), order: shuffle(range(n)), ch: [], ans: [], done: false });
      const tr = att.tries[att.tries.length - 1]; tr.ch = tr.order.map(qi => shuffle(range(q.questions[qi].choices.length)));
      if (await saveAtt(q.id, s.sid, att, r && r.etag)) { mem.boards.delete(q.id); return stateOf(q, s, cls); }
    }
    throw new HttpErr(409, 'حاول مرة أخرى.');
  });
  on('POST', /^\/q\/([a-z0-9]+)\/answer$/, async ({ req, m, body }) => {
    const { q, s, cls } = await student(req, m[1]);
    for (let k = 0; k < 4; k++) {
      const r = await loadAtt(q.id, s.sid); if (!r) throw new HttpErr(409, 'ابدأ المسابقة أولًا.');
      const att = r.data, tr = att.tries[att.tries.length - 1];
      if (tryDone(q, tr) || q.closedAt) {
        if (!tr.done) { tr.done = true; tr.end = Math.min(now(), tr.deadline); await saveAtt(q.id, s.sid, att, r.etag); }
        return Object.assign(await stateOf(q, s, cls), { timeout: true });
      }
      const i = +body.i, c = +body.c;
      if (i !== tr.ans.length) return Object.assign(await stateOf(q, s, cls), { stale: true });   // سؤال أُجيب مسبقًا (نقرة مزدوجة)
      if (!Number.isInteger(c) || c < 0 || c >= tr.ch[i].length) throw new HttpErr(400, 'اختيار غير صالح.');
      const Q = q.questions[tr.order[i]], ch = Q.choices[tr.ch[i][c]];
      tr.ans.push({ c: tr.ch[i][c], ok: !!ch.ok, m: ch.ok ? null : (ch.mis || null), t: now() });
      if (tr.ans.length >= tr.order.length) { tr.done = true; tr.end = now(); }
      if (!(await saveAtt(q.id, s.sid, att, r.etag))) continue;
      mem.boards.delete(q.id);
      const out = await stateOf(q, s, cls);
      out.last = { ok: !!ch.ok }; if (q.reveal) out.last.correct = tr.ch[i].findIndex(x => Q.choices[x].ok);
      return out;
    }
    throw new HttpErr(409, 'حاول مرة أخرى.');
  });
  on('GET', /^\/q\/([a-z0-9]+)\/board$/, async ({ req, m }) => {
    const { q, s } = await student(req, m[1]);
    const rows = await board(q), me = rows.findIndex(r => r.sid === s.sid);
    return { rows: rows.map(({ sid, el, ...r }) => Object.assign(r, sid === s.sid ? { me: true } : {})), rank: me + 1, total: rows.length, status: qStatus(q), now: now() };
  });

  // المعلم
  on('GET', /^\/t\/status$/, async () => ({ claimed: !!(await teacherCfg()) }), 'open');
  on('POST', /^\/t\/claim$/, async ({ body }) => {
    const key = String(body.key || '');
    if (key.length < 10) throw new HttpErr(400, 'السرّ قصير: ١٠ أحرف على الأقل.');
    const salt = randomBytes(16), es = randomBytes(16);
    const rec = { salt: salt.toString('hex'), es: es.toString('hex'), hash: scryptSync(key, salt, 32, { N: 16384, r: 8, p: 1 }).toString('hex'), t: now() };
    const r = await store.set('cfg/teacher', rec, { onlyIfNew: true });
    if (!r.modified) throw new HttpErr(409, 'تم ضبط سرّ المعلم مسبقًا.');
    mem.teacher = rec; return { ok: true };
  }, 'open');
  on('GET', /^\/t\/ping$/, async () => ({ ok: true, now: now() }), true);

  /* رفع الفصول + مزامنة الحسابات: الطالب الذي معه رقم سجل يحصل على حساب (يبدأ بـ ٠٠٠٠ ويُجبَر على تغييره).
     الحساب الموجود يبقى برقمه السري؛ تغيّر رقم السجل ← حساب جديد؛ طالب حُذف من القائمة ← يُحذف حسابه. */
  async function dropAcct(ah) { if (!ah) return; await Promise.all(['acct/', 'rreq/', 'rl/a/'].map(p => store.del(p + ah))); }
  async function upsertClasses(list, ek) {
    const out = [], report = { created: 0, kept: 0, removed: 0, noRec: 0, dup: [] }, seen = new Map();
    for (const c of list) {
      const cid = String(c.id || '').replace(/[^\w-]/g, '').slice(0, 40); if (!cid) continue;
      const label = normName(c.label) || cid;
      const old = (await store.get('cls/' + cid)) || { id: cid, students: [] };
      const byId = new Map(old.students.map(s => [s.sid, s]));
      const incoming = (c.students || []).slice(0, MAX_STU).map(s => ({ sid: String(s.sid || s.id || '').replace(/[^\w-]/g, '').slice(0, 40), name: normName(s.name), no: clampInt(s.no, 0, 999, 0), rec: s.rec === undefined ? undefined : normRec(s.rec) })).filter(s => s.sid && s.name);
      const keep = new Set(incoming.map(s => s.sid));
      for (const s of old.students) if (!keep.has(s.sid)) { if (s.ch) await store.del('code/' + s.ch); if (s.ah) { await dropAcct(s.ah); report.removed++; } }
      const students = [];
      for (const s of incoming) {
        const o = byId.get(s.sid) || {}; if (o.ch) await store.del('code/' + o.ch);   // الرموز القديمة (٨ خانات) لم تعد تُستعمل
        let ah = o.ah || null;
        if (s.rec !== undefined) {   // undefined = لم يُرسَل رقم السجل (رفع من المختبر بلا أرقام): لا تغيير على الحساب
          const nh = s.rec ? await accKey(s.rec) : null;
          if (nh && seen.has(nh)) { report.dup.push(s.name); if (ah === nh) ah = null; }
          else {
            if (ah && ah !== nh) { await dropAcct(ah); report.removed++; ah = null; }
            if (nh) { seen.set(nh, s.sid); ah = nh; }
          }
        }
        if (!ah) { report.noRec++; students.push({ sid: s.sid, name: s.name, no: s.no }); continue; }
        const a = await store.get('acct/' + ah);
        if (a && a.sid !== s.sid && (await store.get('cls/' + a.cid) || { students: [] }).students.some(x => x.sid === a.sid && x.ah === ah)) { report.dup.push(s.name); students.push({ sid: s.sid, name: s.name, no: s.no }); continue; }   // الرقم لطالب آخر
        if (a && a.sid === s.sid) { if (a.name !== s.name || a.cid !== cid || a.cls !== label) { Object.assign(a, { name: s.name, cid, cls: label }); await store.set('acct/' + ah, a); } report.kept++; }
        else { const n = { sid: s.sid, cid, name: s.name, cls: label, re: enc(ek, s.rec), must: true, zero: true, tv: (a && a.tv || 0) + 1, created: now() }; setPin(n, '0000', ah); await store.set('acct/' + ah, n); await store.del('rl/a/' + ah); report.created++; }
        students.push({ sid: s.sid, name: s.name, no: s.no, ah });
      }
      const rec = { id: cid, label, students, updated: now() };
      await store.set('cls/' + cid, rec); out.push({ id: cid, label, students: students.map(s => ({ sid: s.sid, name: s.name, no: s.no, acct: !!s.ah })) });
    }
    return { classes: out, report };
  }
  on('PUT', /^\/t\/classes$/, async ({ body, ek }) => upsertClasses(Array.isArray(body.classes) ? body.classes.slice(0, MAX_CLASSES) : [], ek), true);
  on('PUT', /^\/t\/accounts$/, async ({ body, ek }) => upsertClasses(Array.isArray(body.classes) ? body.classes.slice(0, MAX_CLASSES) : [], ek), true);
  on('GET', /^\/t\/classes$/, async () => {
    const cs = (await Promise.all((await store.list('cls/')).map(k => store.get(k)))).filter(Boolean);
    return { classes: cs.map(c => ({ id: c.id, label: c.label, updated: c.updated, students: c.students.map(s => ({ sid: s.sid, name: s.name, no: s.no, acct: !!s.ah })) })) };
  }, true);
  // حالة الحسابات (مختصرة): pin = 'zero' (لم يغيّر ٠٠٠٠) | 'tmp' (رقم مؤقت من المعلم) | 'set' (اختار رقمه) — مع القفل وطلبات النسيان
  on('GET', /^\/t\/accounts$/, async ({ ek }) => {
    const cs = (await Promise.all((await store.list('cls/')).map(k => store.get(k)))).filter(Boolean);
    const locks = new Map(); for (const k of await store.list('rl/a/')) { const r = await store.get(k); if (r && r.lock > now()) locks.set(k.slice(5), r.lock); }
    const reqs = new Set((await store.list('rreq/')).map(k => k.slice(5)));
    const classes = await Promise.all(cs.map(async c => ({ id: c.id, label: c.label, students: await Promise.all(c.students.map(async s => {
      const a = s.ah && await store.get('acct/' + s.ah);
      if (!a) return { sid: s.sid, name: s.name, no: s.no, id: null };
      return { sid: s.sid, name: s.name, no: s.no, id: s.ah, rec: dec(ek, a.re), pin: !a.must ? 'set' : a.tmp ? 'tmp' : 'zero', tmp: a.must && a.tmp ? dec(ek, a.tmp) : null, first: a.first || null, last: a.last || null, set: a.set || null, lock: locks.get(s.ah) || 0, req: reqs.has(s.ah) };
    })) })));
    return { classes, now: now() };
  }, true);
  async function teacherReset(id, zero, ek) {
    const ah = String(id || '').replace(/[^0-9a-f]/g, '').slice(0, 32), a = ah && await store.get('acct/' + ah);
    if (!a) throw new HttpErr(404, 'الحساب غير موجود على الخادم. زامن الحسابات.');
    const pin = zero ? '0000' : newPin(); setPin(a, pin, ah);
    a.must = true; a.tv = (a.tv || 0) + 1; if (zero) { a.zero = true; delete a.tmp; } else { a.tmp = enc(ek, pin); delete a.zero; }
    await store.set('acct/' + ah, a); await store.del('rreq/' + ah); await store.del('rl/a/' + ah);
    return { ok: true, id: ah, pin, name: a.name, cls: a.cls };
  }
  on('POST', /^\/t\/accounts\/reset$/, async ({ body, ek }) => teacherReset(body.id, !!body.zero, ek), true);
  on('POST', /^\/t\/accounts\/unlock$/, async ({ body }) => { const ah = String(body.id || '').replace(/[^0-9a-f]/g, '').slice(0, 32); if (ah) await store.del('rl/a/' + ah); return { ok: true }; }, true);
  // طلبات «نسيت الرقم السري» (تستطلعها اللوحة بقائمة خفيفة)
  on('GET', /^\/t\/resets$/, async () => {
    const keys = await store.list('rreq/');
    const resets = (await Promise.all(keys.map(async k => { const ah = k.slice(5), r = await store.get(k), a = await store.get('acct/' + ah); if (!r || !a) { if (r) await store.del(k); return null; } return { id: ah, sid: a.sid, name: a.name, cls: a.cls, t: r.t }; }))).filter(Boolean);
    return { resets: resets.sort((x, y) => x.t - y.t), now: now() };
  }, true);
  on('POST', /^\/t\/resets\/approve$/, async ({ body, ek }) => teacherReset(body.id, false, ek), true);
  on('POST', /^\/t\/resets\/reject$/, async ({ body }) => {
    const ah = String(body.id || '').replace(/[^0-9a-f]/g, '').slice(0, 32), a = ah && await store.get('acct/' + ah);
    if (a) { a.rjAt = now(); await store.set('acct/' + ah, a); } if (ah) await store.del('rreq/' + ah); return { ok: true };
  }, true);
  on('DELETE', /^\/t\/classes\/([\w-]+)$/, async ({ m }) => {
    const cid = m[1], c = await store.get('cls/' + cid); if (!c) return { ok: true, removed: 0 };
    const sids = new Set(c.students.map(s => s.sid)); let removed = 0;
    await Promise.all(c.students.map(async s => { if (s.ch) await store.del('code/' + s.ch); await dropAcct(s.ah); }));
    for (const k of await store.list('quiz/')) {
      const q = await store.get(k); if (!q) continue;
      for (const ak of await store.list(`att/${q.id}/`)) if (sids.has(ak.split('/').pop())) { await store.del(ak); removed++; }
      if (q.classes.includes(cid)) { q.classes = q.classes.filter(x => x !== cid); await store.set(k, q); }
    }
    mem.qlist = null; await store.del('cls/' + cid); return { ok: true, removed };
  }, true);

  on('POST', /^\/t\/quizzes$/, async ({ body }) => {
    const qs = Array.isArray(body.questions) ? body.questions.slice(0, MAX_Q) : [];
    const questions = qs.map(Q => {
      const ch = (Q.choices || []).slice(0, MAX_CH).map(c => ({ html: sanitize(c.html), ok: !!c.ok, mis: c.ok ? null : (String(c.mis || '').slice(0, 40) || null) }));
      if (ch.length < 2 || ch.filter(c => c.ok).length !== 1) throw new HttpErr(400, 'سؤال غير صالح: يجب أن يكون له بديل صحيح واحد.');
      return { lesson: String(Q.lesson || '').slice(0, 10), prompt: sanitize(Q.prompt), ctx: sanitize(Q.ctx), small: !!Q.small, choices: ch, answer: sanitize(Q.answer) };
    });
    if (!questions.length) throw new HttpErr(400, 'لا توجد أسئلة.');
    const classes = (body.classes || []).map(String).slice(0, MAX_CLASSES);
    const ex = await Promise.all(classes.map(c => store.get('cls/' + c)));
    if (!classes.length || ex.some(x => !x)) throw new HttpErr(400, 'ارفع الفصول أولًا.');
    const t = now(), opensAt = clampInt(body.opensAt, 0, 9e15, t), closesAt = clampInt(body.closesAt, opensAt + 60e3, opensAt + 60 * 864e5, opensAt + 864e5);
    const mis = {}; Object.entries(body.mis || {}).slice(0, 200).forEach(([k, v]) => { mis[String(k).slice(0, 40)] = { name: normName(v && v.name), hint: sanitize(v && v.hint).slice(0, 2000), lesson: String((v && v.lesson) || '').slice(0, 10) }; });
    const u = body.unit || {};
    const q = { id: rid(10), created: t, title: normName(body.title) || 'مسابقة', unit: { slug: String(u.slug || '').replace(/[^\w-]/g, '').slice(0, 30), title: normName(u.title), chapter: clampInt(u.chapter, 0, 99, 0), prefix: String(u.prefix || '').replace(/[^\w.-]/g, '').slice(0, 40) },
      lessons: (body.lessons || []).slice(0, 30).map(l => ({ id: String(l.id || '').slice(0, 10), title: normName(l.title) })),
      classes, opensAt, closesAt, limitSec: clampInt(body.limitSec, 0, 6 * 3600, 0), attempts: clampInt(body.attempts, 1, 10, 1), reveal: !!body.reveal,
      digits: ['w', 'e', 'book'].includes(body.digits) ? body.digits : 'e', questions, mis };
    await store.set('quiz/' + q.id, q, { onlyIfNew: true }); mem.qlist = null;
    return { id: q.id };
  }, true);
  on('GET', /^\/t\/quizzes$/, async () => {
    const qs = (await Promise.all((await store.list('quiz/')).map(k => store.get(k)))).filter(Boolean);
    const out = await Promise.all(qs.map(async q => ({ ...pubQuiz(q), classes: q.classes, created: q.created, status: qStatus(q), joined: (await store.list(`att/${q.id}/`)).length })));
    return { quizzes: out.sort((a, b) => b.created - a.created) };
  }, true);
  on('GET', /^\/t\/quizzes\/([a-z0-9]+)$/, async ({ m }) => {
    const q = await store.get('quiz/' + m[1]); if (!q) throw new HttpErr(404, 'المسابقة غير موجودة.');
    const classes = (await Promise.all(q.classes.map(c => store.get('cls/' + c)))).filter(Boolean).map(c => ({ id: c.id, label: c.label, students: c.students.map(s => ({ sid: s.sid, name: s.name, no: s.no })) }));
    const atts = (await Promise.all((await store.list(`att/${q.id}/`)).map(k => store.get(k)))).filter(Boolean).map(a => {
      const s = attSummary(q, a); return { sid: a.sid, cid: a.cid, name: a.name, ...s, tries: a.tries.map(tr => ({ start: tr.start, end: tr.end || null, done: tryDone(q, tr), score: tryScore(tr), ans: tr.ans.map((x, i) => ({ q: tr.order[i], ok: x.ok, m: x.m, t: x.t })) })) };
    });
    return { quiz: { ...q, status: qStatus(q) }, classes, attempts: atts, resets: (await store.list('rreq/')).length, now: now() };
  }, true);
  on('PATCH', /^\/t\/quizzes\/([a-z0-9]+)$/, async ({ m, body }) => {
    const q = await store.get('quiz/' + m[1]); if (!q) throw new HttpErr(404, 'المسابقة غير موجودة.');
    if (body.close) q.closedAt = now();
    if (body.reopen) delete q.closedAt;
    if (body.closesAt) q.closesAt = clampInt(body.closesAt, q.opensAt + 60e3, q.opensAt + 60 * 864e5, q.closesAt);
    if (body.attempts) q.attempts = clampInt(body.attempts, 1, 10, q.attempts);
    await store.set('quiz/' + q.id, q); mem.boards.delete(q.id); mem.qlist = null; return { ok: true, status: qStatus(q) };
  }, true);
  on('DELETE', /^\/t\/quizzes\/([a-z0-9]+)$/, async ({ m }) => {
    const keys = await store.list(`att/${m[1]}/`); await Promise.all(keys.map(k => store.del(k)));
    await store.del('quiz/' + m[1]); mem.boards.delete(m[1]); mem.qlist = null; return { ok: true, removed: keys.length };
  }, true);
  on('DELETE', /^\/t\/quizzes\/([a-z0-9]+)\/attempts\/([\w-]+)$/, async ({ m }) => { await store.del(`att/${m[1]}/${m[2]}`); mem.boards.delete(m[1]); return { ok: true }; }, true);

  /* ---------- المعالج ---------- */
  const HDR = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex, nofollow, noarchive', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff' };
  const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type, x-teacher-key', 'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS', 'access-control-max-age': '86400' };
  return async function handle(req, ctx = {}) {
    const url = new URL(req.url), path = url.pathname.replace(/^\/(\.netlify\/functions\/api|api)/, '') || '/';
    const isT = path.startsWith('/t/'), hdr = isT ? { ...HDR, ...CORS } : HDR;
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: isT ? CORS : {} });
    try {
      const r = routes.find(r => r.m === req.method && r.re.test(path));
      if (!r) throw new HttpErr(404, 'غير موجود');
      let body = {};
      if (req.method !== 'GET' && req.method !== 'DELETE') { const t = await req.text(); if (t.length > 600000) throw new HttpErr(413, 'الطلب كبير'); try { body = t ? JSON.parse(t) : {}; } catch (e) { throw new HttpErr(400, 'JSON غير صالح'); } }
      const ip = ctx.ip || '0.0.0.0';
      let ek = null;
      if (r.teacher === true) { ek = await teacherAuth(req, ip); if (!ek) throw new HttpErr(401, (await teacherCfg()) ? 'سرّ المعلم غير صحيح.' : 'لم يُضبط سرّ المعلم بعد.'); }
      const out = await r.fn({ req, body, ip, ek, m: path.match(r.re) });
      return new Response(JSON.stringify(out), { status: 200, headers: hdr });
    } catch (e) {
      if (!(e instanceof HttpErr)) log('ERR', e && e.stack || e);
      const st = e instanceof HttpErr ? e.status : 500;
      return new Response(JSON.stringify({ error: e instanceof HttpErr ? e.message : 'خطأ في الخادم', ...(e instanceof HttpErr && e.extra || {}) }), { status: st, headers: hdr });
    }
  };
}
export class HttpErr extends Error { constructor(status, msg, extra) { super(msg); this.status = status; this.extra = extra; } }

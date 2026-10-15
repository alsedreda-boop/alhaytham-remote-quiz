// src/core.mjs
import { createHmac, scryptSync, randomBytes, randomInt, createCipheriv, createDecipheriv, timingSafeEqual, createHash } from "node:crypto";
var MAX_Q = 60;
var MAX_CH = 6;
var MAX_HTML = 24e3;
var MAX_CLASSES = 60;
var MAX_STU = 200;
var LOGIN_FAILS = 15;
var LOGIN_WIN = 10 * 6e4;
var TEACH_FAILS = 6;
var GRACE = 5e3;
var TOKEN_DAYS = 30;
var ACC_FAILS = 10;
var ACC_LOCK = 5 * 6e4;
var FORGOT_MAX = 10;
var REJECT_COOL = 30 * 6e4;
var sha = (s) => createHash("sha256").update(s).digest("hex");
var b64u = (b) => Buffer.from(b).toString("base64url");
var rid = (n = 10) => Array.from({ length: n }, () => "abcdefghjkmnpqrstuvwxyz23456789"[randomInt(31)]).join("");
var toAsciiDigits = (s) => String(s == null ? "" : s).replace(/[٠-٩]/g, (d) => "\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669".indexOf(d)).replace(/[۰-۹]/g, (d) => "\u06F0\u06F1\u06F2\u06F3\u06F4\u06F5\u06F6\u06F7\u06F8\u06F9".indexOf(d));
var normRec = (s) => {
  const d = toAsciiDigits(s).replace(/\D/g, "");
  return d.length >= 4 && d.length <= 15 ? d : "";
};
var normPin = (s) => {
  const d = toAsciiDigits(s).replace(/\s/g, "");
  return /^\d{4}$/.test(d) ? d : "";
};
var normName = (s) => String(s || "").replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069<>]/g, "").replace(/\s+/g, " ").trim().slice(0, 80);
var clampInt = (v, a, b, d) => {
  v = Math.round(+v);
  return Number.isFinite(v) ? Math.min(b, Math.max(a, v)) : d;
};
function sanitize(h) {
  h = String(h || "").slice(0, MAX_HTML);
  return h.replace(/<\s*(script|style|iframe|object|embed|link|meta|base|form|input|textarea|select|button)\b[\s\S]*?(<\s*\/\s*\1\s*>|$)/gi, "").replace(/<\s*\/?\s*(script|style|iframe|object|embed|link|meta|base|form|input|textarea|select|button)\b[^>]*>/gi, "").replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "").replace(/(href|xlink:href|src|action)\s*=\s*("|')?\s*(javascript|data|vbscript):[^"'\s>]*\2?/gi, "");
}
function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
var range = (n) => Array.from({ length: n }, (_, i) => i);
function createApp({ store, now = () => Date.now(), log = () => {
} }) {
  const mem = { server: null, teacher: null, okKeys: /* @__PURE__ */ new Map(), boards: /* @__PURE__ */ new Map(), qlist: null };
  async function serverKey() {
    if (mem.server) return mem.server;
    let c = await store.get("cfg/server");
    if (!c) {
      await store.set("cfg/server", { k: randomBytes(32).toString("hex"), t: now() }, { onlyIfNew: true });
      c = await store.get("cfg/server");
    }
    mem.server = Buffer.from(c.k, "hex");
    return mem.server;
  }
  async function sign(payload) {
    const p = b64u(JSON.stringify(payload));
    return p + "." + createHmac("sha256", await serverKey()).update("tok:" + p).digest("base64url");
  }
  async function verify(tok) {
    if (!tok || typeof tok !== "string" || tok.length > 600) return null;
    const [p, s] = tok.split(".");
    if (!p || !s) return null;
    const exp = createHmac("sha256", await serverKey()).update("tok:" + p).digest("base64url");
    const a = Buffer.from(s), b = Buffer.from(exp);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
    try {
      const o = JSON.parse(Buffer.from(p, "base64url").toString());
      return o.e > now() ? o : null;
    } catch (e) {
      return null;
    }
  }
  async function teacherCfg() {
    if (!mem.teacher) mem.teacher = await store.get("cfg/teacher");
    return mem.teacher;
  }
  function encKey(secret, cfg) {
    return scryptSync(secret, Buffer.from(cfg.es, "hex"), 32, { N: 16384, r: 8, p: 1 });
  }
  async function teacherAuth(req, ip) {
    const key = req.headers.get("x-teacher-key") || "";
    const cfg = await teacherCfg();
    if (!cfg || !key || key.length > 200) return null;
    const fp = sha("t:" + key), hit = mem.okKeys.get(fp);
    if (hit && hit.exp > now()) return hit.ek;
    if (await limited("rl/t/" + sha(ip).slice(0, 16), TEACH_FAILS)) throw new HttpErr(429, "\u0645\u062D\u0627\u0648\u0644\u0627\u062A \u0643\u062B\u064A\u0631\u0629. \u0627\u0646\u062A\u0638\u0631 \u0639\u0634\u0631 \u062F\u0642\u0627\u0626\u0642.");
    const h = scryptSync(key, Buffer.from(cfg.salt, "hex"), 32, { N: 16384, r: 8, p: 1 });
    if (!timingSafeEqual(h, Buffer.from(cfg.hash, "hex"))) {
      await fail("rl/t/" + sha(ip).slice(0, 16));
      return null;
    }
    const ek = encKey(key, cfg);
    mem.okKeys.set(fp, { ek, exp: now() + 10 * 6e4 });
    return ek;
  }
  const enc = (ek, txt) => {
    const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", ek, iv);
    const ct = Buffer.concat([c.update(txt, "utf8"), c.final()]);
    return b64u(Buffer.concat([iv, c.getAuthTag(), ct]));
  };
  const dec = (ek, s) => {
    try {
      const b = Buffer.from(s, "base64url"), d = createDecipheriv("aes-256-gcm", ek, b.subarray(0, 12));
      d.setAuthTag(b.subarray(12, 28));
      return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
    } catch (e) {
      return null;
    }
  };
  async function limited(key, max) {
    const r = await store.get(key);
    const t = now();
    return !!r && (r.f || []).filter((x) => t - x < LOGIN_WIN).length >= max;
  }
  async function fail(key) {
    const r = await store.get(key) || { f: [] };
    const t = now();
    r.f = r.f.filter((x) => t - x < LOGIN_WIN).concat(t).slice(-30);
    await store.set(key, r);
    return r.f.length;
  }
  const pubQuiz = (q) => ({ id: q.id, title: q.title, unit: { title: q.unit.title, chapter: q.unit.chapter }, lessons: q.lessons, n: q.questions.length, opensAt: q.opensAt, closesAt: q.closesAt, limitSec: q.limitSec, attempts: q.attempts, digits: q.digits, reveal: !!q.reveal, closed: !!q.closedAt });
  const qStatus = (q) => {
    const t = now();
    return q.closedAt || t > q.closesAt ? "closed" : t < q.opensAt ? "soon" : "open";
  };
  const tryDone = (q, tr) => tr.done || tr.ans.length >= tr.order.length || now() > tr.deadline + GRACE;
  const tryScore = (tr) => tr.ans.filter((a) => a.ok).length;
  function viewQ(q, tr, i) {
    const Q = q.questions[tr.order[i]];
    return { i, n: tr.order.length, lesson: Q.lesson, prompt: Q.prompt, ctx: Q.ctx || "", small: !!Q.small, choices: tr.ch[i].map((k) => Q.choices[k].html) };
  }
  function attSummary(q, att) {
    if (!att || !att.tries.length) return null;
    const cur = att.tries[att.tries.length - 1], done = tryDone(q, cur);
    const best = att.tries.reduce((m, tr) => Math.max(m, tryScore(tr)), 0);
    return { tries: att.tries.length, done, answered: cur.ans.length, score: tryScore(cur), best, n: cur.order.length, deadline: cur.deadline, start: cur.start, end: cur.end || (done ? Math.min(now(), cur.deadline) : null) };
  }
  async function loadAtt(qid, sid) {
    return store.getWithEtag(`att/${qid}/${sid}`);
  }
  async function saveAtt(qid, sid, att, etag) {
    const r = await store.set(`att/${qid}/${sid}`, att, etag ? { onlyIfMatch: etag } : { onlyIfNew: true });
    return r.modified;
  }
  async function board(q) {
    const c = mem.boards.get(q.id);
    if (c && now() - c.t < 3e3) return c.rows;
    const keys = await store.list(`att/${q.id}/`);
    const atts = (await Promise.all(keys.map((k) => store.get(k)))).filter(Boolean);
    const rows = atts.map((a) => {
      const s = attSummary(q, a);
      const cur = a.tries[a.tries.length - 1];
      const last = cur.ans.length ? cur.ans[cur.ans.length - 1].t : cur.start;
      return { sid: a.sid, name: a.name, cls: a.clsLabel, score: s.done ? s.best : Math.max(s.best, s.score), answered: s.answered, n: s.n, done: s.done, el: last - cur.start };
    }).sort((a, b) => b.score - a.score || b.done - a.done || b.answered - a.answered || a.el - b.el);
    mem.boards.set(q.id, { t: now(), rows });
    return rows;
  }
  const routes = [];
  const on = (m, re, fn, teacher = false) => routes.push({ m, re, fn, teacher });
  const accKey = async (rec) => createHmac("sha256", await serverKey()).update("rec:" + rec).digest("hex").slice(0, 32);
  const pinHash = (pin, ah, salt) => scryptSync(pin + ":" + ah, salt, 32, { N: 8192, r: 8, p: 1 });
  function setPin(a, pin, ah) {
    const s = randomBytes(16);
    a.ps = s.toString("hex");
    a.ph = pinHash(pin, ah, s).toString("hex");
  }
  const newPin = () => {
    let p;
    do {
      p = String(randomInt(1e4)).padStart(4, "0");
    } while (p === "0000");
    return p;
  };
  const BAD_LOGIN = "\u0631\u0642\u0645 \u0627\u0644\u0633\u062C\u0644 \u0623\u0648 \u0627\u0644\u0631\u0642\u0645 \u0627\u0644\u0633\u0631\u064A \u063A\u064A\u0631 \u0635\u062D\u064A\u062D.";
  const LOCK_MSG = "\u0645\u062D\u0627\u0648\u0644\u0627\u062A \u062E\u0627\u0637\u0626\u0629 \u0643\u062B\u064A\u0631\u0629. \u062D\u0627\u0648\u0644 \u0628\u0639\u062F \u062E\u0645\u0633 \u062F\u0642\u0627\u0626\u0642\u060C \u0623\u0648 \u0627\u0637\u0644\u0628 \u0645\u0646 \u0627\u0644\u0645\u0639\u0644\u0645 \u0641\u062A\u062D \u0627\u0644\u062D\u0633\u0627\u0628.";
  async function lockOf(ah) {
    const r = await store.get("rl/a/" + ah);
    return r && r.lock > now() ? r.lock : 0;
  }
  async function accFail(ah) {
    const r = await store.get("rl/a/" + ah) || { f: [] }, t = now();
    r.f = r.f.filter((x) => t - x < LOGIN_WIN).concat(t).slice(-20);
    if (r.f.length >= ACC_FAILS) {
      r.lock = t + ACC_LOCK;
      r.f = [];
    }
    await store.set("rl/a/" + ah, r);
    return r.lock > t;
  }
  on("POST", /^\/login$/, async ({ body, ip }) => {
    const rk = "rl/l/" + sha(ip).slice(0, 16);
    const ipBad = async () => {
      if (await fail(rk) >= LOGIN_FAILS) throw new HttpErr(429, "\u0645\u062D\u0627\u0648\u0644\u0627\u062A \u062E\u0627\u0637\u0626\u0629 \u0643\u062B\u064A\u0631\u0629 \u0645\u0646 \u0647\u0630\u0627 \u0627\u0644\u062C\u0647\u0627\u0632. \u062D\u0627\u0648\u0644 \u0628\u0639\u062F \u0639\u0634\u0631 \u062F\u0642\u0627\u0626\u0642.");
    };
    if (await limited(rk, LOGIN_FAILS)) throw new HttpErr(429, "\u0645\u062D\u0627\u0648\u0644\u0627\u062A \u062E\u0627\u0637\u0626\u0629 \u0643\u062B\u064A\u0631\u0629 \u0645\u0646 \u0647\u0630\u0627 \u0627\u0644\u062C\u0647\u0627\u0632. \u062D\u0627\u0648\u0644 \u0628\u0639\u062F \u0639\u0634\u0631 \u062F\u0642\u0627\u0626\u0642.");
    const rec = normRec(body.rec), pin = normPin(body.pin);
    if (!rec || !pin) {
      await ipBad();
      throw new HttpErr(401, BAD_LOGIN);
    }
    const ah = await accKey(rec);
    if (await lockOf(ah)) throw new HttpErr(429, LOCK_MSG);
    const r = await store.getWithEtag("acct/" + ah), a = r && r.data;
    const h = pinHash(pin, ah, Buffer.from(a ? a.ps : "00".repeat(16), "hex"));
    if (!a || !timingSafeEqual(h, Buffer.from(a.ph, "hex"))) {
      await ipBad();
      if (await accFail(ah)) throw new HttpErr(429, LOCK_MSG);
      throw new HttpErr(401, BAD_LOGIN);
    }
    await store.del("rl/a/" + ah);
    a.first = a.first || now();
    a.last = now();
    await store.set("acct/" + ah, a);
    return { token: await sign({ a: ah, v: a.tv || 0, e: now() + TOKEN_DAYS * 864e5 }), must: !!a.must, name: a.name, cls: a.cls };
  });
  on("POST", /^\/forgot$/, async ({ body, ip }) => {
    const rk = "rl/f/" + sha(ip).slice(0, 16), done = { ok: true };
    if (await limited(rk, FORGOT_MAX)) throw new HttpErr(429, "\u0637\u0644\u0628\u0627\u062A \u0643\u062B\u064A\u0631\u0629. \u062D\u0627\u0648\u0644 \u0644\u0627\u062D\u0642\u064B\u0627.");
    await fail(rk);
    const rec = normRec(body.rec);
    if (!rec) return done;
    const ah = await accKey(rec), a = await store.get("acct/" + ah);
    if (!a || a.rjAt && now() - a.rjAt < REJECT_COOL || await store.get("rreq/" + ah)) return done;
    if ((await store.list("rreq/")).length >= 300) return done;
    await store.set("rreq/" + ah, { t: now() }, { onlyIfNew: true });
    return done;
  });
  async function account(req, allowMust = false) {
    const tok = await verify((req.headers.get("authorization") || "").replace(/^Bearer\s+/i, ""));
    if (!tok || !tok.a) throw new HttpErr(401, "\u0627\u0646\u062A\u0647\u062A \u0627\u0644\u062C\u0644\u0633\u0629. \u0633\u062C\u0651\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0645\u0631\u0629 \u0623\u062E\u0631\u0649.");
    const r = await store.getWithEtag("acct/" + tok.a), a = r && r.data;
    if (!a || (a.tv || 0) !== tok.v) throw new HttpErr(401, "\u0627\u0646\u062A\u0647\u062A \u0627\u0644\u062C\u0644\u0633\u0629. \u0633\u062C\u0651\u0644 \u0627\u0644\u062F\u062E\u0648\u0644 \u0645\u0631\u0629 \u0623\u062E\u0631\u0649.");
    if (a.must && !allowMust) throw new HttpErr(403, "\u063A\u064A\u0651\u0631 \u0627\u0644\u0631\u0642\u0645 \u0627\u0644\u0633\u0631\u064A \u0623\u0648\u0644\u064B\u0627.", { must: true });
    return { ah: tok.a, a, etag: r.etag };
  }
  on("POST", /^\/pin$/, async ({ req, body }) => {
    const { ah, a } = await account(req, true), pin = normPin(body.pin);
    if (!pin || pin === "0000") throw new HttpErr(400, "\u0627\u062E\u062A\u0631 \u0664 \u0623\u0631\u0642\u0627\u0645 \u063A\u064A\u0631 \u0660\u0660\u0660\u0660.");
    if (!a.must) {
      const old = normPin(body.old);
      if (!old || !timingSafeEqual(pinHash(old, ah, Buffer.from(a.ps, "hex")), Buffer.from(a.ph, "hex"))) throw new HttpErr(401, "\u0627\u0644\u0631\u0642\u0645 \u0627\u0644\u0633\u0631\u064A \u0627\u0644\u062D\u0627\u0644\u064A \u063A\u064A\u0631 \u0635\u062D\u064A\u062D.");
    } else if (timingSafeEqual(pinHash(pin, ah, Buffer.from(a.ps, "hex")), Buffer.from(a.ph, "hex"))) throw new HttpErr(400, "\u0627\u062E\u062A\u0631 \u0631\u0642\u0645\u064B\u0627 \u062C\u062F\u064A\u062F\u064B\u0627 \u063A\u064A\u0631 \u0627\u0644\u0631\u0642\u0645 \u0627\u0644\u0645\u0624\u0642\u062A.");
    setPin(a, pin, ah);
    a.must = false;
    delete a.tmp;
    delete a.zero;
    a.set = now();
    a.tv = (a.tv || 0) + 1;
    await store.set("acct/" + ah, a);
    await store.del("rreq/" + ah);
    return { token: await sign({ a: ah, v: a.tv, e: now() + TOKEN_DAYS * 864e5 }), must: false, name: a.name, cls: a.cls };
  });
  async function allQuizzes() {
    const c = mem.qlist;
    if (c && now() - c.t < 5e3) return c.qs;
    const qs = (await Promise.all((await store.list("quiz/")).map((k) => store.get(k)))).filter(Boolean);
    mem.qlist = { t: now(), qs };
    return qs;
  }
  on("GET", /^\/quizzes$/, async ({ req }) => {
    const { a } = await account(req);
    const qs = (await allQuizzes()).filter((q) => q.classes.includes(a.cid));
    const out = await Promise.all(qs.filter((q) => qStatus(q) !== "closed" || now() - (q.closedAt || q.closesAt) < 14 * 864e5).map(async (q) => {
      const att = await store.get(`att/${q.id}/${a.sid}`);
      const s = attSummary(q, att);
      return { ...pubQuiz(q), status: qStatus(q), mine: s ? { done: s.done, best: s.best, answered: s.answered, n: s.n } : null };
    }));
    const rank = { open: 0, soon: 1, closed: 2 };
    return { me: { name: a.name, cls: a.cls }, quizzes: out.sort((x, y) => rank[x.status] - rank[y.status] || x.closesAt - y.closesAt), now: now() };
  });
  const student = async (req, qid) => {
    const { a } = await account(req);
    const q = await store.get("quiz/" + qid);
    if (!q) throw new HttpErr(404, "\u0627\u0644\u0645\u0633\u0627\u0628\u0642\u0629 \u063A\u064A\u0631 \u0645\u0648\u062C\u0648\u062F\u0629 \u0623\u0648 \u062D\u064F\u0630\u0641\u062A.");
    if (!q.classes.includes(a.cid)) throw new HttpErr(403, "\u0647\u0630\u0647 \u0627\u0644\u0645\u0633\u0627\u0628\u0642\u0629 \u0644\u064A\u0633\u062A \u0644\u0641\u0635\u0644\u0643.");
    return { q, s: { sid: a.sid, name: a.name }, cls: { id: a.cid, label: a.cls } };
  };
  async function stateOf(q, s, cls) {
    const r = await loadAtt(q.id, s.sid);
    const att = r && r.data;
    const sum = attSummary(q, att);
    const out = { me: { name: s.name, cls: cls.label }, quiz: pubQuiz(q), status: qStatus(q), now: now(), att: sum };
    if (sum && !sum.done && qStatus(q) !== "closed") out.q = viewQ(q, att.tries[att.tries.length - 1], sum.answered);
    if (sum && sum.done) out.review = review(q, att.tries[att.tries.length - 1]);
    out.canStart = qStatus(q) === "open" && (!sum || sum.done && sum.tries < q.attempts);
    return out;
  }
  function review(q, tr) {
    const m = {};
    tr.ans.forEach((a) => {
      if (!a.ok && a.m) m[a.m] = (m[a.m] || 0) + 1;
    });
    return { mis: Object.entries(m).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ k, n, name: (q.mis[k] || {}).name || k, hint: (q.mis[k] || {}).hint || "" })) };
  }
  on("GET", /^\/q\/([a-z0-9]+)\/me$/, async ({ req, m }) => {
    const { q, s, cls } = await student(req, m[1]);
    return stateOf(q, s, cls);
  });
  on("POST", /^\/q\/([a-z0-9]+)\/start$/, async ({ req, m }) => {
    const { q, s, cls } = await student(req, m[1]);
    if (qStatus(q) === "soon") throw new HttpErr(403, "\u0644\u0645 \u062A\u0628\u062F\u0623 \u0627\u0644\u0645\u0633\u0627\u0628\u0642\u0629 \u0628\u0639\u062F.");
    if (qStatus(q) === "closed") throw new HttpErr(403, "\u0627\u0646\u062A\u0647\u0649 \u0648\u0642\u062A \u0627\u0644\u0645\u0633\u0627\u0628\u0642\u0629.");
    for (let k = 0; k < 4; k++) {
      const r = await loadAtt(q.id, s.sid);
      const att = r ? r.data : { sid: s.sid, cid: cls.id, name: s.name, clsLabel: cls.label, tries: [] };
      const cur = att.tries[att.tries.length - 1];
      if (cur && !tryDone(q, cur)) return stateOf(q, s, cls);
      if (att.tries.length >= q.attempts) throw new HttpErr(403, "\u0627\u0633\u062A\u0646\u0641\u062F\u062A \u0627\u0644\u0645\u062D\u0627\u0648\u0644\u0627\u062A \u0627\u0644\u0645\u0633\u0645\u0648\u062D\u0629.");
      if (cur && !cur.done) {
        cur.done = true;
        cur.end = Math.min(now(), cur.deadline);
      }
      const n = q.questions.length, t = now();
      att.name = s.name;
      att.clsLabel = cls.label;
      att.cid = cls.id;
      att.tries.push({ start: t, deadline: Math.min(q.limitSec ? t + q.limitSec * 1e3 : Infinity, q.closesAt), order: shuffle(range(n)), ch: [], ans: [], done: false });
      const tr = att.tries[att.tries.length - 1];
      tr.ch = tr.order.map((qi) => shuffle(range(q.questions[qi].choices.length)));
      if (await saveAtt(q.id, s.sid, att, r && r.etag)) {
        mem.boards.delete(q.id);
        return stateOf(q, s, cls);
      }
    }
    throw new HttpErr(409, "\u062D\u0627\u0648\u0644 \u0645\u0631\u0629 \u0623\u062E\u0631\u0649.");
  });
  on("POST", /^\/q\/([a-z0-9]+)\/answer$/, async ({ req, m, body }) => {
    const { q, s, cls } = await student(req, m[1]);
    for (let k = 0; k < 4; k++) {
      const r = await loadAtt(q.id, s.sid);
      if (!r) throw new HttpErr(409, "\u0627\u0628\u062F\u0623 \u0627\u0644\u0645\u0633\u0627\u0628\u0642\u0629 \u0623\u0648\u0644\u064B\u0627.");
      const att = r.data, tr = att.tries[att.tries.length - 1];
      if (tryDone(q, tr) || q.closedAt) {
        if (!tr.done) {
          tr.done = true;
          tr.end = Math.min(now(), tr.deadline);
          await saveAtt(q.id, s.sid, att, r.etag);
        }
        return Object.assign(await stateOf(q, s, cls), { timeout: true });
      }
      const i = +body.i, c = +body.c;
      if (i !== tr.ans.length) return Object.assign(await stateOf(q, s, cls), { stale: true });
      if (!Number.isInteger(c) || c < 0 || c >= tr.ch[i].length) throw new HttpErr(400, "\u0627\u062E\u062A\u064A\u0627\u0631 \u063A\u064A\u0631 \u0635\u0627\u0644\u062D.");
      const Q = q.questions[tr.order[i]], ch = Q.choices[tr.ch[i][c]];
      tr.ans.push({ c: tr.ch[i][c], ok: !!ch.ok, m: ch.ok ? null : ch.mis || null, t: now() });
      if (tr.ans.length >= tr.order.length) {
        tr.done = true;
        tr.end = now();
      }
      if (!await saveAtt(q.id, s.sid, att, r.etag)) continue;
      mem.boards.delete(q.id);
      const out = await stateOf(q, s, cls);
      out.last = { ok: !!ch.ok };
      if (q.reveal) out.last.correct = tr.ch[i].findIndex((x) => Q.choices[x].ok);
      return out;
    }
    throw new HttpErr(409, "\u062D\u0627\u0648\u0644 \u0645\u0631\u0629 \u0623\u062E\u0631\u0649.");
  });
  on("GET", /^\/q\/([a-z0-9]+)\/board$/, async ({ req, m }) => {
    const { q, s } = await student(req, m[1]);
    const rows = await board(q), me = rows.findIndex((r) => r.sid === s.sid);
    return { rows: rows.map(({ sid, el, ...r }) => Object.assign(r, sid === s.sid ? { me: true } : {})), rank: me + 1, total: rows.length, status: qStatus(q), now: now() };
  });
  on("GET", /^\/t\/status$/, async () => ({ claimed: !!await teacherCfg() }), "open");
  on("POST", /^\/t\/claim$/, async ({ body }) => {
    const key = String(body.key || "");
    if (key.length < 10) throw new HttpErr(400, "\u0627\u0644\u0633\u0631\u0651 \u0642\u0635\u064A\u0631: \u0661\u0660 \u0623\u062D\u0631\u0641 \u0639\u0644\u0649 \u0627\u0644\u0623\u0642\u0644.");
    const salt = randomBytes(16), es = randomBytes(16);
    const rec = { salt: salt.toString("hex"), es: es.toString("hex"), hash: scryptSync(key, salt, 32, { N: 16384, r: 8, p: 1 }).toString("hex"), t: now() };
    const r = await store.set("cfg/teacher", rec, { onlyIfNew: true });
    if (!r.modified) throw new HttpErr(409, "\u062A\u0645 \u0636\u0628\u0637 \u0633\u0631\u0651 \u0627\u0644\u0645\u0639\u0644\u0645 \u0645\u0633\u0628\u0642\u064B\u0627.");
    mem.teacher = rec;
    return { ok: true };
  }, "open");
  on("GET", /^\/t\/ping$/, async () => ({ ok: true, now: now() }), true);
  async function dropAcct(ah) {
    if (!ah) return;
    await Promise.all(["acct/", "rreq/", "rl/a/"].map((p) => store.del(p + ah)));
  }
  async function upsertClasses(list, ek) {
    const out = [], report = { created: 0, kept: 0, removed: 0, noRec: 0, dup: [] }, seen = /* @__PURE__ */ new Map();
    for (const c of list) {
      const cid = String(c.id || "").replace(/[^\w-]/g, "").slice(0, 40);
      if (!cid) continue;
      const label = normName(c.label) || cid;
      const old = await store.get("cls/" + cid) || { id: cid, students: [] };
      const byId = new Map(old.students.map((s) => [s.sid, s]));
      const incoming = (c.students || []).slice(0, MAX_STU).map((s) => ({ sid: String(s.sid || s.id || "").replace(/[^\w-]/g, "").slice(0, 40), name: normName(s.name), no: clampInt(s.no, 0, 999, 0), rec: s.rec === void 0 ? void 0 : normRec(s.rec) })).filter((s) => s.sid && s.name);
      const keep = new Set(incoming.map((s) => s.sid));
      for (const s of old.students) if (!keep.has(s.sid)) {
        if (s.ch) await store.del("code/" + s.ch);
        if (s.ah) {
          await dropAcct(s.ah);
          report.removed++;
        }
      }
      const students = [];
      for (const s of incoming) {
        const o = byId.get(s.sid) || {};
        if (o.ch) await store.del("code/" + o.ch);
        let ah = o.ah || null;
        if (s.rec !== void 0) {
          const nh = s.rec ? await accKey(s.rec) : null;
          if (nh && seen.has(nh)) {
            report.dup.push(s.name);
            if (ah === nh) ah = null;
          } else {
            if (ah && ah !== nh) {
              await dropAcct(ah);
              report.removed++;
              ah = null;
            }
            if (nh) {
              seen.set(nh, s.sid);
              ah = nh;
            }
          }
        }
        if (!ah) {
          report.noRec++;
          students.push({ sid: s.sid, name: s.name, no: s.no });
          continue;
        }
        const a = await store.get("acct/" + ah);
        if (a && a.sid !== s.sid && (await store.get("cls/" + a.cid) || { students: [] }).students.some((x) => x.sid === a.sid && x.ah === ah)) {
          report.dup.push(s.name);
          students.push({ sid: s.sid, name: s.name, no: s.no });
          continue;
        }
        if (a && a.sid === s.sid) {
          if (a.name !== s.name || a.cid !== cid || a.cls !== label) {
            Object.assign(a, { name: s.name, cid, cls: label });
            await store.set("acct/" + ah, a);
          }
          report.kept++;
        } else {
          const n = { sid: s.sid, cid, name: s.name, cls: label, re: enc(ek, s.rec), must: true, zero: true, tv: (a && a.tv || 0) + 1, created: now() };
          setPin(n, "0000", ah);
          await store.set("acct/" + ah, n);
          await store.del("rl/a/" + ah);
          report.created++;
        }
        students.push({ sid: s.sid, name: s.name, no: s.no, ah });
      }
      const rec = { id: cid, label, students, updated: now() };
      await store.set("cls/" + cid, rec);
      out.push({ id: cid, label, students: students.map((s) => ({ sid: s.sid, name: s.name, no: s.no, acct: !!s.ah })) });
    }
    return { classes: out, report };
  }
  on("PUT", /^\/t\/classes$/, async ({ body, ek }) => upsertClasses(Array.isArray(body.classes) ? body.classes.slice(0, MAX_CLASSES) : [], ek), true);
  on("PUT", /^\/t\/accounts$/, async ({ body, ek }) => upsertClasses(Array.isArray(body.classes) ? body.classes.slice(0, MAX_CLASSES) : [], ek), true);
  on("GET", /^\/t\/classes$/, async () => {
    const cs = (await Promise.all((await store.list("cls/")).map((k) => store.get(k)))).filter(Boolean);
    return { classes: cs.map((c) => ({ id: c.id, label: c.label, updated: c.updated, students: c.students.map((s) => ({ sid: s.sid, name: s.name, no: s.no, acct: !!s.ah })) })) };
  }, true);
  on("GET", /^\/t\/accounts$/, async ({ ek }) => {
    const cs = (await Promise.all((await store.list("cls/")).map((k) => store.get(k)))).filter(Boolean);
    const locks = /* @__PURE__ */ new Map();
    for (const k of await store.list("rl/a/")) {
      const r = await store.get(k);
      if (r && r.lock > now()) locks.set(k.slice(5), r.lock);
    }
    const reqs = new Set((await store.list("rreq/")).map((k) => k.slice(5)));
    const classes = await Promise.all(cs.map(async (c) => ({ id: c.id, label: c.label, students: await Promise.all(c.students.map(async (s) => {
      const a = s.ah && await store.get("acct/" + s.ah);
      if (!a) return { sid: s.sid, name: s.name, no: s.no, id: null };
      return { sid: s.sid, name: s.name, no: s.no, id: s.ah, rec: dec(ek, a.re), pin: !a.must ? "set" : a.tmp ? "tmp" : "zero", tmp: a.must && a.tmp ? dec(ek, a.tmp) : null, first: a.first || null, last: a.last || null, set: a.set || null, lock: locks.get(s.ah) || 0, req: reqs.has(s.ah) };
    })) })));
    return { classes, now: now() };
  }, true);
  async function teacherReset(id, zero, ek) {
    const ah = String(id || "").replace(/[^0-9a-f]/g, "").slice(0, 32), a = ah && await store.get("acct/" + ah);
    if (!a) throw new HttpErr(404, "\u0627\u0644\u062D\u0633\u0627\u0628 \u063A\u064A\u0631 \u0645\u0648\u062C\u0648\u062F \u0639\u0644\u0649 \u0627\u0644\u062E\u0627\u062F\u0645. \u0632\u0627\u0645\u0646 \u0627\u0644\u062D\u0633\u0627\u0628\u0627\u062A.");
    const pin = zero ? "0000" : newPin();
    setPin(a, pin, ah);
    a.must = true;
    a.tv = (a.tv || 0) + 1;
    if (zero) {
      a.zero = true;
      delete a.tmp;
    } else {
      a.tmp = enc(ek, pin);
      delete a.zero;
    }
    await store.set("acct/" + ah, a);
    await store.del("rreq/" + ah);
    await store.del("rl/a/" + ah);
    return { ok: true, id: ah, pin, name: a.name, cls: a.cls };
  }
  on("POST", /^\/t\/accounts\/reset$/, async ({ body, ek }) => teacherReset(body.id, !!body.zero, ek), true);
  on("POST", /^\/t\/accounts\/unlock$/, async ({ body }) => {
    const ah = String(body.id || "").replace(/[^0-9a-f]/g, "").slice(0, 32);
    if (ah) await store.del("rl/a/" + ah);
    return { ok: true };
  }, true);
  on("GET", /^\/t\/resets$/, async () => {
    const keys = await store.list("rreq/");
    const resets = (await Promise.all(keys.map(async (k) => {
      const ah = k.slice(5), r = await store.get(k), a = await store.get("acct/" + ah);
      if (!r || !a) {
        if (r) await store.del(k);
        return null;
      }
      return { id: ah, sid: a.sid, name: a.name, cls: a.cls, t: r.t };
    }))).filter(Boolean);
    return { resets: resets.sort((x, y) => x.t - y.t), now: now() };
  }, true);
  on("POST", /^\/t\/resets\/approve$/, async ({ body, ek }) => teacherReset(body.id, false, ek), true);
  on("POST", /^\/t\/resets\/reject$/, async ({ body }) => {
    const ah = String(body.id || "").replace(/[^0-9a-f]/g, "").slice(0, 32), a = ah && await store.get("acct/" + ah);
    if (a) {
      a.rjAt = now();
      await store.set("acct/" + ah, a);
    }
    if (ah) await store.del("rreq/" + ah);
    return { ok: true };
  }, true);
  on("DELETE", /^\/t\/classes\/([\w-]+)$/, async ({ m }) => {
    const cid = m[1], c = await store.get("cls/" + cid);
    if (!c) return { ok: true, removed: 0 };
    const sids = new Set(c.students.map((s) => s.sid));
    let removed = 0;
    await Promise.all(c.students.map(async (s) => {
      if (s.ch) await store.del("code/" + s.ch);
      await dropAcct(s.ah);
    }));
    for (const k of await store.list("quiz/")) {
      const q = await store.get(k);
      if (!q) continue;
      for (const ak of await store.list(`att/${q.id}/`)) if (sids.has(ak.split("/").pop())) {
        await store.del(ak);
        removed++;
      }
      if (q.classes.includes(cid)) {
        q.classes = q.classes.filter((x) => x !== cid);
        await store.set(k, q);
      }
    }
    mem.qlist = null;
    await store.del("cls/" + cid);
    return { ok: true, removed };
  }, true);
  on("POST", /^\/t\/quizzes$/, async ({ body }) => {
    const qs = Array.isArray(body.questions) ? body.questions.slice(0, MAX_Q) : [];
    const questions = qs.map((Q) => {
      const ch = (Q.choices || []).slice(0, MAX_CH).map((c) => ({ html: sanitize(c.html), ok: !!c.ok, mis: c.ok ? null : String(c.mis || "").slice(0, 40) || null }));
      if (ch.length < 2 || ch.filter((c) => c.ok).length !== 1) throw new HttpErr(400, "\u0633\u0624\u0627\u0644 \u063A\u064A\u0631 \u0635\u0627\u0644\u062D: \u064A\u062C\u0628 \u0623\u0646 \u064A\u0643\u0648\u0646 \u0644\u0647 \u0628\u062F\u064A\u0644 \u0635\u062D\u064A\u062D \u0648\u0627\u062D\u062F.");
      return { lesson: String(Q.lesson || "").slice(0, 10), prompt: sanitize(Q.prompt), ctx: sanitize(Q.ctx), small: !!Q.small, choices: ch, answer: sanitize(Q.answer) };
    });
    if (!questions.length) throw new HttpErr(400, "\u0644\u0627 \u062A\u0648\u062C\u062F \u0623\u0633\u0626\u0644\u0629.");
    const classes = (body.classes || []).map(String).slice(0, MAX_CLASSES);
    const ex = await Promise.all(classes.map((c) => store.get("cls/" + c)));
    if (!classes.length || ex.some((x) => !x)) throw new HttpErr(400, "\u0627\u0631\u0641\u0639 \u0627\u0644\u0641\u0635\u0648\u0644 \u0623\u0648\u0644\u064B\u0627.");
    const t = now(), opensAt = clampInt(body.opensAt, 0, 9e15, t), closesAt = clampInt(body.closesAt, opensAt + 6e4, opensAt + 60 * 864e5, opensAt + 864e5);
    const mis = {};
    Object.entries(body.mis || {}).slice(0, 200).forEach(([k, v]) => {
      mis[String(k).slice(0, 40)] = { name: normName(v && v.name), hint: sanitize(v && v.hint).slice(0, 2e3), lesson: String(v && v.lesson || "").slice(0, 10) };
    });
    const u = body.unit || {};
    const q = {
      id: rid(10),
      created: t,
      title: normName(body.title) || "\u0645\u0633\u0627\u0628\u0642\u0629",
      unit: { slug: String(u.slug || "").replace(/[^\w-]/g, "").slice(0, 30), title: normName(u.title), chapter: clampInt(u.chapter, 0, 99, 0), prefix: String(u.prefix || "").replace(/[^\w.-]/g, "").slice(0, 40) },
      lessons: (body.lessons || []).slice(0, 30).map((l) => ({ id: String(l.id || "").slice(0, 10), title: normName(l.title) })),
      classes,
      opensAt,
      closesAt,
      limitSec: clampInt(body.limitSec, 0, 6 * 3600, 0),
      attempts: clampInt(body.attempts, 1, 10, 1),
      reveal: !!body.reveal,
      digits: ["w", "e", "book"].includes(body.digits) ? body.digits : "e",
      questions,
      mis
    };
    await store.set("quiz/" + q.id, q, { onlyIfNew: true });
    mem.qlist = null;
    return { id: q.id };
  }, true);
  on("GET", /^\/t\/quizzes$/, async () => {
    const qs = (await Promise.all((await store.list("quiz/")).map((k) => store.get(k)))).filter(Boolean);
    const out = await Promise.all(qs.map(async (q) => ({ ...pubQuiz(q), classes: q.classes, created: q.created, status: qStatus(q), joined: (await store.list(`att/${q.id}/`)).length })));
    return { quizzes: out.sort((a, b) => b.created - a.created) };
  }, true);
  on("GET", /^\/t\/quizzes\/([a-z0-9]+)$/, async ({ m }) => {
    const q = await store.get("quiz/" + m[1]);
    if (!q) throw new HttpErr(404, "\u0627\u0644\u0645\u0633\u0627\u0628\u0642\u0629 \u063A\u064A\u0631 \u0645\u0648\u062C\u0648\u062F\u0629.");
    const classes = (await Promise.all(q.classes.map((c) => store.get("cls/" + c)))).filter(Boolean).map((c) => ({ id: c.id, label: c.label, students: c.students.map((s) => ({ sid: s.sid, name: s.name, no: s.no })) }));
    const atts = (await Promise.all((await store.list(`att/${q.id}/`)).map((k) => store.get(k)))).filter(Boolean).map((a) => {
      const s = attSummary(q, a);
      return { sid: a.sid, cid: a.cid, name: a.name, ...s, tries: a.tries.map((tr) => ({ start: tr.start, end: tr.end || null, done: tryDone(q, tr), score: tryScore(tr), ans: tr.ans.map((x, i) => ({ q: tr.order[i], ok: x.ok, m: x.m, t: x.t })) })) };
    });
    return { quiz: { ...q, status: qStatus(q) }, classes, attempts: atts, resets: (await store.list("rreq/")).length, now: now() };
  }, true);
  on("PATCH", /^\/t\/quizzes\/([a-z0-9]+)$/, async ({ m, body }) => {
    const q = await store.get("quiz/" + m[1]);
    if (!q) throw new HttpErr(404, "\u0627\u0644\u0645\u0633\u0627\u0628\u0642\u0629 \u063A\u064A\u0631 \u0645\u0648\u062C\u0648\u062F\u0629.");
    if (body.close) q.closedAt = now();
    if (body.reopen) delete q.closedAt;
    if (body.closesAt) q.closesAt = clampInt(body.closesAt, q.opensAt + 6e4, q.opensAt + 60 * 864e5, q.closesAt);
    if (body.attempts) q.attempts = clampInt(body.attempts, 1, 10, q.attempts);
    await store.set("quiz/" + q.id, q);
    mem.boards.delete(q.id);
    mem.qlist = null;
    return { ok: true, status: qStatus(q) };
  }, true);
  on("DELETE", /^\/t\/quizzes\/([a-z0-9]+)$/, async ({ m }) => {
    const keys = await store.list(`att/${m[1]}/`);
    await Promise.all(keys.map((k) => store.del(k)));
    await store.del("quiz/" + m[1]);
    mem.boards.delete(m[1]);
    mem.qlist = null;
    return { ok: true, removed: keys.length };
  }, true);
  on("DELETE", /^\/t\/quizzes\/([a-z0-9]+)\/attempts\/([\w-]+)$/, async ({ m }) => {
    await store.del(`att/${m[1]}/${m[2]}`);
    mem.boards.delete(m[1]);
    return { ok: true };
  }, true);
  const HDR = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex, nofollow, noarchive", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" };
  const CORS = { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type, x-teacher-key", "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS", "access-control-max-age": "86400" };
  return async function handle(req, ctx = {}) {
    const url = new URL(req.url), path = url.pathname.replace(/^\/(\.netlify\/functions\/api|api)/, "") || "/";
    const isT = path.startsWith("/t/"), hdr = isT ? { ...HDR, ...CORS } : HDR;
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: isT ? CORS : {} });
    try {
      const r = routes.find((r2) => r2.m === req.method && r2.re.test(path));
      if (!r) throw new HttpErr(404, "\u063A\u064A\u0631 \u0645\u0648\u062C\u0648\u062F");
      let body = {};
      if (req.method !== "GET" && req.method !== "DELETE") {
        const t = await req.text();
        if (t.length > 6e5) throw new HttpErr(413, "\u0627\u0644\u0637\u0644\u0628 \u0643\u0628\u064A\u0631");
        try {
          body = t ? JSON.parse(t) : {};
        } catch (e) {
          throw new HttpErr(400, "JSON \u063A\u064A\u0631 \u0635\u0627\u0644\u062D");
        }
      }
      const ip = ctx.ip || "0.0.0.0";
      let ek = null;
      if (r.teacher === true) {
        ek = await teacherAuth(req, ip);
        if (!ek) throw new HttpErr(401, await teacherCfg() ? "\u0633\u0631\u0651 \u0627\u0644\u0645\u0639\u0644\u0645 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D." : "\u0644\u0645 \u064A\u064F\u0636\u0628\u0637 \u0633\u0631\u0651 \u0627\u0644\u0645\u0639\u0644\u0645 \u0628\u0639\u062F.");
      }
      const out = await r.fn({ req, body, ip, ek, m: path.match(r.re) });
      return new Response(JSON.stringify(out), { status: 200, headers: hdr });
    } catch (e) {
      if (!(e instanceof HttpErr)) log("ERR", e && e.stack || e);
      const st = e instanceof HttpErr ? e.status : 500;
      return new Response(JSON.stringify({ error: e instanceof HttpErr ? e.message : "\u062E\u0637\u0623 \u0641\u064A \u0627\u0644\u062E\u0627\u062F\u0645", ...e instanceof HttpErr && e.extra || {} }), { status: st, headers: hdr });
    }
  };
}
var HttpErr = class extends Error {
  constructor(status, msg, extra) {
    super(msg);
    this.status = status;
    this.extra = extra;
  }
};

// ../rq-tools/node_modules/@netlify/runtime-utils/dist/main.js
var getString = (input) => typeof input === "string" ? input : JSON.stringify(input);
var base64Decode = globalThis.Buffer ? (input) => Buffer.from(input, "base64").toString() : (input) => atob(input);
var base64Encode = globalThis.Buffer ? (input) => Buffer.from(getString(input)).toString("base64") : (input) => btoa(getString(input));
var getEnvironment = () => {
  const { Deno, Netlify, process } = globalThis;
  return Netlify?.env ?? Deno?.env ?? {
    delete: (key) => delete process?.env[key],
    get: (key) => process?.env[key],
    has: (key) => Boolean(process?.env[key]),
    set: (key, value) => {
      if (process?.env) {
        process.env[key] = value;
      }
    },
    toObject: () => process?.env ?? {}
  };
};

// ../rq-tools/node_modules/@netlify/otel/dist/main.js
var GET_TRACER = "__netlify__getTracer";
var getTracer = (name, version) => {
  return globalThis[GET_TRACER]?.(name, version);
};
function withActiveSpan(tracer, name, optionsOrFn, contextOrFn, fn) {
  const func = typeof contextOrFn === "function" ? contextOrFn : typeof optionsOrFn === "function" ? optionsOrFn : fn;
  if (!func) {
    throw new Error("function to execute with active span is missing");
  }
  if (!tracer) {
    return func();
  }
  return tracer.withActiveSpan(name, optionsOrFn, contextOrFn, func);
}

// ../rq-tools/node_modules/@netlify/blobs/dist/chunk-QDL6ESI2.js
var getEnvironmentContext = () => {
  const context = globalThis.netlifyBlobsContext || getEnvironment().get("NETLIFY_BLOBS_CONTEXT");
  if (typeof context !== "string" || !context) {
    return {};
  }
  const data = base64Decode(context);
  try {
    return JSON.parse(data);
  } catch {
  }
  return {};
};
var MissingBlobsEnvironmentError = class extends Error {
  constructor(requiredProperties) {
    super(
      `The environment has not been configured to use Netlify Blobs. To use it manually, supply the following properties when creating a store: ${requiredProperties.join(
        ", "
      )}`
    );
    this.name = "MissingBlobsEnvironmentError";
  }
};
var BASE64_PREFIX = "b64;";
var METADATA_HEADER_INTERNAL = "x-amz-meta-user";
var METADATA_HEADER_EXTERNAL = "netlify-blobs-metadata";
var METADATA_MAX_SIZE = 2 * 1024;
var encodeMetadata = (metadata) => {
  if (!metadata) {
    return null;
  }
  const encodedObject = base64Encode(JSON.stringify(metadata));
  const payload = `b64;${encodedObject}`;
  if (METADATA_HEADER_EXTERNAL.length + payload.length > METADATA_MAX_SIZE) {
    throw new Error("Metadata object exceeds the maximum size");
  }
  return payload;
};
var decodeMetadata = (header) => {
  if (!header?.startsWith(BASE64_PREFIX)) {
    return {};
  }
  const encodedData = header.slice(BASE64_PREFIX.length);
  const decodedData = base64Decode(encodedData);
  const metadata = JSON.parse(decodedData);
  return metadata;
};
var getMetadataFromResponse = (response) => {
  if (!response.headers) {
    return {};
  }
  const value = response.headers.get(METADATA_HEADER_EXTERNAL) || response.headers.get(METADATA_HEADER_INTERNAL);
  try {
    return decodeMetadata(value);
  } catch {
    throw new Error(
      "An internal error occurred while trying to retrieve the metadata for an entry. Please try updating to the latest version of the Netlify Blobs client."
    );
  }
};
var NF_ERROR = "x-nf-error";
var NF_REQUEST_ID = "x-nf-request-id";
var DEPLOY_STORE_PREFIX = "deploy:";
var SITE_STORE_PREFIX = "site:";
var isDeniedWrite = (res, { method, storeName }) => (res.status === 401 || res.status === 403) && (method === "put" || method === "delete") && storeName !== void 0 && !storeName.startsWith(DEPLOY_STORE_PREFIX);
var blobsErrorMessage = (res, context, responseBody) => {
  let details = res.headers.get(NF_ERROR) || `${res.status} status code`;
  if (res.headers.has(NF_REQUEST_ID)) {
    details += `, ID: ${res.headers.get(NF_REQUEST_ID)}`;
  }
  if (isDeniedWrite(res, context)) {
    const storeName = context.storeName?.startsWith(SITE_STORE_PREFIX) ? context.storeName.slice(SITE_STORE_PREFIX.length) : context.storeName;
    const summary = `Netlify Blobs could not write to store '${storeName}' (${details}).`;
    if (context.edgeAccess) {
      return summary;
    }
    return `${summary} Builds and build plugins can only write to deploy-specific stores: use 'getDeployStore' instead of 'getStore', or pass a 'token' with write access to the store. If this code is not running in a build, check that the token and site ID are valid. See https://docs.netlify.com/build/data-and-storage/netlify-blobs/#deploy-specific-stores`;
  }
  let message = `Netlify Blobs has generated an internal error (${details})`;
  if (!res.headers.get(NF_ERROR) && responseBody) {
    message += `: ${responseBody}`;
  }
  return message;
};
var BlobsInternalError = class extends Error {
  constructor(res, context = {}, responseBody) {
    super(blobsErrorMessage(res, context, responseBody));
    this.name = "BlobsInternalError";
    this.status = res.status;
    this.responseBody = responseBody;
  }
};
var createBlobsInternalError = async (res, context = {}) => {
  const responseBody = await res.clone().text().catch(() => void 0);
  return new BlobsInternalError(res, context, responseBody);
};
var collectIterator = async (iterator) => {
  const result = [];
  for await (const item of iterator) {
    result.push(item);
  }
  return result;
};
function withSpan(span, name, fn) {
  if (span) return fn(span);
  return withActiveSpan(getTracer(), name, (span2) => {
    return fn(span2);
  });
}
var BlobsConsistencyError = class extends Error {
  constructor() {
    super(
      `Netlify Blobs has failed to perform a read using strong consistency because the environment has not been configured with a 'uncachedEdgeURL' property`
    );
    this.name = "BlobsConsistencyError";
  }
};
var REGION_AUTO = "auto";
var regions = {
  "us-east-1": true,
  "us-east-2": true,
  "eu-central-1": true,
  "ap-southeast-1": true,
  "ap-southeast-2": true
};
var isValidRegion = (input) => Object.keys(regions).includes(input);
var InvalidBlobsRegionError = class extends Error {
  constructor(region) {
    super(
      `${region} is not a supported Netlify Blobs region. Supported values are: ${Object.keys(regions).join(", ")}.`
    );
    this.name = "InvalidBlobsRegionError";
  }
};
var DEFAULT_RETRY_DELAY = getEnvironment().get("NODE_ENV") === "test" ? 1 : 5e3;
var MIN_RETRY_DELAY = 1e3;
var MAX_RETRY = 5;
var RATE_LIMIT_HEADER = "X-RateLimit-Reset";
var fetchAndRetry = async (fetch, url, options, attemptsLeft = MAX_RETRY, getRetryUrl) => {
  try {
    const res = await fetch(url, options);
    const isRetryable = res.status === 429 || res.status >= 500 || getRetryUrl !== void 0 && res.status === 403;
    if (attemptsLeft > 0 && isRetryable) {
      const delay = getDelay(res.headers.get(RATE_LIMIT_HEADER));
      await sleep(delay);
      const retryUrl = getRetryUrl ? await getRetryUrl() : url;
      return fetchAndRetry(fetch, retryUrl, options, attemptsLeft - 1, getRetryUrl);
    }
    return res;
  } catch (error) {
    if (attemptsLeft === 0) {
      throw error;
    }
    const delay = getDelay();
    await sleep(delay);
    const retryUrl = getRetryUrl ? await getRetryUrl() : url;
    return fetchAndRetry(fetch, retryUrl, options, attemptsLeft - 1, getRetryUrl);
  }
};
var getDelay = (rateLimitReset) => {
  if (!rateLimitReset) {
    return DEFAULT_RETRY_DELAY;
  }
  return Math.max(Number(rateLimitReset) * 1e3 - Date.now(), MIN_RETRY_DELAY);
};
var sleep = (ms) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});
var SIGNED_URL_ACCEPT_HEADER = "application/json;type=signed-url";
var Client = class {
  /**
   * Whether requests reach Blobs through the edge rather than the API. Only
   * runtime environments are given an edge URL.
   */
  get edgeAccess() {
    return this.edgeURL !== void 0;
  }
  constructor({ apiURL, consistency, edgeURL, fetch, region, siteID, token, uncachedEdgeURL }) {
    this.apiURL = apiURL;
    this.consistency = consistency ?? "eventual";
    this.edgeURL = edgeURL;
    this.fetch = fetch ?? globalThis.fetch;
    this.region = region;
    this.siteID = siteID;
    this.token = token;
    this.uncachedEdgeURL = uncachedEdgeURL;
    if (!this.fetch) {
      throw new Error(
        "Netlify Blobs could not find a `fetch` client in the global scope. You can either update your runtime to a version that includes `fetch` (like Node.js 18.0.0 or above), or you can supply your own implementation using the `fetch` property."
      );
    }
  }
  async getFinalRequest({
    consistency: opConsistency,
    key,
    metadata,
    method,
    parameters = {},
    storeName
  }) {
    const encodedMetadata = encodeMetadata(metadata);
    const consistency = opConsistency ?? this.consistency;
    let urlPath = `/${this.siteID}`;
    if (storeName) {
      urlPath += `/${storeName}`;
    }
    if (key) {
      urlPath += `/${key}`;
    }
    if (this.edgeURL) {
      if (consistency === "strong" && !this.uncachedEdgeURL) {
        throw new BlobsConsistencyError();
      }
      const headers = {
        authorization: `Bearer ${this.token}`
      };
      if (encodedMetadata) {
        headers[METADATA_HEADER_INTERNAL] = encodedMetadata;
      }
      if (this.region) {
        urlPath = `/region:${this.region}${urlPath}`;
      }
      const url2 = new URL(urlPath, consistency === "strong" ? this.uncachedEdgeURL : this.edgeURL);
      for (const key2 in parameters) {
        url2.searchParams.set(key2, parameters[key2]);
      }
      return {
        headers,
        url: url2.toString()
      };
    }
    const apiHeaders = { authorization: `Bearer ${this.token}` };
    const url = new URL(`/api/v1/blobs${urlPath}`, this.apiURL ?? "https://api.netlify.com");
    for (const key2 in parameters) {
      url.searchParams.set(key2, parameters[key2]);
    }
    if (this.region) {
      url.searchParams.set("region", this.region);
    }
    if (storeName === void 0 || key === void 0) {
      return {
        headers: apiHeaders,
        url: url.toString()
      };
    }
    if (encodedMetadata) {
      apiHeaders[METADATA_HEADER_EXTERNAL] = encodedMetadata;
    }
    if (method === "head" || method === "delete") {
      return {
        headers: apiHeaders,
        url: url.toString()
      };
    }
    const res = await this.fetch(url.toString(), {
      headers: { ...apiHeaders, accept: SIGNED_URL_ACCEPT_HEADER },
      method
    });
    if (res.status !== 200) {
      throw await createBlobsInternalError(res, { edgeAccess: this.edgeAccess, method, storeName });
    }
    const { url: signedURL } = await res.json();
    const userHeaders = encodedMetadata ? { [METADATA_HEADER_INTERNAL]: encodedMetadata } : void 0;
    return {
      headers: userHeaders,
      url: signedURL
    };
  }
  async makeRequest({
    body,
    conditions = {},
    consistency,
    headers: extraHeaders,
    key,
    metadata,
    method,
    parameters,
    storeName
  }) {
    const { headers: baseHeaders = {}, url } = await this.getFinalRequest({
      consistency,
      key,
      metadata,
      method,
      parameters,
      storeName
    });
    const headers = {
      ...baseHeaders,
      ...extraHeaders
    };
    if (method === "put") {
      headers["cache-control"] = "max-age=0, stale-while-revalidate=60";
    }
    if ("onlyIfMatch" in conditions && conditions.onlyIfMatch) {
      headers["if-match"] = conditions.onlyIfMatch;
    } else if ("onlyIfNew" in conditions && conditions.onlyIfNew) {
      headers["if-none-match"] = "*";
    }
    const options = {
      body,
      headers,
      method
    };
    if (body instanceof ReadableStream) {
      options.duplex = "half";
    }
    const usesSignedUrl = !this.edgeURL && key !== void 0 && storeName !== void 0 && method !== "head" && method !== "delete";
    let getRetryUrl;
    if (usesSignedUrl) {
      getRetryUrl = async () => {
        const finalRequest = await this.getFinalRequest({ consistency, key, metadata, method, parameters, storeName });
        return finalRequest.url;
      };
    }
    return fetchAndRetry(this.fetch, url, options, void 0, getRetryUrl);
  }
};
var getClientOptions = (options, contextOverride) => {
  const context = contextOverride ?? getEnvironmentContext();
  const siteID = context.siteID ?? options.siteID;
  const token = context.token ?? options.token;
  if (!siteID || !token) {
    throw new MissingBlobsEnvironmentError(["siteID", "token"]);
  }
  if (options.region !== void 0 && !isValidRegion(options.region)) {
    throw new InvalidBlobsRegionError(options.region);
  }
  const clientOptions = {
    apiURL: context.apiURL ?? options.apiURL,
    consistency: options.consistency,
    edgeURL: context.edgeURL ?? options.edgeURL,
    fetch: options.fetch,
    region: options.region,
    siteID,
    token,
    uncachedEdgeURL: context.uncachedEdgeURL ?? options.uncachedEdgeURL
  };
  return clientOptions;
};

// ../rq-tools/node_modules/@netlify/blobs/dist/main.js
var LEGACY_STORE_INTERNAL_PREFIX = "netlify-internal/legacy-namespace/";
var STATUS_OK = 200;
var STATUS_PRE_CONDITION_FAILED = 412;
var Store = class _Store {
  constructor(options) {
    this.client = options.client;
    if ("deployID" in options) {
      _Store.validateDeployID(options.deployID);
      let name = DEPLOY_STORE_PREFIX + options.deployID;
      if (options.name) {
        name += `:${options.name}`;
      }
      this.name = name;
    } else if (options.name.startsWith(LEGACY_STORE_INTERNAL_PREFIX)) {
      const storeName = options.name.slice(LEGACY_STORE_INTERNAL_PREFIX.length);
      _Store.validateStoreName(storeName);
      this.name = storeName;
    } else {
      _Store.validateStoreName(options.name);
      this.name = SITE_STORE_PREFIX + options.name;
    }
  }
  async delete(key) {
    const res = await this.client.makeRequest({ key, method: "delete", storeName: this.name });
    if (![200, 204, 404].includes(res.status)) {
      throw new BlobsInternalError(res, {
        edgeAccess: this.client.edgeAccess,
        method: "delete",
        storeName: this.name
      });
    }
  }
  async deleteAll() {
    let totalDeletedBlobs = 0;
    let hasMore = true;
    while (hasMore) {
      const res = await this.client.makeRequest({ method: "delete", storeName: this.name });
      if (res.status !== 200) {
        throw new BlobsInternalError(res, {
          edgeAccess: this.client.edgeAccess,
          method: "delete",
          storeName: this.name
        });
      }
      const data = await res.json();
      if (typeof data.blobs_deleted !== "number") {
        throw new BlobsInternalError(res);
      }
      totalDeletedBlobs += data.blobs_deleted;
      hasMore = typeof data.has_more === "boolean" && data.has_more;
    }
    return {
      deletedBlobs: totalDeletedBlobs
    };
  }
  async get(key, options) {
    return withSpan(options?.span, "blobs.get", async (span) => {
      const { consistency, type } = options ?? {};
      span?.setAttributes({
        "blobs.store": this.name,
        "blobs.key": key,
        "blobs.type": type,
        "blobs.method": "GET",
        "blobs.consistency": consistency
      });
      const res = await this.client.makeRequest({
        consistency,
        key,
        method: "get",
        storeName: this.name
      });
      span?.setAttributes({
        "blobs.response.body.size": res.headers.get("content-length") ?? void 0,
        "blobs.response.status": res.status
      });
      if (res.status === 404) {
        return null;
      }
      if (res.status !== 200) {
        throw new BlobsInternalError(res);
      }
      if (type === void 0 || type === "text") {
        return res.text();
      }
      if (type === "arrayBuffer") {
        return res.arrayBuffer();
      }
      if (type === "blob") {
        return res.blob();
      }
      if (type === "json") {
        return res.json();
      }
      if (type === "stream") {
        return res.body;
      }
      throw new BlobsInternalError(res);
    });
  }
  async getMetadata(key, options = {}) {
    return withSpan(options?.span, "blobs.getMetadata", async (span) => {
      span?.setAttributes({
        "blobs.store": this.name,
        "blobs.key": key,
        "blobs.method": "HEAD",
        "blobs.consistency": options.consistency
      });
      const res = await this.client.makeRequest({
        consistency: options.consistency,
        key,
        method: "head",
        storeName: this.name
      });
      span?.setAttributes({
        "blobs.response.status": res.status
      });
      if (res.status === 404) {
        return null;
      }
      if (res.status !== 200 && res.status !== 304) {
        throw new BlobsInternalError(res);
      }
      const etag = res?.headers.get("etag") ?? void 0;
      const metadata = getMetadataFromResponse(res);
      const result = {
        etag,
        metadata
      };
      return result;
    });
  }
  async getWithMetadata(key, options) {
    return withSpan(options?.span, "blobs.getWithMetadata", async (span) => {
      const { consistency, etag: requestETag, type } = options ?? {};
      const headers = requestETag ? { "if-none-match": requestETag } : void 0;
      span?.setAttributes({
        "blobs.store": this.name,
        "blobs.key": key,
        "blobs.method": "GET",
        "blobs.consistency": options?.consistency,
        "blobs.type": type,
        "blobs.request.etag": requestETag
      });
      const res = await this.client.makeRequest({
        consistency,
        headers,
        key,
        method: "get",
        storeName: this.name
      });
      const responseETag = res?.headers.get("etag") ?? void 0;
      span?.setAttributes({
        "blobs.response.body.size": res.headers.get("content-length") ?? void 0,
        "blobs.response.etag": responseETag,
        "blobs.response.status": res.status
      });
      if (res.status === 404) {
        return null;
      }
      if (res.status !== 200 && res.status !== 304) {
        throw new BlobsInternalError(res);
      }
      const metadata = getMetadataFromResponse(res);
      const result = {
        etag: responseETag,
        metadata
      };
      if (res.status === 304 && requestETag) {
        return { data: null, ...result };
      }
      if (type === void 0 || type === "text") {
        return { data: await res.text(), ...result };
      }
      if (type === "arrayBuffer") {
        return { data: await res.arrayBuffer(), ...result };
      }
      if (type === "blob") {
        return { data: await res.blob(), ...result };
      }
      if (type === "json") {
        return { data: await res.json(), ...result };
      }
      if (type === "stream") {
        return { data: res.body, ...result };
      }
      throw new Error(`Invalid 'type' property: ${type}. Expected: arrayBuffer, blob, json, stream, or text.`);
    });
  }
  list(options = {}) {
    return withSpan(options.span, "blobs.list", (span) => {
      span?.setAttributes({
        "blobs.store": this.name,
        "blobs.method": "GET",
        "blobs.list.paginate": options.paginate ?? false
      });
      const iterator = this.getListIterator(options);
      if (options.paginate) {
        return iterator;
      }
      return collectIterator(iterator).then(
        (items) => items.reduce(
          (acc, item) => ({
            blobs: [...acc.blobs, ...item.blobs],
            directories: [...acc.directories, ...item.directories]
          }),
          { blobs: [], directories: [] }
        )
      );
    });
  }
  async set(key, data, options = {}) {
    return withSpan(options.span, "blobs.set", async (span) => {
      span?.setAttributes({
        "blobs.store": this.name,
        "blobs.key": key,
        "blobs.method": "PUT",
        "blobs.data.size": typeof data == "string" ? data.length : data instanceof Blob ? data.size : data.byteLength,
        "blobs.data.type": typeof data == "string" ? "string" : data instanceof Blob ? "blob" : "arrayBuffer",
        "blobs.atomic": Boolean(options.onlyIfMatch ?? options.onlyIfNew)
      });
      _Store.validateKey(key);
      const conditions = _Store.getConditions(options);
      const res = await this.client.makeRequest({
        conditions,
        body: data,
        key,
        metadata: options.metadata,
        method: "put",
        storeName: this.name
      });
      const etag = res.headers.get("etag") ?? "";
      span?.setAttributes({
        "blobs.response.etag": etag,
        "blobs.response.status": res.status
      });
      if (conditions) {
        return res.status === STATUS_PRE_CONDITION_FAILED ? { modified: false } : { etag, modified: true };
      }
      if (res.status === STATUS_OK) {
        return {
          etag,
          modified: true
        };
      }
      throw await createBlobsInternalError(res, {
        edgeAccess: this.client.edgeAccess,
        method: "put",
        storeName: this.name
      });
    });
  }
  async setJSON(key, data, options = {}) {
    return withSpan(options.span, "blobs.setJSON", async (span) => {
      span?.setAttributes({
        "blobs.store": this.name,
        "blobs.key": key,
        "blobs.method": "PUT",
        "blobs.data.type": "json",
        "blobs.atomic": Boolean(options.onlyIfMatch ?? options.onlyIfNew)
      });
      _Store.validateKey(key);
      const conditions = _Store.getConditions(options);
      const payload = JSON.stringify(data);
      const headers = {
        "content-type": "application/json"
      };
      const res = await this.client.makeRequest({
        conditions,
        body: payload,
        headers,
        key,
        metadata: options.metadata,
        method: "put",
        storeName: this.name
      });
      const etag = res.headers.get("etag") ?? "";
      span?.setAttributes({
        "blobs.response.etag": etag,
        "blobs.response.status": res.status
      });
      if (conditions) {
        return res.status === STATUS_PRE_CONDITION_FAILED ? { modified: false } : { etag, modified: true };
      }
      if (res.status === STATUS_OK) {
        return {
          etag,
          modified: true
        };
      }
      throw new BlobsInternalError(res, {
        edgeAccess: this.client.edgeAccess,
        method: "put",
        storeName: this.name
      });
    });
  }
  static formatListResultBlob(result) {
    if (!result.key) {
      return null;
    }
    return {
      etag: result.etag,
      key: result.key
    };
  }
  static getConditions(options) {
    if ("onlyIfMatch" in options && "onlyIfNew" in options) {
      throw new Error(
        `The 'onlyIfMatch' and 'onlyIfNew' options are mutually exclusive. Using 'onlyIfMatch' will make the write succeed only if there is an entry for the key with the given content, while 'onlyIfNew' will make the write succeed only if there is no entry for the key.`
      );
    }
    if ("onlyIfMatch" in options && options.onlyIfMatch) {
      if (typeof options.onlyIfMatch !== "string") {
        throw new Error(`The 'onlyIfMatch' property expects a string representing an ETag.`);
      }
      return {
        onlyIfMatch: options.onlyIfMatch
      };
    }
    if ("onlyIfNew" in options && options.onlyIfNew) {
      if (typeof options.onlyIfNew !== "boolean") {
        throw new Error(
          `The 'onlyIfNew' property expects a boolean indicating whether the write should fail if an entry for the key already exists.`
        );
      }
      return {
        onlyIfNew: true
      };
    }
  }
  static validateKey(key) {
    if (key === "") {
      throw new Error("Blob key must not be empty.");
    }
    if (key.startsWith("/") || key.startsWith("%2F")) {
      throw new Error("Blob key must not start with forward slash (/).");
    }
    if (new TextEncoder().encode(key).length > 600) {
      throw new Error(
        "Blob key must be a sequence of Unicode characters whose UTF-8 encoding is at most 600 bytes long."
      );
    }
  }
  static validateDeployID(deployID) {
    if (!/^\w{1,24}$/.test(deployID)) {
      throw new Error(`'${deployID}' is not a valid Netlify deploy ID.`);
    }
  }
  static validateStoreName(name) {
    if (name.includes("/") || name.includes("%2F")) {
      throw new Error("Store name must not contain forward slashes (/).");
    }
    if (new TextEncoder().encode(name).length > 64) {
      throw new Error(
        "Store name must be a sequence of Unicode characters whose UTF-8 encoding is at most 64 bytes long."
      );
    }
  }
  getListIterator(options) {
    const { client, name: storeName } = this;
    const parameters = {};
    if (options?.prefix) {
      parameters.prefix = options.prefix;
    }
    if (options?.directories) {
      parameters.directories = "true";
    }
    return {
      [Symbol.asyncIterator]() {
        let currentCursor = null;
        let done = false;
        return {
          async next() {
            return withSpan(options?.span, "blobs.list.next", async (span) => {
              span?.setAttributes({
                "blobs.store": storeName,
                "blobs.method": "GET",
                "blobs.list.paginate": options?.paginate ?? false,
                "blobs.list.done": done,
                "blobs.list.cursor": currentCursor ?? void 0
              });
              if (done) {
                return { done: true, value: void 0 };
              }
              const nextParameters = { ...parameters };
              if (currentCursor !== null) {
                nextParameters.cursor = currentCursor;
              }
              const res = await client.makeRequest({
                method: "get",
                parameters: nextParameters,
                storeName
              });
              span?.setAttributes({
                "blobs.response.status": res.status
              });
              let blobs = [];
              let directories = [];
              if (![200, 204, 404].includes(res.status)) {
                throw new BlobsInternalError(res);
              }
              if (res.status === 404) {
                done = true;
              } else {
                const page = await res.json();
                if (page.next_cursor) {
                  currentCursor = page.next_cursor;
                } else {
                  done = true;
                }
                blobs = (page.blobs ?? []).map(_Store.formatListResultBlob).filter(Boolean);
                directories = page.directories ?? [];
              }
              return {
                done: false,
                value: {
                  blobs,
                  directories
                }
              };
            });
          }
        };
      }
    };
  }
};
var getDeployStoreRegion = (clientOptions, context) => {
  if (clientOptions.region) {
    return clientOptions.region;
  }
  if (clientOptions.edgeURL || clientOptions.uncachedEdgeURL) {
    if (!context.primaryRegion) {
      throw new Error(
        "When accessing a deploy store, the Netlify Blobs client needs to be configured with a region, and one was not found in the environment. To manually set the region, set the `region` property in the store options. If you are using the Netlify CLI, you may have an outdated version; run `npm install -g netlify-cli@latest` to update and try again."
      );
    }
    return context.primaryRegion;
  }
  return REGION_AUTO;
};
var getStore = (input, options) => {
  if (typeof input === "string") {
    const contextOverride = options?.siteID && options?.token ? { siteID: options?.siteID, token: options?.token } : void 0;
    const clientOptions = getClientOptions(options ?? {}, contextOverride);
    const client = new Client(clientOptions);
    return new Store({ client, name: input });
  }
  if (typeof input?.name === "string") {
    const { name } = input;
    const contextOverride = input?.siteID && input?.token ? { siteID: input?.siteID, token: input?.token } : void 0;
    const clientOptions = getClientOptions(input, contextOverride);
    if (!name) {
      throw new MissingBlobsEnvironmentError(["name"]);
    }
    const client = new Client(clientOptions);
    return new Store({ client, name });
  }
  if (typeof input?.deployID === "string") {
    const context = getEnvironmentContext();
    const clientOptions = getClientOptions(input, context);
    const { deployID } = input;
    if (!deployID) {
      throw new MissingBlobsEnvironmentError(["deployID"]);
    }
    clientOptions.region = getDeployStoreRegion(clientOptions, context);
    const client = new Client(clientOptions);
    return new Store({ client, deployID });
  }
  throw new Error(
    "The `getStore` method requires the name of the store as a string or as the `name` property of an options object"
  );
};

// src/store-blobs.mjs
function blobsStore(name = "remote-quiz") {
  const S = () => getStore({ name, consistency: "strong" });
  return {
    get: (k) => S().get(k, { type: "json" }),
    async getWithEtag(k) {
      const s = S();
      const r = await s.getWithMetadata(k, { type: "json" });
      if (!r || r.data == null) return null;
      if (r.etag) return { data: r.data, etag: r.etag };
      const { blobs } = await s.list({ prefix: k });
      const b = blobs.find((x) => x.key === k);
      const again = await s.get(k, { type: "json" });
      return again == null ? null : { data: again, etag: b && b.etag };
    },
    async set(k, v, o = {}) {
      const opt = {};
      if (o.onlyIfNew) opt.onlyIfNew = true;
      if (o.onlyIfMatch) opt.onlyIfMatch = o.onlyIfMatch;
      const r = await S().setJSON(k, v, opt);
      return { modified: !r || r.modified !== false };
    },
    del: (k) => S().delete(k),
    async list(prefix) {
      const { blobs } = await S().list({ prefix });
      return blobs.map((b) => b.key);
    }
  };
}
export {
  blobsStore,
  createApp
};

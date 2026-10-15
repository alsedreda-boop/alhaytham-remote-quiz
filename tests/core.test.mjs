/* اختبار منطق الخادم مباشرة (مخزن في الذاكرة) */
import { createApp } from '../src/core.mjs';
import { memoryStore } from '../src/store-memory.mjs';
// RQ_STORE=blobs: نفس الاختبارات على مُحوِّل Netlify Blobs الفعلي (من الحزمة المنشورة lib/rq-server.mjs) مقابل خادم Blobs المحلي الرسمي
let store, blobsSrv;
if (process.env.RQ_STORE === 'blobs') {
  const { createRequire } = await import('node:module'); // الحزمة من node_modules للمشروع أو من RQ_TOOLS
  const { BlobsServer } = createRequire((process.env.RQ_TOOLS || process.cwd()) + '/x.js')('@netlify/blobs/server');
  const os = await import('node:os'), fs = await import('node:fs');
  blobsSrv = new BlobsServer({ directory: fs.mkdtempSync(os.tmpdir() + '/rq-blobs-'), token: 'local-token' });
  const { port } = await blobsSrv.start(); const u = 'http://localhost:' + port;
  process.env.NETLIFY_BLOBS_CONTEXT = Buffer.from(JSON.stringify({ edgeURL: u, uncachedEdgeURL: u, siteID: 'local-site', token: 'local-token' })).toString('base64');
  store = (await import('../lib/rq-server.mjs')).blobsStore(); console.log('store: Netlify Blobs (local BlobsServer ' + u + ')');
} else store = memoryStore();
let T = Date.now(); const app = createApp({ store, now: () => T });
let pass = 0, failN = 0; const ok = (n, c, x = '') => { if (c) pass++; else failN++; console.log((c ? 'PASS ' : 'FAIL ') + n, c ? '' : x); };
const call = async (m, p, body, h = {}, ip = '1.1.1.1') => { const r = await app(new Request('http://x/api' + p, { method: m, headers: { 'content-type': 'application/json', ...h }, body: body ? JSON.stringify(body) : undefined }), { ip }); return { s: r.status, j: await r.json(), h: r.headers }; };
const K = { 'x-teacher-key': 'teacher-secret-123' };
ok('status unclaimed', (await call('GET', '/t/status')).j.claimed === false);
ok('ping before claim 401', (await call('GET', '/t/ping', null, K)).s === 401);
ok('short secret rejected', (await call('POST', '/t/claim', { key: 'short' })).s === 400);
ok('claim', (await call('POST', '/t/claim', { key: K['x-teacher-key'] })).j.ok);
ok('second claim 409', (await call('POST', '/t/claim', { key: 'another-secret-xyz' })).s === 409);
ok('wrong key 401', (await call('GET', '/t/ping', null, { 'x-teacher-key': 'wrong-secret-000' })).s === 401);
ok('ping ok', (await call('GET', '/t/ping', null, K)).j.ok);
const stu = Array.from({ length: 5 }, (_, i) => ({ sid: 'sid-' + i, name: 'طالب ' + i, no: i + 1, rec: String(1100000000 + i) }));
const REC = i => String(1100000000 + i), X9REC = '2200000009';
// ترحيل: بيانات النسخة السابقة (رموز ٨ خانات) تبقى صالحة للمسابقات وتُنظَّف رموزها عند المزامنة
await store.set('cls/c1', { id: 'c1', label: 'أول 1', students: [{ sid: 'sid-0', name: 'طالب 0', no: 1, ch: 'oldhash', ce: 'oldenc' }] }); await store.set('code/oldhash', { cid: 'c1', sid: 'sid-0' });
let r = await call('PUT', '/t/accounts', { classes: [{ id: 'c1', label: 'أول 1', students: stu }, { id: 'c2', label: 'أول 2', students: [{ sid: 'x9', name: 'آخر', no: 1, rec: X9REC }, { sid: 'x8', name: 'بلا رقم', no: 2 }] }] }, K);
ok('accounts synced (6 created, 1 without record no)', r.s === 200 && r.j.classes.length === 2 && r.j.report.created === 6 && r.j.report.noRec === 1, JSON.stringify(r.j.report));
const raw0 = JSON.stringify([...(await Promise.all((await store.list('')).map(k => store.get(k))))]);
ok('migration: old code index removed, class entry has account', !(await store.get('code/oldhash')) && (await store.get('cls/c1')).students.every(s => s.ah && !s.ch && !s.ce));
ok('no plaintext record number stored', !raw0.includes(REC(0)) && !raw0.includes(X9REC));
ok('teacher secret blob untouched by sync', !!(await store.get('cfg/teacher')) && (await store.get('cfg/teacher')).hash);
r = await call('PUT', '/t/accounts', { classes: [{ id: 'c1', label: 'أول 1', students: stu }] }, K);
ok('re-sync keeps accounts', r.j.report.kept === 5 && r.j.report.created === 0, JSON.stringify(r.j.report));
r = await call('PUT', '/t/classes', { classes: [{ id: 'c1', label: 'أول 1', students: stu.map(({ rec, ...s }) => s) }] }, K);
ok('lab upload without record nos keeps accounts', r.j.classes[0].students.every(s => s.acct), JSON.stringify(r.j.classes[0].students));
r = await call('PUT', '/t/accounts', { classes: [{ id: 'c3', label: 'أول 3', students: [{ sid: 'd1', name: 'مكرر', no: 1, rec: REC(1) }] }] }, K);
ok('duplicate record no (other student) rejected', r.j.report.dup.length === 1 && r.j.report.created === 0, JSON.stringify(r.j.report));
await call('DELETE', '/t/classes/c3', null, K);
let acc = (await call('GET', '/t/accounts', null, K)).j;
const A0 = acc.classes.find(c => c.id === 'c1').students.find(s => s.sid === 'sid-0');
ok('teacher accounts view: rec decrypted, pin=zero', A0.rec === REC(0) && A0.pin === 'zero' && !A0.first && A0.id, JSON.stringify(A0));
const login = (rec, pin, ip = '1.1.1.1') => call('POST', '/login', { rec, pin }, {}, ip);
// أول دخول بـ ٠٠٠٠ ← تغيير إجباري
r = await login('١١٠٠٠٠٠٠٠٠', '٠٠٠٠'); ok('first login 0000 (Arabic-Indic digits) → must change', r.s === 200 && r.j.must === true && r.j.name === 'طالب 0', JSON.stringify(r.j));
let M = { authorization: 'Bearer ' + r.j.token };
r = await call('GET', '/quizzes', null, M); ok('must-change token blocked elsewhere (403 must)', r.s === 403 && r.j.must === true, JSON.stringify(r.j));
ok('new PIN 0000 rejected', (await call('POST', '/pin', { pin: '0000' }, M)).s === 400);
ok('new PIN 3 digits rejected', (await call('POST', '/pin', { pin: '123' }, M)).s === 400);
r = await call('POST', '/pin', { pin: '٤٨٢١' }, M); ok('PIN changed', r.s === 200 && r.j.must === false && r.j.token, JSON.stringify(r.j));
let A = { authorization: 'Bearer ' + r.j.token };
ok('old (must) token dead after change', (await call('POST', '/pin', { pin: '5555' }, M)).s === 401);
ok('0000 no longer works', (await login(REC(0), '0000', '1.1.1.2')).s === 401);
r = await login(REC(0), '4821', '1.1.1.2'); ok('login with own PIN', r.s === 200 && r.j.must === false);
acc = (await call('GET', '/t/accounts', null, K)).j; ok('teacher sees PIN set + first login', (s => s.pin === 'set' && s.first && s.set)(acc.classes[0].students.find(s => s.sid === 'sid-0') || acc.classes[1].students.find(s => s.sid === 'sid-0')));
// رسائل عامة: الرقم غير الموجود والرقم السري الخاطئ نفس الرسالة
const e1 = await login('1999999999', '1234', '1.1.1.3'), e2 = await login(REC(0), '9999', '1.1.1.3');
ok('generic error (unknown rec == wrong PIN)', e1.s === 401 && e2.s === 401 && e1.j.error === e2.j.error, e1.j.error + ' | ' + e2.j.error);
// حدّ عنوان IP (الموجود سابقًا)
for (let i = 0; i < 14; i++) await login('1999999' + String(100 + i), '1111', '9.9.9.9');
r = await login('1999999888', '1111', '9.9.9.9'); ok('per-IP limit: 15th wrong → 429', r.s === 429, r.s);
ok('right PIN blocked while IP limited', (await login(REC(0), '4821', '9.9.9.9')).s === 429);
// قفل الحساب: ١٠ أخطاء من عناوين مختلفة ← ٥ دقائق
await login(REC(1), '0000', '2.0.0.1').then(async x => { const t = { authorization: 'Bearer ' + x.j.token }; await call('POST', '/pin', { pin: '2468' }, t); });
for (let i = 0; i < 9; i++) await login(REC(1), String(1000 + i), '2.0.1.' + i);
r = await login(REC(1), '1111', '2.0.2.1'); ok('10th wrong PIN → account locked (429)', r.s === 429, JSON.stringify(r.j));
ok('right PIN refused while locked', (await login(REC(1), '2468', '2.0.2.2')).s === 429);
for (let i = 0; i < 10; i++) await login('1888888888', String(2000 + i), '2.0.3.' + i);
ok('unknown rec locks the same way (no existence leak)', (await login('1888888888', '0000', '2.0.4.1')).s === 429);
acc = (await call('GET', '/t/accounts', null, K)).j; const L1 = acc.classes.flatMap(c => c.students).find(s => s.sid === 'sid-1');
ok('teacher sees lock', L1.lock > T, JSON.stringify(L1));
ok('teacher unlock', (await call('POST', '/t/accounts/unlock', { id: L1.id }, K)).j.ok && (await login(REC(1), '2468', '2.0.5.1')).s === 200);
T += 5 * 60e3 + 1000; ok('lock expires after 5 min', (await login('1888888888', '0000', '2.0.6.1')).s === 401);
// نسيت الرقم السري ← موافقة المعلم ← رقم مؤقت ← تغيير إجباري
const f1 = await call('POST', '/forgot', { rec: REC(2) }, {}, '3.0.0.1'), f2 = await call('POST', '/forgot', { rec: '1777777777' }, {}, '3.0.0.1');
ok('forgot: same generic reply for known/unknown', f1.s === 200 && f2.s === 200 && JSON.stringify(f1.j) === JSON.stringify(f2.j));
for (let i = 0; i < 3; i++) await call('POST', '/forgot', { rec: REC(2) }, {}, '3.0.1.' + i);
r = await call('GET', '/t/resets', null, K); ok('teacher sees exactly 1 request (no spam)', r.j.resets.length === 1 && r.j.resets[0].name === 'طالب 2' && r.j.resets[0].cls === 'أول 1', JSON.stringify(r.j));
const rid2 = r.j.resets[0].id;
const st2 = (await call('GET', '/t/quizzes', null, K)).j; // (يعمل قبل وجود مسابقات)
r = await call('POST', '/t/resets/approve', { id: rid2 }, K); ok('approve → random temp PIN (4 digits, not 0000)', /^\d{4}$/.test(r.j.pin) && r.j.pin !== '0000' && r.j.name === 'طالب 2', JSON.stringify(r.j));
const tmp2 = r.j.pin;
ok('request cleared', (await call('GET', '/t/resets', null, K)).j.resets.length === 0);
acc = (await call('GET', '/t/accounts', null, K)).j; ok('accounts view shows temp PIN', (s => s.pin === 'tmp' && s.tmp === tmp2)(acc.classes.flatMap(c => c.students).find(s => s.sid === 'sid-2')));
ok('temp PIN not stored in plaintext', !JSON.stringify(await store.get('acct/' + rid2)).includes('"' + tmp2 + '"'));
r = await login(REC(2), tmp2, '3.0.2.1'); ok('temp PIN login → must change', r.s === 200 && r.j.must);
M = { authorization: 'Bearer ' + r.j.token };
ok('cannot keep the temp PIN', (await call('POST', '/pin', { pin: tmp2 }, M)).s === 400);
ok('change after temp', (await call('POST', '/pin', { pin: '1357' }, M)).j.must === false);
await call('POST', '/forgot', { rec: REC(3) }, {}, '3.0.3.1');
ok('reject request', (await call('POST', '/t/resets/reject', { id: (await call('GET', '/t/resets', null, K)).j.resets[0].id }, K)).j.ok && (await call('GET', '/t/resets', null, K)).j.resets.length === 0);
await call('POST', '/forgot', { rec: REC(3) }, {}, '3.0.3.2'); ok('cool-down after reject (no re-spam)', (await call('GET', '/t/resets', null, K)).j.resets.length === 0);
const fz = []; for (let i = 0; i < 12; i++) fz.push((await call('POST', '/forgot', { rec: REC(4) }, {}, '3.3.3.3')).s); ok('forgot per-IP limit', fz.includes(429), JSON.stringify(fz));
// إعادة ضبط استباقية إلى ٠٠٠٠
const id4 = acc.classes.flatMap(c => c.students).find(s => s.sid === 'sid-4').id;
r = await call('POST', '/t/accounts/reset', { id: id4, zero: true }, K); ok('teacher reset to 0000', r.j.pin === '0000' && (await login(REC(4), '0000', '3.0.4.1')).j.must === true);
const Q = i => ({ lesson: '1-3', prompt: `<bdi class="num">س${i}</bdi><script>alert(1)</script><img src=x onerror="alert(2)">`, choices: [{ html: 'A' + i, ok: true }, { html: 'B' + i, ok: false, mis: 'ops_ltr' }, { html: 'C' + i, ok: false, mis: 'ops_paren' }, { html: 'D' + i, ok: false, mis: 'ops_ltr' }] });
r = await call('POST', '/t/quizzes', { title: 'تجربة', unit: { slug: 'algebra', title: 'الجبر', chapter: 1, prefix: 'haytham.alg.te.' }, lessons: [{ id: '1-3', title: 'ترتيب' }], classes: ['c1'], opensAt: T - 1000, closesAt: T + 3600e3, limitSec: 600, attempts: 1, questions: [0, 1, 2, 3].map(Q), mis: { ops_ltr: { name: 'خطأ ١', hint: 'تلميح' } } }, K);
ok('quiz created', r.s === 200 && r.j.id, JSON.stringify(r.j)); const qid = r.j.id;
const qrec = await store.get('quiz/' + qid); ok('sanitized', !/script|onerror/.test(JSON.stringify(qrec.questions)), qrec.questions[0].prompt);
// قائمة مسابقات الطالب حسب فصله
r = await call('GET', '/quizzes', null, A); ok('student quiz list shows class quiz', r.s === 200 && r.j.quizzes.length === 1 && r.j.quizzes[0].id === qid && r.j.quizzes[0].status === 'open' && r.j.me.name === 'طالب 0', JSON.stringify(r.j).slice(0, 200));
let XA; { const x = await login(X9REC, '0000', '4.0.0.1'); XA = { authorization: 'Bearer ' + (await call('POST', '/pin', { pin: '9090' }, { authorization: 'Bearer ' + x.j.token })).j.token }; }
ok('other class: quiz not listed', (await call('GET', '/quizzes', null, XA)).j.quizzes.length === 0);
ok('other class: quiz → 403', (await call('GET', `/q/${qid}/me`, null, XA)).s === 403);
ok('student without record no has no account', (await call('GET', '/t/accounts', null, K)).j.classes.flatMap(c => c.students).find(s => s.sid === 'x8').id === null);
const P = p => `/q/${qid}${p}`, tok = A.authorization.slice(7);
r = await call('GET', P('/me'), null, A); ok('me before start', r.j.canStart && !r.j.q && r.j.me.name === 'طالب 0', JSON.stringify(r.j).slice(0, 200));
ok('forged token 401', (await call('GET', P('/me'), null, { authorization: 'Bearer ' + tok.slice(0, -2) + 'xx' })).s === 401);
r = await call('POST', P('/start'), {}, A); ok('start gives q0', r.j.q && r.j.q.i === 0 && r.j.q.choices.length === 4, JSON.stringify(r.j).slice(0, 300));
ok('no answers leaked', !/"ok"|"mis"/.test(JSON.stringify(r.j.q)));
// أجب: صحيح، خطأ، صحيح، خطأ
let score = 0;
for (let i = 0; i < 4; i++) {
  const ch = r.j.q.choices; const want = i % 2 === 0 ? ch.findIndex(h => h.startsWith('A')) : ch.findIndex(h => h.startsWith('B'));
  r = await call('POST', P('/answer'), { i, c: want }, A); if (i % 2 === 0) score++;
  ok('answer ' + i + ' scored ' + (i % 2 === 0), r.j.last && r.j.last.ok === (i % 2 === 0), JSON.stringify(r.j).slice(0, 200));
}
ok('done with score 2', r.j.att.done && r.j.att.score === 2);
ok('review lists ops_ltr', r.j.review.mis[0].k === 'ops_ltr' && r.j.review.mis[0].n === 2);
ok('replay answer ignored', (await call('POST', P('/answer'), { i: 1, c: 0 }, A)).j.att.score === 2);
ok('no 2nd attempt', (await call('POST', P('/start'), {}, A)).s === 403);
// طالب ثانٍ ولوحة الترتيب
const t2 = (await login(REC(1), '2468', '1.2.3.4')).j.token, A2 = { authorization: 'Bearer ' + t2 };
r = await call('POST', P('/start'), {}, A2); r = await call('POST', P('/answer'), { i: 0, c: r.j.q.choices.findIndex(h => h.startsWith('A')) }, A2);
// نقرات متزامنة على الإجابة نفسها (هاتف بطيء/نقر مزدوج): تُحتسب مرة واحدة فقط
const dup = await Promise.all(Array.from({ length: 6 }, () => call('POST', P('/answer'), { i: 1, c: 0 }, A2)));
const a2 = await store.get(`att/${qid}/sid-1`);
ok('concurrent double-taps counted once', a2 && a2.tries.at(-1).ans.length === 2 && dup.some(d => d.s === 200), JSON.stringify(dup.map(d => d.s)) + ' ' + JSON.stringify(a2 && a2.tries.at(-1).ans));
T += 4000;
r = await call('GET', P('/board'), null, A2); ok('board 2 rows, rank', r.j.total === 2 && r.j.rows[0].name === 'طالب 0' && r.j.rank === 2 && r.j.rows[1].me, JSON.stringify(r.j));
ok('board hides sid', !JSON.stringify(r.j).includes('sid-'));
// المهلة
T += 700e3; r = await call('POST', P('/answer'), { i: 2, c: 0 }, A2); ok('timeout after limit', r.j.timeout && r.j.att.done, JSON.stringify(r.j).slice(0, 200));
// المعلم
r = await call('GET', '/t/quizzes/' + qid, null, K); ok('teacher detail', r.j.attempts.length === 2 && r.j.classes[0].students.length === 5 && r.j.quiz.questions[0].choices[0].ok === true);
const t2b = (await login(REC(2), '1357', '5.5.5.5')).j.token;
r = await call('POST', '/t/accounts/reset', { id: rid2 }, K); ok('teacher reset → new temp PIN', /^\d{4}$/.test(r.j.pin) && r.j.pin !== '0000');
ok('old PIN dead after reset', (await login(REC(2), '1357', '3.3.3.4')).s === 401);
ok('old session invalid after reset', (await call('GET', P('/me'), null, { authorization: 'Bearer ' + t2b })).s === 401);
ok('temp PIN works (must change)', (await login(REC(2), r.j.pin, '3.3.3.4')).j.must === true);
ok('reset attempt', (await call('DELETE', `/t/quizzes/${qid}/attempts/sid-0`, null, K)).j.ok && (await call('GET', P('/me'), null, A)).j.att === null);
ok('cors on teacher', (await call('GET', '/t/ping', null, K)).h.get('access-control-allow-origin') === '*');
ok('no cors on student', (await call('GET', P('/me'), null, A)).h.get('access-control-allow-origin') === null);
// وحدة مستقبلية (لا يعرفها الخادم): الخادم لا يحوي أي وحدة/درس مُدمَج — المختبر يرسل الأسئلة وخريطة الأخطاء
{ const fq = await call('POST', '/t/quizzes', { title: 'وحدة مستقبلية', unit: { slug: 'geometry', title: 'الهندسة', chapter: 5, prefix: 'haytham.geo.te.' }, lessons: [{ id: '5-1', title: 'درس' }, { id: '5-2', title: 'درس ٢' }], classes: ['c2'], opensAt: T - 1000, closesAt: T + 3600e3, limitSec: 0, attempts: 2, questions: ['5-1', '5-2', '5-1'].map((l, i) => ({ ...Q(i), lesson: l })), mis: { ops_ltr: { name: 'خطأ', hint: 'ت' } } }, K);
  const FA = XA, FP = p => `/q/${fq.j.id}${p}`;
  let fr = await call('POST', FP('/start'), {}, FA); for (let i = 0; i < 3; i++) fr = await call('POST', FP('/answer'), { i, c: fr.j.q ? fr.j.q.choices.findIndex(h => h.startsWith('A')) : 0 }, FA);
  const fd = (await call('GET', '/t/quizzes/' + fq.j.id, null, K)).j;
  ok('future unit plugs in (no server change): create/login/score/teacher detail', fq.s === 200 && fr.j.att.done && fr.j.att.score === 3 && fd.quiz.unit.prefix === 'haytham.geo.te.' && fd.quiz.lessons.length === 2, JSON.stringify(fd.quiz.unit));
  ok('teacher-set attempts=2 allows a 2nd try', (await call('POST', FP('/start'), {}, FA)).s === 200);
  await call('DELETE', '/t/quizzes/' + fq.j.id, null, K); }
// الفصل 3 (المعادلات الخطية): أسئلة نموذج البطاقات (HTML ‎.mmat/.tx/.tp/.tm‎) تمرّ بالتنقية كما هي، والبادئة haytham.lin.te. تُحفظ للاستيراد
{ const tile = '<span class="mmat" dir="rtl"><span class="mside"><i class="tx">س</i><i class="tm">\u2066−1\u2069</i></span><b>=</b><span class="mside"><i class="tp">1</i><i class="tp">1</i></span></span>';
  const lq = await call('POST', '/t/quizzes', { title: 'الفصل 3', unit: { slug: 'linear-equations', title: 'الجبر: المعادلات الخطية والدوال', chapter: 3, prefix: 'haytham.lin.te.' }, lessons: [{ id: '3-2', title: 'معادلات الجمع والطرح' }], classes: ['c2'], opensAt: T - 1000, closesAt: T + 3600e3, limitSec: 0, attempts: 1,
    questions: [{ lesson: '3-2', prompt: 'ما حل المعادلة التي يمثّلها النموذج؟<br>' + tile + '<span class="lp lg"><i class="tx">س</i> = متغير</span><img src=x onerror=alert(1)>', choices: [{ html: 'A3', ok: true }, { html: 'B1', ok: false, mis: 'eq_same_op' }, { html: 'C-3', ok: false, mis: 'eq_int_sign' }], answer: '3' }],
    mis: { eq_same_op: { name: 'استعمال العملية نفسها بدل العكسية', hint: 'ت', lesson: '3-2' }, eq_int_sign: { name: 'خطأ في إشارة الناتج', hint: 'ت', lesson: '3-2' } } }, K);
  const ld = (await call('GET', '/t/quizzes/' + lq.j.id, null, K)).j.quiz;
  ok('unit 3 quiz stored with prefix haytham.lin.te. + mis names', lq.s === 200 && ld.unit.prefix === 'haytham.lin.te.' && ld.unit.slug === 'linear-equations' && ld.mis.eq_int_sign.name.length > 0, JSON.stringify(ld.unit));
  ok('unit 3 tile HTML kept by sanitize; onerror stripped', ld.questions[0].prompt.includes(tile) && !/onerror/i.test(ld.questions[0].prompt), ld.questions[0].prompt.slice(0, 160));
  const LA = XA, LP = p => `/q/${lq.j.id}${p}`;
  const st = await call('POST', LP('/start'), {}, LA);
  ok('student gets tile question without answer key', st.s === 200 && st.j.q.prompt.includes('class="tx"') && !JSON.stringify(st.j).includes('"ok"') && !JSON.stringify(st.j).includes('eq_same_op'), JSON.stringify(st.j).slice(0, 200));
  const an = await call('POST', LP('/answer'), { i: 0, c: st.j.q.choices.findIndex(h => h.startsWith('C')) }, LA);
  const ld2 = (await call('GET', '/t/quizzes/' + lq.j.id, null, K)).j;
  ok('unit 3 wrong answer graded server-side with misconception key', an.s === 200 && ld2.attempts[0].tries[0].ans[0].m === 'eq_int_sign' && !ld2.attempts[0].tries[0].ans[0].ok, JSON.stringify(ld2.attempts[0] && ld2.attempts[0].tries));
  await call('DELETE', '/t/quizzes/' + lq.j.id, null, K); }
// الفصل 4 (النسبة والتناسب): النسبة RTL (الحد الأول يمينًا) والكسر المكدّس والنسبة المئوية والعدد الكسري تمرّ بالتنقية، والبادئة haytham.rat.te.
{ const rat = '<bdi class="num ex rat" dir="rtl">\u2067٤\u2069 : \u2067٦\u2069</bdi>', fr = '<bdi class="num ex fx" dir="rtl"><span class="frac"><span>\u2067٢\u2069</span><span>\u2067٣\u2069</span></span></bdi>';
  const pc = '<bdi class="num pct" dir="rtl">\u2067٦٢,٥\u2069٪</bdi>', mx = '<bdi class="num ex mixed" dir="ltr">\u2067١\u2069<span class="frac"><span>\u2067١\u2069</span><span>\u2067٢\u2069</span></span></bdi>';
  const fu = '<bdi class="num fu" dir="rtl"><span class="frac"><span><bdi class="num" dir="rtl">\u2067٨٤٠\u2069</bdi> ريالًا</span><span><bdi class="num" dir="rtl">\u2067٤٠\u2069</bdi> ساعة</span></span></bdi>';
  const rq = await call('POST', '/t/quizzes', { title: 'الفصل 4', unit: { slug: 'ratio-proportion', title: 'النسبة والتناسب', chapter: 4, prefix: 'haytham.rat.te.' }, lessons: [{ id: '4-1', title: 'النسبة' }, { id: '4-8', title: 'الكسور والنسب المئوية' }], classes: ['c2'], opensAt: T - 1000, closesAt: T + 3600e3, limitSec: 0, attempts: 1,
    questions: [{ lesson: '4-1', prompt: 'اكتب النسبة ' + rat + ' في أبسط صورة. ' + fu + '<script>alert(1)</script>', choices: [{ html: 'A' + fr, ok: true }, { html: 'B<bdi class="num ex fx" dir="rtl"><span class="frac"><span>3</span><span>2</span></span></bdi>', ok: false, mis: 'rat_order' }, { html: 'C' + mx, ok: false, mis: 'rat_simplify' }], answer: fr },
      { lesson: '4-8', prompt: 'اكتب ' + pc + ' على صورة كسر.', choices: [{ html: 'A5/8', ok: true }, { html: 'B625/10', ok: false, mis: 'pct_100' }], answer: '5/8' }],
    mis: { rat_order: { name: 'عكس ترتيب حدَّي النسبة', hint: 'ت', lesson: '4-1' }, rat_simplify: { name: 'عدم التبسيط', hint: 'ت', lesson: '4-1' }, pct_100: { name: 'من ١٠٠', hint: 'ت', lesson: '4-8' } } }, K);
  const rd = (await call('GET', '/t/quizzes/' + rq.j.id, null, K)).j.quiz;
  ok('unit 4 quiz stored with prefix haytham.rat.te. + 2 lessons', rq.s === 200 && rd.unit.prefix === 'haytham.rat.te.' && rd.unit.slug === 'ratio-proportion' && rd.lessons.length === 2 && rd.mis.rat_order.name.length > 0, JSON.stringify(rd.unit));
  ok('unit 4 ratio/fraction/percent/mixed HTML kept; script stripped', rd.questions[0].prompt.includes(rat) && rd.questions[0].prompt.includes(fu) && rd.questions[0].choices[0].html.includes(fr) && rd.questions[0].choices[2].html.includes(mx) && rd.questions[1].prompt.includes(pc) && !/<script/i.test(rd.questions[0].prompt), rd.questions[0].prompt.slice(0, 200));
  const RA = XA, RP = p => `/q/${rq.j.id}${p}`;
  let st = await call('POST', RP('/start'), {}, RA);
  if (st.j.q && !st.j.q.prompt.includes('class="num ex rat"')) st = await call('POST', RP('/answer'), { i: 0, c: st.j.q.choices.findIndex(h => h.startsWith('A')) }, RA);   // ترتيب الأسئلة عشوائي
  ok('student gets ratio question (dir=rtl kept) without answer key', st.s === 200 && st.j.q.prompt.includes('class="num ex rat" dir="rtl"') && !JSON.stringify(st.j.q).includes('"ok"') && !JSON.stringify(st.j).includes('rat_order'), JSON.stringify(st.j).slice(0, 200));
  const an = await call('POST', RP('/answer'), { i: st.j.q.i, c: st.j.q.choices.findIndex(h => h.startsWith('B')) }, RA);
  const rd2 = (await call('GET', '/t/quizzes/' + rq.j.id, null, K)).j;
  ok('unit 4 wrong answer graded server-side with rat_order', an.s === 200 && rd2.attempts[0].tries[0].ans.some(x => x.m === 'rat_order' && !x.ok), JSON.stringify(rd2.attempts[0] && rd2.attempts[0].tries));
  await call('DELETE', '/t/quizzes/' + rq.j.id, null, K); }
r = await call('DELETE', '/t/classes/c1', null, K); ok('delete class data', r.j.ok && !(await store.get('cls/c1')) && (await store.list('att/' + qid + '/')).length === 0);
ok('accounts gone after class delete', (await login(REC(0), '4821', '4.4.4.4')).s === 401 && (await store.list('acct/')).length === 1);
r = await call('DELETE', '/t/quizzes/' + qid, null, K); ok('delete quiz', r.j.ok && !(await store.get('quiz/' + qid)));
ok('teacher secret still intact at end', (await call('GET', '/t/ping', null, K)).j.ok);
console.log(`${pass}/${pass + failN} passed`); process.exit(failN ? 1 : 0);

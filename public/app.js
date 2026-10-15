/* «مسابقة عن بعد» — صفحة الطالب. الدخول برقم السجل + رقم سري من ٤ أرقام. التصحيح على الخادم فقط. */
(function () {
  'use strict';
  var BR = {"teacher": "معلم/معلمة المادة", "teacherFull": "معلم/معلمة المادة", "school": "منصة الإنجليزي", "telegram": "https://t.me/alhaythammath", "telegramLabel": "منصة الهيثم"};
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var V = $('#view');
  var P = new URLSearchParams(location.search), QID = (P.get('q') || (location.hash.match(/q=([a-z0-9]+)/) || [])[1] || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  var TK = 'rq.tok', tok = null, st = null, off = 0, tab = 'q', timers = {}, busy = false, boardData = null, backoff = 0, cur = '', list = null, me = null;
  try { tok = localStorage.getItem(TK); Object.keys(localStorage).forEach(function (k) { if (k.indexOf('rq.tok.') === 0) localStorage.removeItem(k); }); } catch (e) { }   // جلسات الرموز القديمة
  var EAST = '٠١٢٣٤٥٦٧٨٩';
  function dg(n) { return String(n).replace(/[0-9]/g, function (d) { return EAST[d]; }).replace(/([٠-٩])\.(?=[٠-٩])/g, '$1,'); }   // أرقام عربية ١٢٣ دائمًا، والفاصلة العشرية «,» كما في الكتاب
  /* أسلوب الكتاب لكل HTML رياضي يأتي من الخادم (نص السؤال، الخيارات، التلميحات):
     المسابقات القديمة وُلِّدت بنمط 123 أو ١٢٣ (LTR)، فتُحوَّل هنا كما يفعل نمط «أسلوب الكتاب» في المختبرات:
     كل عدد معزول RLI، والتعبير RTL (المعامل يمين المتغير: ٢ك − ٥د، ك = ٦)، والفاصلة العشرية «,»، و٪، وقوائم الأعداد « ، ».
     استثناءات المختبر نفسها: العدد الكسري (.mixed) والساعة (٧:٣٠) يبقيان LTR. التحويل لا يغيّر شيئًا في أسئلة أسلوب الكتاب سوى الأرقام اللاتينية المتبقية. */
  function bookText(t) { return dg(t.replace(/\u2066/g, '\u2067')).replace(/%/g, '٪'); }
  function mathHTML(h) { return h ? String(h) : ''; }   /* English build: questions are English (LTR spans) — no digit/direction conversion */
  function mathHTML_unused(h) {
    if (!h) return '';
    var out = String(h).split(/(<\/?[a-zA-Z][^>]*>)/).map(function (p) {
      return /^<\/?[a-zA-Z]/.test(p) ? (/class="[^"]*\bmixed\b/.test(p) ? p : p.replace(/\sdir="ltr"/g, ' dir="rtl"')) : bookText(p);
    }).join('');
    return out.replace(/\)(?:²|٢)(?=<\/bdi>)/g, ')<sup>٢</sup>')
      .replace(/<bdi class="num" dir="rtl">\u2067([٠-٩]+:[٠-٩]+)\u2069<\/bdi>/g, '<bdi class="num" dir="ltr">\u2066$1\u2069</bdi>')
      .replace(/(<bdi class="num ex" [^>]*>)([^<]*)(<\/bdi>)/g, function (m, a, b, c) { return a + b.replace(/\u2069\s*,\s*(?=\u2067)/g, '\u2069 ، ') + c; })
      .replace(/(<\/bdi>)\s*,\s*(\.\.\.)/g, '$1 ، $2');
  }
  function ascii(s) { return String(s || '').replace(/[٠-٩]/g, function (d) { return EAST.indexOf(d); }).replace(/[۰-۹]/g, function (d) { return '۰۱۲۳۴۵۶۷۸۹'.indexOf(d); }); }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function bd(s) { return '<bdi>' + esc(s) + '</bdi>'; }
  function now() { return Date.now() + off; }
  function fmtT(ms) { ms = Math.max(0, ms); var s = Math.round(ms / 1000), h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return dg((h ? h + ':' + (m < 10 ? '0' : '') : '') + m + ':' + (x < 10 ? '0' : '') + x); }
  function fmtDate(t) { try { return dg(new Intl.DateTimeFormat('ar-SA-u-nu-latn', { weekday: 'long', hour: 'numeric', minute: '2-digit', day: 'numeric', month: 'long' }).format(new Date(t))); } catch (e) { return dg(new Date(t).toLocaleString()); } }
  function api(m, p, body) {
    var h = { 'content-type': 'application/json' }; if (tok) h.authorization = 'Bearer ' + tok;
    return fetch('/api' + p, { method: m, headers: h, body: body ? JSON.stringify(body) : undefined, cache: 'no-store' }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (j && j.now) off = j.now - Date.now();
        if (!r.ok) { var e = new Error(j.error || 'تعذّر الاتصال'); e.status = r.status; e.must = !!j.must; throw e; }
        return j;
      });
    });
  }
  function Q(p) { return '/q/' + cur + p; }
  function setTok(t) { tok = t; try { if (t) localStorage.setItem(TK, t); else localStorage.removeItem(TK); } catch (e) { } }
  function clearTimers() { Object.keys(timers).forEach(function (k) { clearInterval(timers[k]); clearTimeout(timers[k]); }); timers = {}; }
  function logout() { setTok(null); st = null; list = null; me = null; cur = ''; clearTimers(); viewLogin(); }
  function fail(e) { if (e.must) return viewChange(true); if (e.status === 401) { logout(); showErr(e.message); } else showErr(e.message || 'تعذّر الاتصال بالخادم. تحقّق من الإنترنت.'); }
  function showErr(m) { var b = $('#err'); if (b) { b.textContent = m; b.hidden = false; } else { var d = document.createElement('div'); d.className = 'err'; d.textContent = m; V.prepend(d); } }
  /* نصوص SVG العربية: اتجاه RTL مع عكس المرساة (كما في المختبرات) */
  function fixSvg(root) { root.querySelectorAll('svg text').forEach(function (t) { if (/[\u0621-\u064A]/.test(t.textContent) && !t.getAttribute('direction')) { t.setAttribute('direction', 'rtl'); var a = t.getAttribute('text-anchor') || 'start'; if (a !== 'middle') t.setAttribute('text-anchor', a === 'end' ? 'start' : 'end'); } t.style.unicodeBidi = 'isolate'; }); }
  /* حقول الأرقام: لوحة أرقام على الجوال، وتقبل الأرقام العربية ١٢٣ (تُحوَّل) */
  function numIn(id, label, max, pin) { return '<label class="fld"><span>' + label + '</span><input class="num-in' + (pin ? ' pin-in' : '') + '" id="' + id + '" ' + (pin ? 'type="password" autocomplete="' + (pin === 'new' ? 'new-password' : 'current-password') + '" pattern="[0-9]{4}" maxlength="4"' : 'type="text" autocomplete="username" maxlength="' + max + '"') + ' inputmode="numeric" dir="ltr" required></label>'; }
  function digitsOnly(inp, max) { inp.addEventListener('input', function () { var v = ascii(inp.value).replace(/\D/g, '').slice(0, max); if (v !== inp.value) inp.value = v; }); }
  function formErr(m) { var e = $('#err'); e.textContent = m; e.hidden = false; }

  /* ---------- الدخول ---------- */
  function viewLogin(msg, rec0) {
    clearTimers(); setTabs(false);
    V.innerHTML = '<form class="card center" id="lf" autocomplete="on" novalidate><h1>مسابقات اللغة الإنجليزية</h1><p class="mut">ادخل برقم السجل والرقم السري.</p>' +
      numIn('rec', 'رقم السجل', 15) + numIn('pin', 'الرقم السري (٤ أرقام)', 4, 'cur') +
      (msg ? '<div class="okm">' + esc(msg) + '</div>' : '') + '<div class="err" id="err" hidden></div><button class="btn" id="go" type="submit">دخول</button>' +
      '<button class="link" id="fg" type="button">نسيت الرقم السري</button></form>';
    var r = $('#rec'), p = $('#pin'); digitsOnly(r, 15); digitsOnly(p, 4);
    try { var last = rec0 || localStorage.getItem('rq.rec'); if (last) r.value = last; } catch (e) { }
    $('#fg').addEventListener('click', function () { viewForgot(r.value); });
    $('#lf').addEventListener('submit', function (ev) {
      ev.preventDefault(); $('#err').hidden = true;
      if (r.value.length < 4) return formErr('اكتب رقم السجل.');
      if (p.value.length !== 4) return formErr('الرقم السري ٤ أرقام.');
      var b = $('#go'); b.disabled = true;
      api('POST', '/login', { rec: r.value, pin: p.value }).then(function (j) { setTok(j.token); me = { name: j.name, cls: j.cls }; try { localStorage.setItem('rq.rec', r.value); } catch (e) { } if (j.must) viewChange(true); else home(); })
        .catch(function (e) { b.disabled = false; formErr(e.message); p.value = ''; p.focus(); });
    });
    setTimeout(function () { (r.value ? p : r).focus(); }, 50);
  }
  function viewChange(forced) {
    clearTimers(); setTabs(false);
    V.innerHTML = '<form class="card center" id="cf" novalidate><h1>' + (forced ? 'اختر رقمك السري' : 'تغيير الرقم السري') + '</h1>' + (me ? '<div class="hello">أهلًا يا ' + bd(me.name) + ' 👋</div>' : '') +
      '<p class="mut">' + (forced ? 'اختر ٤ أرقام تتذكّرها (غير ٠٠٠٠) لتدخل بها كل مرة.' : 'اكتب الرقم الحالي ثم الرقم الجديد.') + '</p>' +
      (forced ? '' : numIn('old', 'الرقم السري الحالي', 4, 'cur')) + numIn('p1', 'الرقم السري الجديد', 4, 'new') + numIn('p2', 'أعد كتابته للتأكيد', 4, 'new') +
      '<div class="err" id="err" hidden></div><button class="btn" id="go" type="submit">حفظ</button>' + (forced ? '<button class="link" id="out" type="button">خروج</button>' : '<button class="link" id="back" type="button">رجوع</button>') + '</form>';
    ['old', 'p1', 'p2'].forEach(function (id) { var i = $('#' + id); if (i) digitsOnly(i, 4); });
    if ($('#out')) $('#out').addEventListener('click', logout);
    if ($('#back')) $('#back').addEventListener('click', home);
    $('#cf').addEventListener('submit', function (ev) {
      ev.preventDefault(); $('#err').hidden = true;
      var a = $('#p1').value, b2 = $('#p2').value, o = $('#old') ? $('#old').value : undefined;
      if (o !== undefined && o.length !== 4) return formErr('اكتب الرقم السري الحالي.');
      if (a.length !== 4) return formErr('الرقم السري ٤ أرقام.');
      if (a === '0000') return formErr('اختر رقمًا غير ٠٠٠٠.');
      if (a !== b2) return formErr('الرقمان غير متطابقين.');
      var b = $('#go'); b.disabled = true;
      api('POST', '/pin', { pin: a, old: o }).then(function (j) { setTok(j.token); me = { name: j.name, cls: j.cls }; home(); })
        .catch(function (e) { b.disabled = false; if (e.status === 401 && forced) return fail(e); formErr(e.message); });
    });
    setTimeout(function () { ($('#old') || $('#p1')).focus(); }, 50);
  }
  function viewForgot(rec) {
    clearTimers(); setTabs(false);
    V.innerHTML = '<form class="card center" id="ff" novalidate><h1>نسيت الرقم السري</h1><p class="mut">اكتب رقم السجل، وسيصل طلبك إلى المعلم ليرسل لك رقمًا مؤقتًا.</p>' +
      numIn('rec', 'رقم السجل', 15) + '<div class="err" id="err" hidden></div><button class="btn" id="go" type="submit">إرسال الطلب</button><button class="link" id="back" type="button">رجوع</button></form>';
    var r = $('#rec'); digitsOnly(r, 15); r.value = ascii(rec || '').replace(/\D/g, '');
    $('#back').addEventListener('click', function () { viewLogin('', r.value); });
    $('#ff').addEventListener('submit', function (ev) {
      ev.preventDefault(); $('#err').hidden = true; if (r.value.length < 4) return formErr('اكتب رقم السجل.');
      var b = $('#go'); b.disabled = true;
      api('POST', '/forgot', { rec: r.value }).then(function () { viewLogin('✅ وصل طلبك إلى المعلم. سيرسل لك رقمًا مؤقتًا على الخاص، ادخل به ثم اختر رقمًا جديدًا.', r.value); })
        .catch(function (e) { b.disabled = false; formErr(e.message); });
    });
    setTimeout(function () { r.focus(); }, 50);
  }
  /* ---------- مسابقاتي (طلب واحد عند الدخول/الرجوع، بلا استطلاع) ---------- */
  function home(pick, msg) {
    clearTimers(); setTabs(false); st = null; boardData = null;
    api('GET', '/quizzes').then(function (j) {
      list = j.quizzes; me = j.me;
      var act = list.filter(function (q) { return q.status !== 'closed'; }), want = QID && list.find(function (q) { return q.id === QID; });
      if (!pick && want) { QID = ''; return openQuiz(want.id); }
      if (!pick && act.length === 1) return openQuiz(act[0].id);
      viewPicker(); if (msg) showErr(msg);
    }).catch(fail);
  }
  function viewPicker() {
    var stx = { open: 'مفتوحة الآن', soon: 'لم تبدأ', closed: 'انتهت' };
    V.innerHTML = '<div class="card center"><div class="hello">أهلًا يا ' + bd(me.name) + ' 👋</div><div class="mut">' + bd(me.cls) + '</div></div>' +
      '<div class="card"><h2>📋 مسابقاتي</h2>' + (list.length ? '<div class="qpick">' + list.map(function (q) {
        var m = q.mine, res = m ? (m.done ? '✓ ' + dg(m.best) + ' / ' + dg(m.n) : 'بدأت: ' + dg(m.answered) + ' / ' + dg(m.n)) : '';
        return '<button class="qp st-' + q.status + '" data-q="' + esc(q.id) + '"><b>' + esc(q.title) + '</b><span class="mut">' + esc(q.unit.title) + '</span><span class="row2"><span class="chip">' + stx[q.status] + '</span>' + (res ? '<span class="chip">' + res + '</span>' : '') + '</span></button>';
      }).join('') + '</div>' : '<p class="mut center">لا توجد مسابقات لفصلك الآن.</p>') + '</div>' +
      '<div class="card center"><button class="link" id="chg">تغيير الرقم السري</button> · <button class="link" id="out">خروج</button></div>';
    V.querySelectorAll('[data-q]').forEach(function (b) { b.addEventListener('click', function () { openQuiz(b.dataset.q); }); });
    $('#chg').addEventListener('click', function () { viewChange(false); });
    $('#out').addEventListener('click', logout);
  }
  function openQuiz(id) { cur = id; tab = 'q'; boardData = null; load(); }
  function backBtn() { return list && list.length > 1 ? '<button class="out" id="mine">↩ مسابقاتي</button>' : ''; }
  function wireBack() { var b = $('#mine'); if (b) b.addEventListener('click', function () { home(true); }); }
  function load() { api('GET', Q('/me')).then(function (j) { st = j; route(); }).catch(function (e) { if (e.status === 404 || (e.status === 403 && !e.must)) { cur = ''; return home(true, e.message); } fail(e); }); }
  function route() {
    clearTimers();
    if (st.q) { setTabs(true); return tab === 'b' ? viewBoard() : viewQuestion(); }
    if (st.att && st.att.done) { setTabs(true); return tab === 'b' ? viewBoard() : viewEnd(); }
    setTabs(false); viewWelcome();
  }
  function lessonsHTML() { return '<div class="les">' + st.quiz.lessons.map(function (l) { return '<span><bdi dir="rtl">' + esc(dg(l.id)) + '</bdi> ' + esc(l.title) + '</span>'; }).join('') + '</div>'; }
  function viewWelcome() {
    var q = st.quiz, lim = q.limitSec ? dg(Math.round(q.limitSec / 60)) + ' دقيقة' : 'حتى الإغلاق';
    var msg = st.status === 'soon' ? '<div class="info">تبدأ المسابقة: <b>' + fmtDate(q.opensAt) + '</b><br>بعد <b id="cd"></b></div>' :
      st.status === 'closed' ? '<div class="err">انتهى وقت هذه المسابقة.</div>' : '';
    V.innerHTML = '<div class="card center"><div class="hello">أهلًا يا ' + bd(st.me.name) + ' 👋</div><div class="mut">' + bd(st.me.cls) + '</div>' +
      '<h1 style="margin-top:.8rem">' + esc(q.title) + '</h1><div class="mut">' + esc(q.unit.title) + '</div>' + lessonsHTML() +
      '<div class="meta"><div>عدد الأسئلة<b>' + dg(q.n) + '</b></div><div>الوقت<b>' + lim + '</b></div><div>المحاولات<b>' + dg(q.attempts) + '</b></div><div>تُغلق<b style="font-size:.8rem">' + fmtDate(q.closesAt) + '</b></div></div>' + msg +
      (st.canStart ? '<button class="btn" id="start">ابدأ المسابقة</button><p class="mut">بعد البدء يعمل المؤقّت حتى لو أغلقت الصفحة.</p>' : '') +
      '<button class="btn sec" id="lb">لوحة الترتيب</button>' + backBtn() + '<button class="out" id="out">لست ' + bd(st.me.name) + '؟ خروج</button></div>';
    if ($('#start')) $('#start').addEventListener('click', function () { this.disabled = true; api('POST', Q('/start')).then(function (j) { st = j; tab = 'q'; route(); }).catch(fail); });
    $('#lb').addEventListener('click', function () { tab = 'b'; setTabs(true, true); viewBoard(); });
    $('#out').addEventListener('click', logout); wireBack();
    if (st.status === 'soon') timers.cd = setInterval(function () { var ms = q.opensAt - now(); if (ms <= 0) { load(); return; } var c = $('#cd'); if (c) c.textContent = fmtT(ms); }, 1000);
  }
  /* ---------- السؤال ---------- */
  function viewQuestion(fb) {
    var q = st.q, a = st.att, qp = mathHTML(q.prompt), qc = mathHTML(q.ctx), qch = q.choices.map(mathHTML);
    var long = q.choices.some(function (h) { return h.replace(/<[^>]+>/g, '').length > 16; });
    V.innerHTML = '<div class="card"><div class="qbar"><span class="no">' + dg(q.i + 1) + ' / ' + dg(q.n) + '</span><span class="pg"><i style="width:' + Math.round(100 * q.i / q.n) + '%"></i></span><span class="tm" id="tm"></span></div>' +
      (qc ? '<div class="q-ctx">' + qc + '</div>' : '') + '<div class="q-prompt">' + qp + '</div>' +
      '<div class="choices' + (q.small ? ' small' : '') + (long ? ' one' : '') + '">' + qch.map(function (h, i) { return '<button class="choice" data-i="' + i + '">' + h + '</button>'; }).join('') + '</div>' +
      '<div class="fb" id="fb"></div><div class="mini"><span>النقاط: <b>' + dg(a.score) + '</b></span><span id="rk"></span></div></div>';
    fixSvg(V);
    V.querySelectorAll('.choice').forEach(function (b) { b.addEventListener('click', function () { answer(+b.dataset.i, b); }); });
    tick(); timers.tm = setInterval(tick, 1000);
    pollRank();
  }
  function tick() {
    var el = $('#tm'); if (!el || !st.att) return;
    var ms = st.att.deadline - now();
    if (st.att.deadline > 9e14) { el.textContent = ''; return; }
    el.textContent = '⏱ ' + fmtT(ms); el.classList.toggle('low', ms < 60e3);
    if (ms <= 0) { V.querySelectorAll('.choice').forEach(function (b) { b.disabled = true; }); var f = $('#fb'); if (f) { f.className = 'fb bad'; f.textContent = '⏰ انتهى الوقت'; } }
    if (ms <= -6500 && !busy) { clearInterval(timers.tm); load(); }   // بعد مهلة الخادم: النتيجة تُحسب هناك
  }
  function answer(c, btn) {
    if (busy) return; busy = true;
    V.querySelectorAll('.choice').forEach(function (b) { b.disabled = true; });
    api('POST', Q('/answer'), { i: st.q.i, c: c }).then(function (j) {
      var L = j.last, fb = $('#fb');
      if (L) {
        btn.classList.add(L.ok ? 'ok' : 'bad');
        if (!L.ok && L.correct != null) { var cb = V.querySelector('.choice[data-i="' + L.correct + '"]'); if (cb) cb.classList.add('ok'); }
        fb.className = 'fb ' + (L.ok ? 'ok' : 'bad'); fb.textContent = L.ok ? '✓ إجابة صحيحة' : '✗ إجابة غير صحيحة';
      }
      setTimeout(function () { busy = false; st = j; route(); }, L ? 850 : 0);
    }).catch(function (e) { busy = false; V.querySelectorAll('.choice').forEach(function (b) { b.disabled = false; }); fail(e); });
  }
  /* ---------- الترتيب (استطلاع كل ٦ ثوانٍ، يتوقف عند إخفاء الصفحة) ---------- */
  function fetchBoard() { return api('GET', Q('/board')).then(function (j) { boardData = j; backoff = 0; return j; }).catch(function (e) { backoff = Math.min(60e3, (backoff || 6e3) * 2); if (e.status === 401) fail(e); throw e; }); }
  function schedule(fn) { clearTimeout(timers.poll); if (document.hidden) return; timers.poll = setTimeout(fn, backoff || 6000); }
  function pollRank() { fetchBoard().then(function (j) { var r = $('#rk'); if (r && j.rank) r.innerHTML = 'ترتيبك: <b>' + dg(j.rank) + '</b> من ' + dg(j.total); }).catch(function () { }).then(function () { schedule(pollRank); }); }
  function viewBoard() {
    clearInterval(timers.tm);
    var paint = function (j) {
      var rows = j.rows;
      V.innerHTML = '<div class="card"><h2>🏆 لوحة الترتيب <span class="mut" style="font-size:.8rem">(تتحدّث تلقائيًا)</span></h2>' + (j.rank ? '<p class="mut">ترتيبك <b>' + dg(j.rank) + '</b> من ' + dg(j.total) + ' مشاركًا</p>' : '') +
        (rows.length ? '<ol class="lb">' + rows.map(function (r, i) {
          return '<li class="' + (r.me ? 'me' : '') + '"><span class="rk">' + dg(i + 1) + '</span><div class="nm">' + bd(r.name) + (r.me ? ' (أنت)' : '') + '<small>' + bd(r.cls) + ' · ' + (r.done ? 'أنهى ✓' : 'يجيب الآن… ' + dg(r.answered) + '/' + dg(r.n)) + '</small><div class="pb"><i style="width:' + Math.round(100 * r.answered / r.n) + '%"></i></div></div><span class="sc">' + dg(r.score) + '<small>نقطة</small></span></li>';
        }).join('') + '</ol>' : '<p class="mut center">لم يبدأ أحد بعد.</p>') + '</div>';
    };
    if (boardData) paint(boardData); else V.innerHTML = '<div class="card center"><div class="spin"></div></div>';
    var loop = function () { fetchBoard().then(function (j) { if (tab === 'b') paint(j); }).catch(function () { }).then(function () { if (tab === 'b') schedule(loop); }); };
    loop();
  }
  /* ---------- النهاية ---------- */
  function viewEnd() {
    var a = st.att, rv = st.review || { mis: [] }, pct = a.n ? Math.round(100 * a.best / a.n) : 0;
    var cheer = pct >= 90 ? 'أبدعت! 🌟' : pct >= 70 ? 'أحسنت! 👏' : pct >= 50 ? 'جيد، واصل التدريب 💪' : 'لا بأس، راجع الدرس وحاول مجددًا 📘';
    V.innerHTML = '<div class="card center"><h1>انتهت المسابقة</h1><div class="hello">' + bd(st.me.name) + '</div><div class="big-score">' + dg(a.best) + ' / ' + dg(a.n) + '</div><div style="font-weight:900;font-size:1.1rem">' + cheer + '</div><p class="mut" id="rk2"></p>' +
      (st.canStart ? '<button class="btn" id="again">محاولة أخرى (' + dg(st.quiz.attempts - a.tries) + ' متبقية)</button>' : '') + '<button class="btn sec" id="lb">لوحة الترتيب</button>' + backBtn() + '</div>' +
      (rv.mis.length ? '<div class="card"><h2>📌 راجع هذه المفاهيم</h2><ul class="mis">' + rv.mis.map(function (m) { return '<li><b>' + dg(esc(m.name)) + '</b> (' + dg(m.n) + ')' + (m.hint ? '<br>' + mathHTML(m.hint) : '') + '</li>'; }).join('') + '</ul></div>' : '') +
      '<div class="card brand-end"><div>إعداد المعلم: <b>' + esc(BR.teacher) + '</b></div><div class="mut">' + esc(BR.school) + '</div>' + $('.tg').outerHTML + '</div>';
    fixSvg(V);
    $('#lb').addEventListener('click', function () { tab = 'b'; setTabs(true, true); viewBoard(); }); wireBack();
    if ($('#again')) $('#again').addEventListener('click', function () { this.disabled = true; api('POST', Q('/start')).then(function (j) { st = j; tab = 'q'; route(); }).catch(fail); });
    fetchBoard().then(function (j) { var r = $('#rk2'); if (r && j.rank) r.innerHTML = 'ترتيبك <b>' + dg(j.rank) + '</b> من ' + dg(j.total); }).catch(function () { });
  }
  /* ---------- التبويبات السفلية ---------- */
  function setTabs(show, forceBoard) {
    var t = $('.tabs'); if (!show) { if (t) t.remove(); return; }
    if (!t) { t = document.createElement('nav'); t.className = 'tabs'; document.body.appendChild(t); }
    var first = st && st.q ? 'السؤال' : (st && st.att && st.att.done ? 'نتيجتي' : 'البداية');
    t.innerHTML = '<button data-t="q" class="' + (tab === 'q' ? 'on' : '') + '">📝 ' + first + '</button><button data-t="b" class="' + (tab === 'b' ? 'on' : '') + '">🏆 الترتيب</button>';
    t.querySelectorAll('button').forEach(function (b) { b.addEventListener('click', function () { tab = b.dataset.t; if (tab === 'q') { load(); } else { setTabs(true); clearTimers(); viewBoard(); } }); });
  }
  document.addEventListener('visibilitychange', function () { if (!document.hidden && tok && st && cur) { if (tab === 'b') viewBoard(); else load(); } else clearTimeout(timers.poll); });
  if (tok) home(); else viewLogin();
})();

#!/usr/bin/env python3
"""English remote quiz — build the public student page (public/) from web/. No teacher/school names are baked in:
the student page is generic (the buyer's name appears only inside quizzes they create). The server bundle lib/rq-server.mjs
is the unchanged copy of the remote-quiz server (src/ is identical), so it is not rebuilt here."""
import json, pathlib, hashlib
R = pathlib.Path(__file__).parent; W = R / 'web'; P = R / 'public'; P.mkdir(exist_ok=True)
rd = lambda p: p.read_text(encoding='utf-8')
BR = {'teacher': 'معلم/معلمة المادة', 'teacherFull': 'معلم/معلمة المادة', 'school': 'منصة الإنجليزي', 'telegram': 'https://t.me/alhaythammath', 'telegramLabel': 'منصة الهيثم'}
TG = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M9.8 15.6 9.6 19c.4 0 .6-.2.8-.4l2-1.9 4.1 3c.8.4 1.3.2 1.5-.7l2.7-12.6c.3-1.1-.4-1.6-1.1-1.3L3.7 10.9c-1 .4-1 1 0 1.3l4.1 1.3 9.5-6c.4-.3.9-.1.6.2"/></svg>'
js = rd(W / 'app.js').replace('/*BRAND*/', json.dumps(BR, ensure_ascii=False)); css = rd(W / 'app.css')
ver = hashlib.sha1((js + css).encode()).hexdigest()[:8]
html = rd(W / 'index.html').replace('إعداد المعلم: /*TEACHER*/ · /*SCHOOL*/', 'اللغة الإنجليزية · منصة الهيثم').replace('<div class="logo" aria-hidden="true">ه</div>', '<div class="logo" aria-hidden="true">E</div>')
for k, v in {'/*VER*/': ver, '/*TG*/': BR['telegram'], '/*TGLABEL*/': BR['telegramLabel'], '/*TGICON*/': TG}.items(): html = html.replace(k, v)
html = html.replace('<title>مسابقة عن بعد</title>', '<link rel="icon" href="data:,">\n<title>مسابقة الإنجليزي عن بعد</title>')
assert '/*' not in html
(P / 'index.html').write_text(html, encoding='utf-8'); (P / 'app.js').write_text(js, encoding='utf-8'); (P / 'app.css').write_text(css, encoding='utf-8')
(P / 'robots.txt').write_text('User-agent: *\nDisallow: /\n', encoding='utf-8')
print('public:', sorted(x.name for x in P.iterdir()), len(js), len(css))

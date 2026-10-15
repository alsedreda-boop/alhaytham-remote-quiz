# English Remote Quiz — server kit (Netlify)

[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/alsedreda-boop/alhaytham-remote-quiz)

A small public site that pairs with the offline English classroom platform:

- `public/`: the student page. Students log in with a record number and a 4-digit PIN (0000 the first time, then they choose their own).
- `netlify/functions/api.mjs`: one Netlify Function serving `/api/*`. It handles teacher endpoints `/api/t/*` (with CORS) and student endpoints.
- Storage is **Netlify Blobs**. It is configured automatically inside Netlify Functions, so **no environment variables** are needed.
- There is **no build step and no runtime dependencies**. `lib/rq-server.mjs` is a prebuilt bundle (built from `src/`, with `@netlify/blobs` inlined).

There are no secrets, teacher names or school names in this repo. The teacher key is set *after* deploying, from the platform's 📡 setup page (`POST /api/t/claim`). Whoever claims first owns the site, so claim it immediately after the first deploy.

## Deploy (buyer)
1. Create a free Netlify account.
2. Press **Deploy to Netlify** (above). Netlify copies this repo into your own GitHub account and deploys it.
3. In the platform, go to 📡 → ⚙️ الإعداد. Paste your `https://<name>.netlify.app` URL, type a teacher key (10+ characters), then press Save and Claim.
4. In the الحسابات tab: paste record numbers, sync, then print the PIN sheets.

See `docs/دليل-المشتري.md` for the Arabic step-by-step guide.

## Local check
```
npm run dev          # http://localhost:8899  (file store in .data/, or: node dev/server.mjs 8899 :memory:)
npm test             # core tests (90)
RQ_TOOLS=<dir containing node_modules/@netlify/blobs> npm run test:function   # function + Blobs smoke
```
`python3 build_eng.py` rebuilds `public/` from `web/`. This is only needed if you edit `web/`.

## Button for other pages
Markdown:
`[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/alsedreda-boop/alhaytham-remote-quiz)`

HTML:
`<a href="https://app.netlify.com/start/deploy?repository=https://github.com/alsedreda-boop/alhaytham-remote-quiz"><img src="https://www.netlify.com/img/deploy/button.svg" alt="Deploy to Netlify"></a>`

Repo: https://github.com/alsedreda-boop/alhaytham-remote-quiz

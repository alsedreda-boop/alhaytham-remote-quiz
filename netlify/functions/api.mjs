/* Netlify Function واحدة لكل مسارات /api/* — المنطق في src/ (مجمَّع في lib/rq-server.mjs). */
import { createApp, blobsStore } from '../../lib/rq-server.mjs';
let app;
export default async (req, context) => {
  app = app || createApp({ store: blobsStore(), log: (...a) => console.error(...a) });
  return app(req, { ip: context.ip });
};
export const config = { path: '/api/*' };

/* مُحوِّل Netlify Blobs (الإنتاج). اتساق قوي: القراءة بعد الكتابة فورية لكل الطلاب. */
import { getStore } from '@netlify/blobs';
export function blobsStore(name = 'remote-quiz') {
  // يُنشأ المتجر عند كل عملية: رمز Blobs يُقرأ من سياق الاستدعاء الحالي وينتهي بعد مدة،
  // فالمتجر المحفوظ في نسخة دالة دافئة كان يفشل بعد انتهاء رمزه («Failed to decode token: Token expired»).
  const S = () => getStore({ name, consistency: 'strong' });
  return {
    get: k => S().get(k, { type: 'json' }),
    async getWithEtag(k) {
      const s = S(); const r = await s.getWithMetadata(k, { type: 'json' });
      if (!r || r.data == null) return null;
      if (r.etag) return { data: r.data, etag: r.etag };
      // احتياط (خادم Blobs المحلي لا يعيد ETag مع القراءة): نأخذ الوسم من القائمة *قبل* إعادة القراءة؛
      // إن تغيّرت القيمة بينهما فشلت الكتابة الشرطية وأعاد المنطق المحاولة — آمن دائمًا.
      const { blobs } = await s.list({ prefix: k }); const b = blobs.find(x => x.key === k);
      const again = await s.get(k, { type: 'json' });
      return again == null ? null : { data: again, etag: b && b.etag };
    },
    async set(k, v, o = {}) { const opt = {}; if (o.onlyIfNew) opt.onlyIfNew = true; if (o.onlyIfMatch) opt.onlyIfMatch = o.onlyIfMatch;
      const r = await S().setJSON(k, v, opt); return { modified: !r || r.modified !== false }; },
    del: k => S().delete(k),
    async list(prefix) { const { blobs } = await S().list({ prefix }); return blobs.map(b => b.key); },
  };
}

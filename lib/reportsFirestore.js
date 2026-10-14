'use strict';
/**
 * Durable storage for the crowd-report pipeline (lib/reports.js adapter contract: get/set/del/all, namespaces 'rec'|'rep').
 * Cloud Run disk is ephemeral, so production (THREAT_STORE=firestore) keeps reports in Firestore.
 * Collections: <prefix>_reports_rec, <prefix>_reports_rep. Doc id = URL-encoded key (Firestore ids cannot contain '/').
 */
function firestoreReportsAdapter(opts = {}) {
  let db = opts.db;
  if (!db) {
    const { Firestore } = require('@google-cloud/firestore');
    db = new Firestore({
      projectId: process.env.GOOGLE_CLOUD_PROJECT || undefined,
      databaseId: process.env.FIRESTORE_DATABASE || undefined,
      ignoreUndefinedProperties: true
    });
  }
  const prefix = opts.prefix || process.env.THREAT_FS_PREFIX || 'threat';
  const col = ns => db.collection(`${prefix}_reports_${ns}`);
  const id = k => encodeURIComponent(String(k)).slice(0, 1400);
  return {
    kind: 'firestore',
    async get(ns, k) { const d = await col(ns).doc(id(k)).get(); return d.exists ? d.data().v : undefined; },
    async set(ns, k, v) { await col(ns).doc(id(k)).set({ k: String(k), v }); },
    async del(ns, k) { await col(ns).doc(id(k)).delete(); },
    async all(ns) { const out = []; (await col(ns).get()).forEach(d => out.push([d.data().k, d.data().v])); return out; }
  };
}
module.exports = { firestoreReportsAdapter };

'use strict';
const crypto = require('crypto');

const TIERS = { free: { mult: 1 }, pilot: { mult: 5 } };

/** Constant-time string compare (length-independent via hashing both sides). */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
const sha256hex = s => crypto.createHash('sha256').update(String(s)).digest('hex');

function parseKeys(json) {
  const keys = new Map();
  if (!json) return keys;
  try {
    const o = JSON.parse(json);
    for (const [id, v] of Object.entries(o || {})) {
      if (!/^[A-Za-z0-9_-]{3,40}$/.test(id) || !v || !/^[0-9a-f]{64}$/i.test(String(v.secretHash || ''))) continue;
      keys.set(id, { secretHash: String(v.secretHash).toLowerCase(), tier: TIERS[v.tier] ? v.tier : 'free', rpm: Number(v.rpm) > 0 ? Number(v.rpm) : null });
    }
  } catch (e) { console.warn('[apiKeys] API_KEYS_JSON is not valid JSON; no keys loaded'); }
  return keys;
}

function createKeyStore(json = process.env.API_KEYS_JSON) {
  const keys = parseKeys(json);
  const DUMMY = sha256hex('dummy');
  return {
    size: keys.size,
    /** -> {ok:true, keyId:null|string, tier, rpm}  or {ok:false}. No header => anonymous free tier. */
    authenticate(header) {
      if (header == null || header === '') return { ok: true, keyId: null, tier: 'free', rpm: null };
      const s = String(header);
      const dot = s.indexOf('.');
      const id = dot > 0 ? s.slice(0, dot) : '';
      const secret = dot > 0 ? s.slice(dot + 1) : '';
      const rec = keys.get(id);
      const match = safeEqual(sha256hex(secret), rec ? rec.secretHash : DUMMY);
      if (!rec || !secret || !match) return { ok: false };
      return { ok: true, keyId: id, tier: rec.tier, rpm: rec.rpm };
    }
  };
}

module.exports = { createKeyStore, parseKeys, safeEqual, sha256hex, TIERS };

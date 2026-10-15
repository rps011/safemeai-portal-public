'use strict';
/**
 * Threat-intel signals for the text scam engine: phone numbers, UPI IDs and entity names found in a message are looked up
 * in the in-memory threat store (O(1) per candidate) and in confirmed crowd reports. Pure/offline; fails open (any error or a
 * missing store yields "no signal", never a verdict of safety or a crash). Message text is only ever used as lookup keys:
 * every flag is built from store data (sanitised) and normalised values, so message content cannot inject output text.
 */
const { normaliseValue } = require('./ingest/contract');

const MIN_BLOCK_CONFIDENCE = 0.6;
const NON_THREAT = new Set(['popular-site', 'regulated-entity']);
const REGULATOR_CATS = new Set(['unauthorised-forex', 'unregistered-investment']);
const CAT_LABEL = {
  'unauthorised-forex': 'unauthorised forex platform', 'unregistered-investment': 'unregistered investment scheme',
  'fraud-report': 'reported fraud', phishing: 'phishing', malware: 'malware distribution'
};
const GENERIC = new Set(['finance', 'capital', 'trading', 'investment', 'investments', 'securities', 'services', 'solutions', 'global',
  'limited', 'digital', 'markets', 'forex', 'wealth', 'advisory', 'ventures', 'industries', 'private', 'enterprises', 'technologies',
  'financial', 'international', 'consultancy', 'holdings', 'infotech', 'software', 'company', 'india', 'bharat', 'national']);
const HELPLINE_PREFIXES = ['1800', '1860', '1947', '1930', '14444'];
const ACCOUNTISH = /(?:a\/c|acct?|account|acc\.?|ref(?:erence)?|txn|utr|order|invoice|policy|loan|card|id|no\.?|number|#)\W{0,3}$/i;

const clean = (s, n = 80) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);

function prep(raw) {
  let s = String(raw == null ? '' : raw).normalize('NFKC').replace(/[​-‏⁠﻿]/g, '');
  return s.slice(0, 5000);
}

/** @returns {{phones:string[], upis:string[], words:string[]}} normalised candidates (capped). */
function extract(raw) {
  const text = prep(raw);
  const phones = new Set(), upis = new Set();
  const upiRe = /(?<![a-z0-9._-])([a-z0-9._-]{2,64})@([a-z][a-z0-9]{1,31})(?![a-z0-9]|\.[a-z])/gi;
  let m;
  while ((m = upiRe.exec(text)) && upis.size < 5) { const v = normaliseValue('upi', m[1] + '@' + m[2]); if (v) upis.add(v); }
  // Indian mobile: optional +91/91/0 prefix, then 10 digits (solid, 5-5, 4-3-3 or 3-3-4 groups)
  const phRe = /(?<![\d.])(\+?\s?91[\s-]?|0)?([6-9]\d{4}[\s-]?\d{5}|[6-9]\d{3}[\s-]\d{3}[\s-]\d{3}|[6-9]\d{2}[\s-]\d{3}[\s-]\d{4})(?![\d]|[\s-]\d)/g;
  while ((m = phRe.exec(text)) && phones.size < 5) {
    const prefix = m[1] || '';
    if (!prefix) { // bare 10 digits: skip when it reads as an account / reference / order number
      const before = text.slice(Math.max(0, m.index - 16), m.index);
      if (ACCOUNTISH.test(before)) continue;
    }
    const nat = m[2].replace(/\D/g, '');
    if (HELPLINE_PREFIXES.some(p => nat.startsWith(p))) continue; // can never be flagged by this path
    const v = normaliseValue('phone', '+91' + nat);
    if (v) phones.add(v);
  }
  // word list for entity n-gram matching
  const words = text.toLowerCase().replace(/[^\p{L}\p{N}&.,'()\- ]+/gu, ' ').split(/\s+/).filter(Boolean).slice(0, 400);
  return { phones: [...phones], upis: [...upis], words };
}

function entityCandidates(words, maxN = 8) {
  const out = new Set();
  for (let i = 0; i < words.length; i++) {
    for (let n = 1; n <= maxN && i + n <= words.length; n++) {
      const g = words.slice(i, i + n).join(' ');
      const t = g.replace(/[.,]+$/, '');
      for (const c of (t === g ? [g] : [g, t])) if (c.length >= 6 && c.length <= 200) out.add(c);
      if (g.length > 200) break;
    }
  }
  return [...out];
}

function threatHits(store, type, value) {
  try {
    return store.lookup(type, value).filter(h => !NON_THREAT.has(h.category) && Number(h.confidence) >= MIN_BLOCK_CONFIDENCE);
  } catch (_) { return []; }
}
const bestOf = (hits) => hits.slice().sort((a, b) => (REGULATOR_CATS.has(b.category) - REGULATOR_CATS.has(a.category)) || b.confidence - a.confidence)[0];
const maskPhone = (v) => v.slice(0, 5) + 'XXXXX' + v.slice(-3);
const maskUpi = (v) => { const [a, b] = v.split('@'); return a.slice(0, 2) + '***@' + b; };

/**
 * @param {string} raw
 * @param {{threatStore?:object, reports?:{isBlocked:Function}}} deps
 * @returns {Promise<{minScore:number, critical:boolean, flags:string[], context:string[], kind:string|null, hits:object[]}>}
 */
async function assess(raw, deps = {}) {
  const res = { minScore: 0, critical: false, flags: [], context: [], kind: null, hits: [] };
  try {
    const { phones, upis, words } = extract(raw);
    const store = deps.store || deps.threatStore;
    const haveStore = store && typeof store.lookup === 'function';
    const raise = (score, kind, flag, hit) => {
      res.minScore = Math.max(res.minScore, score);
      if (!res.kind) res.kind = kind;
      if (!res.flags.includes(flag)) res.flags.push(flag);
      res.hits.push(hit);
    };

    for (const [type, vals, mask] of [['phone', phones, maskPhone], ['upi', upis, maskUpi]]) {
      for (const v of vals) {
        if (haveStore) {
          const h = bestOf(threatHits(store, type, v));
          if (h) {
            const label = CAT_LABEL[h.category] || clean(h.category, 40);
            const what = type === 'phone' ? 'number' : 'UPI ID';
            const flag = h.category === 'fraud-report'
              ? `Reported fraud ${what} ${mask(v)} (${clean(h.sourceName || h.source, 60)}${h.meta && h.meta.reporters ? ', ' + Number(h.meta.reporters) + ' reporters' : ''})`
              : `${clean(h.sourceName || h.source, 60)}: ${what} ${mask(v)} linked to ${label}`;
            raise(90, type === 'phone' ? 'phone' : 'upi', flag, { type, source: clean(h.source, 40), category: clean(h.category, 40) });
          }
        }
        if (deps.reports && typeof deps.reports.isBlocked === 'function') {
          const b = await deps.reports.isBlocked(type, v).catch(() => null);
          if (b) {
            const n = Number.isFinite(b.reporters) ? b.reporters : 0;
            const flag = `Reported fraud ${type === 'phone' ? 'number' : 'UPI ID'} ${mask(v)} (SafeMeAI community, ${n} reporter${n === 1 ? '' : 's'})`;
            raise(b.level === 'block' ? 90 : 72, type, flag, { type, source: 'safeme-community', category: clean(b.category, 40) });
          }
        }
      }
    }

    if (haveStore) {
      const seen = new Set();
      let ctxHits = 0;
      for (const c of entityCandidates(words)) {
        if (GENERIC.has(c)) continue;
        let hits;
        try { hits = store.lookup('entity', c); } catch (_) { continue; }
        for (const h of hits) {
          const key = h.source + '|' + h.category + '|' + c;
          if (seen.has(key)) continue; seen.add(key);
          const name = clean(h.value || c, 80);
          if (h.category === 'regulated-entity') {
            if (ctxHits < 2 && h.meta && h.meta.label) {
              ctxHits++;
              res.context.push(`${clean(h.meta.label, 100)} (verify the number at ${h.meta.regulator === 'RBI' ? 'rbi.org.in' : 'sebi.gov.in'})`);
            }
          } else if (!NON_THREAT.has(h.category) && Number(h.confidence) >= MIN_BLOCK_CONFIDENCE) {
            const label = CAT_LABEL[h.category] || clean(h.category, 40);
            const src = clean(h.sourceName || h.source, 60);
            if (REGULATOR_CATS.has(h.category)) {
              res.critical = true;
              raise(90, 'entity', `${src}: ${label} '${name}'`, { type: 'entity', source: clean(h.source, 40), category: clean(h.category, 40) });
            } else {
              raise(75, 'entity', `${src}: '${name}' listed as ${label}`, { type: 'entity', source: clean(h.source, 40), category: clean(h.category, 40) });
            }
          }
        }
      }
    }
  } catch (_) { /* fail open for the signal only */ }
  return res;
}

const COPY = {
  phone: ['Known Fraud Number', 'Do not call back or pay: this number is on a fraud list.'],
  upi: ['Known Fraud UPI ID', 'Do not send money: this UPI ID is on a fraud list.'],
  entity: ['Unauthorised / Unregistered Investment Platform', 'Do not invest: the named entity is on a regulator warning list.']
};

/** Merge an assessment into a text-engine verdict. Only ever raises risk; context flags never reduce it. */
function applyToVerdict(v, a, levelFor) {
  if (!v || !a) return v;
  const out = { ...v, flags: [...(v.flags || [])] };
  if (a.context.length) out.flags.push(...a.context.map(c => 'Context (not a safety verdict): ' + c));
  if (a.minScore > 0) {
    const score = Math.max(Number(out.riskScore) || 0, a.minScore);
    out.riskScore = score;
    out.riskLevel = a.critical ? 'CRITICAL' : levelFor(score);
    const [type, advice] = COPY[a.kind] || COPY.phone;
    out.scamType = type;
    out.headline = `🚨 ${type.toUpperCase()}: ${a.flags[0]}`;
    out.flags = [...a.flags, ...out.flags];
    out.verdictDescription = `${a.flags.join('; ')}. ${v.verdictDescription || ''}`.trim();
    out.actionAdvice = [`🛑 ${advice}`, ...(v.actionAdvice || [])];
    out.threatIntel = { hits: a.hits.slice(0, 5) };
  }
  return out;
}

module.exports = { extract, entityCandidates, assess, applyToVerdict };

'use strict';
/**
 * Crowd-report pipeline for SafeMeAI.
 *
 * Goals: turn citizen reports into a blocklist signal WITHOUT letting attackers or competitors weaponise it.
 *
 * Lifecycle of a reported value (domain | phone | upi):
 *   pending            < N independent reporters
 *   community-reported >= N independent reporters (warn level; shown in the public feed)
 *   blocked            BLOCK quality: >= N_BLOCK independent reporters spread over >= minSpanMs, OR >= N reporters
 *                      AND engine corroboration (domain younger than 30d, or lookalike of an allow-listed brand)
 *   review             human decision required. Always the outcome for allow-listed / sovereign / shared-hosting-parent
 *                      domains and toll-free numbers, and for old well-established domains that mass-reports target.
 *   dismissed          a human rejected it; reports are accepted but no longer promote it
 *   expired            TTL elapsed (tombstone is kept for a while so devices can drop the entry)
 *
 * Independence: reporters are keyed by an HMAC of device id (app) or IP+UA (web), and additionally grouped by
 * network (/24 IPv4, /48 IPv6). Many reports from one network count once.
 * PII: reporter name/phone are never read. Only salted HMAC keys are stored. Free text is redacted.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const net = require('net');
const engine = require('./domainEngine');

const DAY = 86400000;
const DEFAULTS = {
  N: 3,                       // independent reporters for community-reported
  N_BLOCK: 6,                 // independent reporters for BLOCK without corroboration
  minSpanMs: 10 * 60 * 1000,  // first..latest independent report spread needed for count-only BLOCK
  youngDomainDays: 30,
  establishedDomainDays: 730, // older than this and not a lookalike: mass reports go to human review
  ttl: { pending: 30 * DAY, 'community-reported': 90 * DAY, blocked: 180 * DAY, review: 90 * DAY, dismissed: 90 * DAY, confirmed: 365 * DAY },
  tombstoneMs: 30 * DAY,
  rate: { perReporterHour: 10, perReporterDay: 30, perNetworkDay: 60 },
  maxReportersPerRecord: 500,
  maxRecords: 100000,
  burnedDismissals: 3         // reporter whose reports were dismissed >= this (and more than confirmed) counts for nothing
};

const SCAM_TYPES = {
  'digital arrest': 'digital-arrest', upi: 'upi-fraud', collect: 'upi-fraud', kyc: 'kyc-phishing', phishing: 'phishing',
  bank: 'bank-impersonation', loan: 'loan-scam', lottery: 'lottery-prize', prize: 'lottery-prize', job: 'job-scam',
  electricity: 'utility-threat', challan: 'challan-scam', parcel: 'parcel-scam', courier: 'parcel-scam',
  investment: 'investment-scam', trading: 'investment-scam', sextortion: 'sextortion', apk: 'malicious-apk',
  govt: 'govt-impersonation', government: 'govt-impersonation', police: 'govt-impersonation', 'tech support': 'tech-support'
};

function categoryOf(label) {
  const l = String(label || '').toLowerCase();
  for (const k of Object.keys(SCAM_TYPES)) if (l.includes(k)) return SCAM_TYPES[k];
  return 'other';
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------
const HELPLINE_PREFIXES = ['1800', '1860', '1947', '1930', '14444'];

function normalisePhone(raw) {
  const plus = /^\s*\+/.test(raw);
  let d = String(raw).replace(/\D/g, '');
  if (!plus) {
    if (d.startsWith('00')) d = d.slice(2);
    else if (d.length === 11 && d.startsWith('0')) d = '91' + d.slice(1);
    else if (d.length <= 11) d = '91' + d.replace(/^0/, '');
  }
  if (d.startsWith('91')) {
    const nat = d.slice(2);
    if (HELPLINE_PREFIXES.some(p => nat.startsWith(p))) return { value: '+91' + nat, tollFree: true };
    return /^[6-9]\d{9}$/.test(nat) ? { value: '+' + d, tollFree: false } : null;
  }
  if (d.length < 8 || d.length > 15 || d.startsWith('0')) return null;
  return { value: '+' + d, tollFree: false };
}

function normaliseUpi(raw) {
  const s = String(raw).trim().toLowerCase();
  const m = s.match(/^([a-z0-9._-]{2,64})@([a-z]{2,32})$/); // PSP handles have no dots; this also rejects e-mail addresses
  return m ? { value: `${m[1]}@${m[2]}` } : null;
}

/** -> {ok, type, value, tollFree?, sharedParent?} | {ok:false, error} */
function normaliseTarget(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return { ok: false, error: 'empty' };
  if (s.length > 2048) return { ok: false, error: 'too_long' };
  if (/[\u0000-\u001f]/.test(s)) return { ok: false, error: 'invalid_characters' };
  if (/^[+\d][\d\s().+-]*$/.test(s)) {
    const p = normalisePhone(s);
    return p ? { ok: true, type: 'phone', value: p.value, tollFree: p.tollFree } : { ok: false, error: 'invalid_phone' };
  }
  if (s.includes('@') && !s.includes('/') && !/^[a-z][a-z0-9+.-]*:/i.test(s)) {
    const u = normaliseUpi(s);
    return u ? { ok: true, type: 'upi', value: u.value } : { ok: false, error: 'invalid_upi_or_email' };
  }
  const t = engine.parseTarget(s);
  if (!t.ok) return { ok: false, error: 'invalid_domain' };
  if (t.nonWebScheme) return { ok: false, error: 'unsupported_scheme' };
  if (t.isIp ? engine.isNonPublicIp(t.host) : engine.isInternalHostname(t.host)) return { ok: false, error: 'non_public_host' };
  const sharedParent = !t.isIp && engine.SHARED_HOSTING_PARENTS.includes(t.host) ? t.host : null;
  return { ok: true, type: 'domain', value: t.host, sharedParent };
}

/** Free text: strip HTML/control chars and anything that looks like personal data. */
function redact(text, n = 300) {
  return String(text == null ? '' : text)
    .replace(/[\u0000-\u001f<>]/g, ' ')
    .replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, '[email]')
    .replace(/\b\d{4}\s?\d{4}\s?\d{4}\b/g, '[id]')
    .replace(/(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g, '[phone]')
    .replace(/\b\d{6,}\b/g, '[number]')
    .replace(/\s+/g, ' ').trim().slice(0, n);
}

function maskTarget(type, value) {
  if (type === 'phone') return value.slice(0, 5) + 'XXXXX' + value.slice(-3);
  if (type === 'upi') { const [a, b] = value.split('@'); return a.slice(0, 2) + '***@' + b; }
  return value;
}

function networkGroup(ip) {
  const s = String(ip || '').replace(/^::ffff:/, '');
  if (net.isIPv4(s)) return s.split('.').slice(0, 3).join('.') + '.0/24';
  if (net.isIPv6(s)) return s.toLowerCase().split(':').slice(0, 3).join(':') + '::/48';
  return 'unknown';
}

// ---------------------------------------------------------------------------
// Storage adapters
// ---------------------------------------------------------------------------
/** Adapter contract: get(ns,k) set(ns,k,v) del(ns,k) all(ns)->[[k,v]] (sync or async). Namespaces: 'rec', 'rep'. */
function memoryAdapter() {
  const m = { rec: new Map(), rep: new Map() };
  return {
    kind: 'memory',
    get: (ns, k) => m[ns].get(k), set: (ns, k, v) => { m[ns].set(k, v); }, del: (ns, k) => { m[ns].delete(k); },
    all: ns => [...m[ns].entries()]
  };
}

function fileAdapter(file) {
  let data = { rec: {}, rep: {} };
  try { data = Object.assign(data, JSON.parse(fs.readFileSync(file, 'utf8'))); } catch (_) { /* first run */ }
  let timer = null;
  const flush = () => {
    timer = null;
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      const tmp = file + '.' + process.pid + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(data));
      fs.renameSync(tmp, file);
    } catch (e) { console.error('[reports] persist failed:', e.message); }
  };
  const dirty = () => { if (!timer) { timer = setTimeout(flush, 500); if (timer.unref) timer.unref(); } };
  return {
    kind: 'file', file, flush,
    get: (ns, k) => data[ns][k], set: (ns, k, v) => { data[ns][k] = v; dirty(); }, del: (ns, k) => { delete data[ns][k]; dirty(); },
    all: ns => Object.entries(data[ns])
  };
}

/** lib/threatStore.js (ingestion agent) wins if it exposes a compatible `reportsAdapter`; otherwise a local JSON file. */
function defaultAdapter(file) {
  if (process.env.THREAT_STORE === 'firestore') {
    try { return require('./reportsFirestore').firestoreReportsAdapter(); }
    catch (e) { console.error('[reports] Firestore adapter unavailable, falling back to file:', e.message); }
  }
  try {
    const ts = require('./threatStore');
    const a = ts && (ts.reportsAdapter || (typeof ts.getReportsAdapter === 'function' && ts.getReportsAdapter()));
    if (a && ['get', 'set', 'del', 'all'].every(f => typeof a[f] === 'function')) return a;
  } catch (_) { /* not present */ }
  return fileAdapter(file || process.env.REPORTS_FILE || path.join(__dirname, '..', 'data', 'runtime', 'reports.json'));
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------
function createReports(opts = {}) {
  const cfg = Object.assign({}, DEFAULTS, opts.config || {}, { ttl: Object.assign({}, DEFAULTS.ttl, (opts.config || {}).ttl), rate: Object.assign({}, DEFAULTS.rate, (opts.config || {}).rate) });
  const store = opts.store || defaultAdapter(opts.file);
  const now = opts.now || (() => Date.now());
  const isProtected = opts.isProtected || (() => false);
  const corroborate = opts.corroborate || null; // async (type,value) => {ageDays, lookalike}
  const secret = opts.secret || process.env.REPORTER_HASH_SECRET || (() => {
    // Ephemeral random secret: reporter keys then do not survive restarts (fails safe: nobody is linkable across restarts).
    return crypto.randomBytes(32).toString('hex');
  })();

  const hmac = (s) => crypto.createHmac('sha256', secret).update(s).digest('hex').slice(0, 24);
  const buckets = new Map(); // rate limit timestamps, in-memory by design
  let lastSweep = 0;

  function reporterKey({ deviceId, ip, ua }) {
    return deviceId ? hmac('dev:' + String(deviceId).slice(0, 128)) : hmac('web:' + (ip || '') + '|' + String(ua || '').slice(0, 200));
  }

  function rateCheck(rk, grp) {
    const t = now();
    const hit = (key, limit, windowMs) => {
      const arr = (buckets.get(key) || []).filter(x => t - x < windowMs);
      buckets.set(key, arr);
      if (arr.length >= limit) return Math.ceil((windowMs - (t - arr[0])) / 1000);
      return 0;
    };
    const wait = Math.max(hit('h:' + rk, cfg.rate.perReporterHour, 3600000), hit('d:' + rk, cfg.rate.perReporterDay, DAY), hit('n:' + grp, cfg.rate.perNetworkDay, DAY));
    if (wait) return wait;
    for (const key of ['h:' + rk, 'd:' + rk, 'n:' + grp]) buckets.get(key).push(t);
    if (buckets.size > 50000) for (const [k, v] of buckets) if (!v.length || t - v[v.length - 1] > DAY) buckets.delete(k);
    return 0;
  }

  async function repOf(rk) { return (await store.get('rep', rk)) || { confirmed: 0, dismissed: 0 }; }
  const isBurned = r => r.dismissed >= cfg.burnedDismissals && r.dismissed > r.confirmed;

  /** Independent reporter count: distinct network groups among reporters that are not burned. */
  async function independent(rec) {
    const groups = new Set(); const times = [];
    for (const [rk, r] of Object.entries(rec.reporters)) {
      if (isBurned(await repOf(rk))) continue;
      if (!groups.has(r.g)) { groups.add(r.g); }
      times.push(r.t);
    }
    return { count: groups.size, spanMs: times.length ? Math.max(...times) - Math.min(...times) : 0 };
  }

  function holdReason(rec) {
    if (rec.type === 'domain') {
      if (isProtected(rec.value)) return 'allow-listed-or-sovereign';
      if (rec.sharedParent) return 'shared-hosting-or-shortener-parent';
    }
    if (rec.type === 'phone' && rec.tollFree) return 'toll-free-or-helpline-number';
    return null;
  }

  function setState(rec, state) {
    if (rec.state !== state) { rec.state = state; rec.updatedAt = now(); }
  }

  function syncPublished(rec) {
    const should = (rec.state === 'blocked' || rec.state === 'community-reported') && !holdReason(rec);
    if (should && !rec.everPublished) rec.everPublished = true;
    if (should !== rec.published) { rec.published = should; rec.updatedAt = now(); }
  }

  /** Recompute state from evidence. Human decisions are sticky; the allow-list always wins. */
  async function evaluate(rec) {
    const hold = holdReason(rec);
    if (rec.review.status === 'dismissed') { setState(rec, 'dismissed'); syncPublished(rec); return rec; }
    if (!hold && rec.review.status === 'queued' && rec.review.reason === 'established-domain-mass-reported') { setState(rec, 'review'); syncPublished(rec); return rec; }
    if (hold) {
      if (rec.review.status !== 'confirmed') { rec.review = { status: 'queued', reason: hold, at: rec.review.at || now() }; setState(rec, 'review'); }
      else if (hold === 'allow-listed-or-sovereign') { rec.review = { status: 'queued', reason: hold, at: now() }; setState(rec, 'review'); }
      syncPublished(rec); return rec;
    }
    if (rec.review.status === 'confirmed') { setState(rec, 'blocked'); syncPublished(rec); return rec; }
    const { count, spanMs } = await independent(rec);
    rec.independent = count;
    if (count >= cfg.N && corroborate && rec.type === 'domain' && !rec.corroboration) {
      try { rec.corroboration = Object.assign({ at: now() }, await corroborate(rec.type, rec.value)); } catch (_) { rec.corroboration = null; }
    }
    const c = rec.corroboration || {};
    const young = typeof c.ageDays === 'number' && c.ageDays < cfg.youngDomainDays;
    const established = typeof c.ageDays === 'number' && c.ageDays >= cfg.establishedDomainDays && !c.lookalike;
    let state = 'pending';
    if (count >= cfg.N) state = 'community-reported';
    if (count >= cfg.N && (young || c.lookalike)) state = 'blocked';
    else if (count >= cfg.N_BLOCK && spanMs >= cfg.minSpanMs) state = 'blocked';
    if (state === 'blocked' && established) {
      // Old, healthy domain being mass-reported: could be brigading or a compromised site. A human decides.
      rec.review = { status: 'queued', reason: 'established-domain-mass-reported', at: rec.review.at || now() };
      state = 'review';
    }
    setState(rec, state);
    syncPublished(rec);
    return rec;
  }

  function ttlFor(rec) {
    if (rec.review.status === 'confirmed') return cfg.ttl.confirmed;
    return cfg.ttl[rec.state] || cfg.ttl.pending;
  }

  async function sweep(force) {
    const t = now();
    if (!force && t - lastSweep < 60000) return 0;
    lastSweep = t; let n = 0;
    for (const [k, rec] of await store.all('rec')) {
      if (rec.state === 'expired') {
        if (t - rec.updatedAt > cfg.tombstoneMs) { await store.del('rec', k); n++; }
        continue;
      }
      if (t - rec.lastReported > ttlFor(rec)) {
        rec.state = 'expired'; rec.updatedAt = t; rec.published = false;
        await store.set('rec', k, rec); n++;
      }
    }
    return n;
  }

  async function submit(input) {
    const { target, scamType, details, deviceId, ip, ua, channel = 'web' } = input || {};
    const norm = normaliseTarget(target);
    if (!norm.ok) return { ok: false, status: 400, error: norm.error, message: 'Could not read that as a phone number, UPI ID, domain or URL.' };
    await sweep();
    const rk = reporterKey({ deviceId, ip, ua });
    const grp = networkGroup(ip);
    const key = norm.type + ':' + norm.value;
    const t = now();
    let rec = await store.get('rec', key);
    if (rec && rec.reporters[rk] && rec.state !== 'expired') {
      return { ok: true, duplicate: true, record: view(rec), message: 'You already reported this. Thank you.' };
    }
    const wait = rateCheck(rk, grp);
    if (wait) return { ok: false, status: 429, error: 'rate_limited', retryAfterSec: wait, message: 'Too many reports. Please try again later.' };
    if (!rec || rec.state === 'expired') {
      if (!rec && (await store.all('rec')).length >= cfg.maxRecords) return { ok: false, status: 503, error: 'capacity', message: 'Report intake is temporarily full.' };
      rec = {
        key, id: 'REP-' + crypto.createHash('sha256').update(key).digest('hex').slice(0, 8).toUpperCase(),
        type: norm.type, value: norm.value, tollFree: Boolean(norm.tollFree), sharedParent: norm.sharedParent || null,
        state: 'pending', categories: {}, reporters: {}, reporterCount: 0, firstReported: t, lastReported: t,
        notes: [], corroboration: null, review: { status: 'none' }, published: false, updatedAt: t, independent: 0
      };
    }
    const cat = categoryOf(scamType);
    rec.categories[cat] = (rec.categories[cat] || 0) + 1;
    if (Object.keys(rec.reporters).length < cfg.maxReportersPerRecord) rec.reporters[rk] = { g: grp, t, ch: channel === 'app' ? 'app' : 'web' };
    rec.reporterCount++;
    rec.lastReported = t;
    const note = redact(details);
    if (note && rec.notes.length < 5) rec.notes.push({ t, cat, label: redact(scamType, 60) || 'Unspecified Scam', text: note });
    await evaluate(rec);
    await store.set('rec', key, rec);
    return { ok: true, duplicate: false, record: view(rec) };
  }

  function statusLabel(rec) {
    return { pending: 'RECEIVED', 'community-reported': 'COMMUNITY_REPORTED', blocked: 'BLOCKED', review: 'QUEUED_FOR_REVIEW', dismissed: 'RECEIVED', expired: 'EXPIRED' }[rec.state] || 'RECEIVED';
  }

  function ago(ts) {
    const m = Math.max(0, Math.round((now() - ts) / 60000));
    if (m < 1) return 'Just now'; if (m < 60) return m + ' mins ago';
    const h = Math.round(m / 60); return h < 24 ? h + ' hours ago' : Math.round(h / 24) + ' days ago';
  }

  /** Public shape used by public/js/app.js: {id, scamType, target, details, time, status}. Reporter data never appears. */
  function view(rec) {
    const n = rec.notes[rec.notes.length - 1];
    return {
      id: rec.id, scamType: (n && n.label) || 'Unspecified Scam', target: maskTarget(rec.type, rec.value),
      details: (n && n.text) || 'Citizen reported fraudulent behavior.', time: ago(rec.lastReported), status: statusLabel(rec)
    };
  }

  /** Public feed: only values that reached community-reported or blocked (so arbitrary submissions are never echoed publicly). */
  async function publicFeed(limit = 20) {
    await sweep();
    return (await store.all('rec')).map(([, r]) => r)
      .filter(r => r.published && !holdReason(r))
      .sort((a, b) => b.lastReported - a.lastReported).slice(0, limit).map(view);
  }

  /** Delta of devices-facing changes since `since` (ms epoch). Removals are explicit so devices can drop entries. */
  async function delta(since = 0, limit = 1000) {
    await sweep();
    const rows = [];
    for (const [, r] of await store.all('rec')) {
      if (r.updatedAt <= since) continue;
      const live = r.published && !holdReason(r) && (r.state === 'blocked' || r.state === 'community-reported');
      if (live) rows.push({ action: 'add', type: r.type, value: r.value, level: r.state === 'blocked' ? 'block' : 'warn', category: topCategory(r), reporters: r.independent || 0, updatedAt: r.updatedAt, expiresAt: r.lastReported + ttlFor(r) });
      else if (r.everPublished) rows.push({ action: 'remove', type: r.type, value: r.value, updatedAt: r.updatedAt });
    }
    rows.sort((a, b) => a.updatedAt - b.updatedAt);
    const page = rows.slice(0, limit);
    return { entries: page, hasMore: rows.length > limit, next: page.length ? page[page.length - 1].updatedAt : since };
  }

  function topCategory(rec) {
    return Object.entries(rec.categories).sort((a, b) => b[1] - a[1])[0]?.[0] || 'other';
  }

  async function reviewQueue() {
    return (await store.all('rec')).map(([, r]) => r).filter(r => r.state === 'review').map(r => ({ id: r.id, type: r.type, value: r.value, reason: r.review.reason, independent: r.independent || 0, reports: r.reporterCount, corroboration: r.corroboration }));
  }

  /** Human decision. Confirming an allow-listed/sovereign domain is refused: fix the allow-list first. */
  async function decide(typeValueKey, decision) {
    const rec = await store.get('rec', typeValueKey);
    if (!rec) return { ok: false, error: 'not_found' };
    if (decision === 'confirm') {
      if (rec.type === 'domain' && isProtected(rec.value)) return { ok: false, error: 'protected_domain', message: 'Remove it from the allow-list first.' };
      if (holdReason(rec) && rec.type !== 'phone') return { ok: false, error: 'cannot_block_shared_parent' };
      rec.review = { status: 'confirmed', at: now() }; rec.tollFree = false;
    } else if (decision === 'dismiss') rec.review = { status: 'dismissed', at: now() };
    else return { ok: false, error: 'bad_decision' };
    for (const rk of Object.keys(rec.reporters)) {
      const rep = await repOf(rk);
      if (decision === 'confirm') rep.confirmed++; else rep.dismissed++;
      await store.set('rep', rk, rep);
    }
    rec.lastReported = now();
    await evaluate(rec); await store.set('rec', typeValueKey, rec);
    return { ok: true, record: view(rec) };
  }

  /**
   * Bridge for the text engine: is this phone/UPI value currently published (community-reported or blocked)?
   * O(1) keyed read. Allow-listed / toll-free / held values answer null. Never throws (fail open for the signal).
   * @returns {Promise<null|{level:'block'|'warn', reporters:number, category:string}>}
   */
  async function isBlocked(type, value) {
    try {
      if (type !== 'phone' && type !== 'upi') return null;
      const n = normaliseTarget(String(value));
      if (!n.ok || n.type !== type) return null;
      const rec = await store.get('rec', type + ':' + n.value);
      if (!rec || !rec.published || holdReason(rec)) return null;
      if (rec.state !== 'blocked' && rec.state !== 'community-reported') return null;
      if (now() - rec.lastReported > ttlFor(rec)) return null;
      return { level: rec.state === 'blocked' ? 'block' : 'warn', reporters: rec.independent || 0, category: topCategory(rec) };
    } catch (_) { return null; }
  }

  return { submit, isBlocked, publicFeed, delta, reviewQueue, decide, sweep, view, _store: store, _cfg: cfg, adapterKind: store.kind || 'external' };
}

// ---------------------------------------------------------------------------
// Signed delta (HMAC-SHA256 over the exact payload string)
// ---------------------------------------------------------------------------
function signDelta(deltaObj, since, key, nowMs = Date.now()) {
  if (!key) return null;
  const payload = JSON.stringify({ format: 1, generatedAt: nowMs, since, next: deltaObj.next, hasMore: deltaObj.hasMore, entries: deltaObj.entries });
  // PEM private key => Ed25519 (the Android app embeds only the PUBLIC key, so extracting it from the APK cannot forge feeds).
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(String(key))) {
    const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), crypto.createPrivateKey(String(key))).toString('base64');
    return { payload, sig, alg: 'Ed25519' };
  }
  const sig = crypto.createHmac('sha256', key).update(payload, 'utf8').digest('hex');
  return { payload, sig, alg: 'HMAC-SHA256' };
}
function verifyDelta(body, key) {
  if (!body || !key) return false;
  const exp = crypto.createHmac('sha256', key).update(String(body.payload), 'utf8').digest();
  const got = Buffer.from(String(body.sig), 'hex');
  return got.length === exp.length && crypto.timingSafeEqual(got, exp);
}

module.exports = { createReports, normaliseTarget, redact, maskTarget, networkGroup, categoryOf, memoryAdapter, fileAdapter, signDelta, verifyDelta, DEFAULTS };

'use strict';
/**
 * Shared ingestion contract: record validation / normalisation, and the polite HTTP helper handed to sources.
 * See lib/ingest/contract.md for the human-readable spec. Zero third-party dependencies.
 */
const { domainToASCII } = require('url');

const TYPES = new Set(['domain', 'url', 'phone', 'upi', 'entity']);
/** Categories that describe a *threat*. Anything else (e.g. 'popular-site') is context, never a block. */
const NON_THREAT_CATEGORIES = new Set(['popular-site', 'regulated-entity']);
/** Regulator-style listings: surfaced as CRITICAL with the regulator named. */
const REGULATOR_CATEGORIES = new Set(['unauthorised-forex', 'unregistered-investment']);

const LIMITS = {
  maxValueLen: 2048, maxSourceUrlLen: 512, maxCategoryLen: 48, maxMetaBytes: 1024, maxRecordBytes: 4096,
  defaultMaxRecords: 5_000_000
};

const LABEL_RE = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;

function normaliseDomain(v) {
  if (typeof v !== 'string') return null;
  let s = v.trim().toLowerCase();
  if (!s || s.length > 300) return null;
  s = s.replace(/^\*\./, '').replace(/\.+$/, '');
  if (/[\s/\\@:?#]/.test(s)) return null;
  if (!/^[\x00-\x7f]*$/.test(s)) { s = domainToASCII(s); if (!s) return null; }
  if (s.length > 253 || !s.includes('.')) return null;
  const labels = s.split('.');
  if (!labels.every(l => LABEL_RE.test(l))) return null;
  if (/^\d+$/.test(labels[labels.length - 1])) return null; // bare IPv4 / numeric TLD is not a domain
  return s;
}

function normaliseUrl(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s || s.length > LIMITS.maxValueLen) return null;
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : 'http://' + s); } catch (_) { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (!u.hostname) return null;
  u.hash = '';
  let href = u.href.toLowerCase();
  if (u.pathname === '/' && !u.search) href = href.replace(/\/$/, '');
  return href.length <= LIMITS.maxValueLen ? href : null;
}

/** Indian-first E.164-ish normalisation. Returns '+91XXXXXXXXXX' for Indian numbers, '+<digits>' otherwise. */
function normalisePhone(v) {
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  let d = String(v).replace(/[\s().-]/g, '');
  const plus = d.startsWith('+');
  d = d.replace(/^\+/, '');
  if (!/^\d+$/.test(d)) return null;
  if (d.startsWith('00')) d = d.slice(2);
  else if (!plus && d.length === 11 && d[0] === '0') d = '91' + d.slice(1);
  else if (!plus && d.length === 10) d = '91' + d;
  if (d.startsWith('91') && d.length === 12) return /^91[6-9]\d{9}$/.test(d) ? '+' + d : null;
  if (d.length < 8 || d.length > 15 || d[0] === '0') return null;
  return '+' + d;
}

function normaliseUpi(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  return /^[a-z0-9._-]{2,256}@[a-z][a-z0-9.-]{1,64}$/.test(s) ? s : null;
}

function normaliseEntity(v) {
  if (typeof v !== 'string') return null;
  const s = v.normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}&.,'()\- ]+/gu, ' ').replace(/\s+/g, ' ').trim();
  return s.length >= 3 && s.length <= 200 ? s : null;
}

const NORMALISERS = { domain: normaliseDomain, url: normaliseUrl, phone: normalisePhone, upi: normaliseUpi, entity: normaliseEntity };
function normaliseValue(type, value) { const f = NORMALISERS[type]; return f ? f(value) : null; }

function toMs(v) {
  if (v == null) return null;
  if (v instanceof Date) { const t = v.getTime(); return Number.isFinite(t) ? t : null; }
  if (typeof v === 'number') return Number.isFinite(v) && v > 0 ? Math.round(v) : null;
  if (typeof v === 'string') { const t = Date.parse(v); return Number.isFinite(t) ? t : null; }
  return null;
}

/**
 * Validate + normalise one record. Never throws.
 * @returns {{ok:true, record:object}|{ok:false, reason:string}}
 */
function validateRecord(rec, { sourceId, now = Date.now() } = {}) {
  if (!rec || typeof rec !== 'object') return { ok: false, reason: 'not_object' };
  const type = rec.type;
  if (!TYPES.has(type)) return { ok: false, reason: 'bad_type' };
  const value = normaliseValue(type, rec.value);
  if (!value) return { ok: false, reason: 'bad_value' };
  const category = typeof rec.category === 'string' ? rec.category.trim().toLowerCase().slice(0, LIMITS.maxCategoryLen) : '';
  if (!/^[a-z0-9][a-z0-9_-]*$/.test(category)) return { ok: false, reason: 'bad_category' };
  let confidence = Number(rec.confidence);
  if (!Number.isFinite(confidence)) confidence = 0.5;
  confidence = Math.min(1, Math.max(0, Math.round(confidence * 100) / 100));
  const firstSeen = toMs(rec.firstSeen) || now;
  const lastSeen = Math.max(firstSeen, toMs(rec.lastSeen) || now);
  const out = { type, value, category, source: sourceId || String(rec.source || ''), confidence, firstSeen, lastSeen };
  if (!out.source) return { ok: false, reason: 'no_source' };
  if (typeof rec.sourceUrl === 'string' && rec.sourceUrl) {
    if (!/^https?:\/\//i.test(rec.sourceUrl) || rec.sourceUrl.length > LIMITS.maxSourceUrlLen) return { ok: false, reason: 'bad_sourceUrl' };
    out.sourceUrl = rec.sourceUrl;
  }
  const exp = toMs(rec.expiresAt);
  if (exp) out.expiresAt = exp;
  if (rec.meta != null) {
    if (typeof rec.meta !== 'object' || Array.isArray(rec.meta)) return { ok: false, reason: 'bad_meta' };
    let m; try { m = JSON.stringify(rec.meta); } catch (_) { return { ok: false, reason: 'bad_meta' }; }
    if (m.length > LIMITS.maxMetaBytes) return { ok: false, reason: 'meta_too_large' };
    if (m !== '{}') out.meta = JSON.parse(m);
  }
  if (out.expiresAt && out.expiresAt <= now) return { ok: false, reason: 'already_expired' };
  return { ok: true, record: out };
}

/** Validate a batch; duplicates (same type+value) keep the higher confidence. */
function sanitizeRecords(records, { sourceId, now = Date.now(), maxRecords = LIMITS.defaultMaxRecords } = {}) {
  const byKey = new Map();
  const rejected = {};
  let rejectedCount = 0;
  if (!Array.isArray(records)) return { records: [], rejected: { not_array: 1 }, rejectedCount: 1, truncated: false };
  let truncated = false;
  for (const r of records) {
    const v = validateRecord(r, { sourceId, now });
    if (!v.ok) { rejected[v.reason] = (rejected[v.reason] || 0) + 1; rejectedCount++; continue; }
    const k = v.record.type + '\u0000' + v.record.value;
    const prev = byKey.get(k);
    if (!prev || v.record.confidence > prev.confidence) byKey.set(k, v.record);
    if (byKey.size >= maxRecords) { truncated = true; break; }
  }
  return { records: [...byKey.values()], rejected, rejectedCount, truncated };
}

// ---------------------------------------------------------------------------------------------------------------
// Polite HTTP helper
// ---------------------------------------------------------------------------------------------------------------
const sleepReal = (ms) => new Promise(r => setTimeout(r, ms));

function parseRobots(text, uaToken) {
  const groups = [];
  let cur = null, lastWasAgent = false;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) continue;
    const i = line.indexOf(':');
    if (i < 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    if (k === 'user-agent') {
      if (!lastWasAgent || !cur) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(v.toLowerCase());
      lastWasAgent = true;
    } else if ((k === 'allow' || k === 'disallow') && cur) {
      lastWasAgent = false;
      cur.rules.push({ allow: k === 'allow', path: v });
    } else lastWasAgent = false;
  }
  const tok = uaToken.toLowerCase();
  const specific = groups.filter(g => g.agents.some(a => a !== '*' && tok.includes(a)));
  const chosen = specific.length ? specific : groups.filter(g => g.agents.includes('*'));
  return chosen.flatMap(g => g.rules);
}

function robotsAllows(rules, pathAndQuery) {
  let best = null;
  for (const r of rules) {
    if (r.path === '') continue; // empty Disallow = allow all
    const re = new RegExp('^' + r.path.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\\\$$/, '$'));
    if (re.test(pathAndQuery)) {
      const len = r.path.length;
      if (!best || len > best.len || (len === best.len && r.allow)) best = { len, allow: r.allow };
    }
  }
  return !best || best.allow;
}

/**
 * Build the ctx.http helper.
 * @param {object} o { fetchImpl, userAgent, stateStore:{get,set}, sleep, now, minIntervalMs, timeoutMs, maxBytes, signal, hostIntervals }
 * Returned function: http(url, {method, headers, timeoutMs, maxBytes, robots=true, conditional=true, binary=false, force})
 *   -> { status, text|buffer, headers, etag, lastModified, notModified }
 * Throws on network error, robots disallow (err.code='ROBOTS_DISALLOWED'), oversize (err.code='TOO_LARGE'), non-2xx (err.status).
 * ETag/Last-Modified are kept *pending* (http.pending) and committed by the runner only after the source succeeded.
 */
function createHttp(o = {}) {
  const fetchImpl = o.fetchImpl || globalThis.fetch;
  const contact = process.env.INGEST_CONTACT || 'https://safemeai.in/security';
  const userAgent = o.userAgent || `SafeMeAI-ThreatIntel/1.0 (+${contact})`;
  const sleep = o.sleep || sleepReal;
  const nowFn = o.now || Date.now;
  const minInterval = o.minIntervalMs != null ? o.minIntervalMs : 1000;
  const hostNext = o.hostNext || new Map();
  const robotsCache = o.robotsCache || new Map();
  const pending = {};

  async function rawGet(url, { headers = {}, timeoutMs, maxBytes, binary, signal, method = 'GET', body } = {}) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    const onAbort = () => ac.abort();
    if (signal) { if (signal.aborted) ac.abort(); else signal.addEventListener('abort', onAbort, { once: true }); }
    try {
      const res = await fetchImpl(url, { method, body, headers: { 'User-Agent': userAgent, 'Accept-Encoding': 'gzip, br', ...headers }, signal: ac.signal, redirect: 'follow' });
      const out = { status: res.status, headers: res.headers, res };
      if (res.status === 304) return out;
      const cl = Number(res.headers && res.headers.get && res.headers.get('content-length'));
      if (Number.isFinite(cl) && cl > maxBytes) { const e = new Error(`response too large (${cl} > ${maxBytes})`); e.code = 'TOO_LARGE'; throw e; }
      const chunks = [];
      let total = 0;
      if (res.body && typeof res.body.getReader === 'function') {
        const reader = res.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          if (total > maxBytes) { try { await reader.cancel(); } catch (_) {} const e = new Error(`response exceeded ${maxBytes} bytes`); e.code = 'TOO_LARGE'; throw e; }
          chunks.push(Buffer.from(value));
        }
      } else {
        const ab = Buffer.from(await res.arrayBuffer());
        if (ab.length > maxBytes) { const e = new Error('response too large'); e.code = 'TOO_LARGE'; throw e; }
        chunks.push(ab);
      }
      const buf = Buffer.concat(chunks);
      if (binary) out.buffer = buf; else out.text = buf.toString('utf8');
      return out;
    } finally {
      clearTimeout(t);
      if (signal) signal.removeEventListener('abort', onAbort);
    }
  }

  async function throttle(host) {
    const t = nowFn();
    const next = hostNext.get(host) || 0;
    hostNext.set(host, Math.max(t, next) + minInterval);
    if (next > t) await sleep(next - t);
  }

  async function robotsOk(u, timeoutMs) {
    const key = u.origin;
    let ent = robotsCache.get(key);
    if (!ent || nowFn() - ent.at > 24 * 3600 * 1000) {
      let rules = [];
      try {
        await throttle(u.host);
        const r = await rawGet(`${u.origin}/robots.txt`, { timeoutMs: Math.min(timeoutMs, 10000), maxBytes: 512 * 1024, signal: o.signal });
        if (r.status >= 500) rules = [{ allow: false, path: '/' }];
        else if (r.status < 300 && typeof r.text === 'string') rules = parseRobots(r.text, 'SafeMeAI-ThreatIntel');
      } catch (_) { /* unreachable robots.txt = no restrictions */ }
      ent = { at: nowFn(), rules };
      robotsCache.set(key, ent);
    }
    return robotsAllows(ent.rules, u.pathname + u.search);
  }

  async function http(url, opts = {}) {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('unsupported protocol');
    const timeoutMs = opts.timeoutMs || o.timeoutMs || 30000;
    const maxBytes = opts.maxBytes || o.maxBytes || 32 * 1024 * 1024;
    if (opts.robots !== false && !(await robotsOk(u, timeoutMs))) {
      const e = new Error(`robots.txt disallows ${u.origin}${u.pathname}`); e.code = 'ROBOTS_DISALLOWED'; throw e;
    }
    const headers = { ...(opts.headers || {}) };
    const ckey = 'http:' + u.href;
    const useCond = opts.conditional !== false && !opts.force && !o.force && o.stateStore;
    if (useCond) {
      const c = await o.stateStore.get(ckey);
      if (c && c.etag) headers['If-None-Match'] = c.etag;
      if (c && c.lastModified) headers['If-Modified-Since'] = c.lastModified;
    }
    await throttle(u.host);
    const method = String(opts.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'POST') throw new Error(`unsupported method ${method}`);
    const r = await rawGet(u.href, { headers, timeoutMs, maxBytes, binary: opts.binary, signal: o.signal, method, body: method === 'POST' ? opts.body : undefined });
    if (r.status === 304) return { status: 304, notModified: true, headers: r.headers };
    if (r.status < 200 || r.status >= 300) { const e = new Error(`HTTP ${r.status} for ${u.origin}${u.pathname}`); e.status = r.status; throw e; }
    const etag = r.headers.get('etag') || null;
    const lastModified = r.headers.get('last-modified') || null;
    if (o.stateStore && opts.conditional !== false && (etag || lastModified)) pending[ckey] = { etag, lastModified };
    return { status: r.status, notModified: false, text: r.text, buffer: r.buffer, headers: r.headers, etag, lastModified };
  }
  http.pending = pending;
  http.userAgent = userAgent;
  return http;
}

module.exports = {
  TYPES, NON_THREAT_CATEGORIES, REGULATOR_CATEGORIES, LIMITS,
  normaliseDomain, normaliseUrl, normalisePhone, normaliseUpi, normaliseEntity, normaliseValue,
  validateRecord, sanitizeRecords, createHttp, parseRobots, robotsAllows
};

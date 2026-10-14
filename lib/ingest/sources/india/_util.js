'use strict';
/**
 * Shared helpers for the India regulator sources.
 * Dependency-free. Everything here is pure except `guardedResult`, which only
 * reads/writes the ctx.state it is handed.
 */
const { domainToASCII } = require('node:url');

class IndiaParseError extends Error {
  constructor(source, message) {
    super(`[${source}] ${message}`);
    this.name = 'IndiaParseError';
    this.source = source;
  }
}

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '-', mdash: '-', rsquo: "'", lsquo: "'" };
function decodeEntities(s) {
  return String(s).replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const cp = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(cp) && cp > 0 && cp < 0x110000 ? String.fromCodePoint(cp) : m;
    }
    const v = ENTITIES[e.toLowerCase()];
    return v === undefined ? m : v;
  });
}
function stripTags(s) {
  return decodeEntities(String(s).replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
}

/** Split html into rows of cell html strings. Tolerant of nested tables / unclosed tags. */
function tableRows(html) {
  const rows = [];
  const chunks = String(html).split(/<tr[\s>]/i).slice(1);
  for (const chunk of chunks) {
    const end = chunk.search(/<\/tr\s*>/i);
    const body = end >= 0 ? chunk.slice(0, end) : chunk;
    const cells = [];
    const re = /<t[dh][^>]*>([\s\S]*?)(?=<\/t[dh]\s*>|<t[dh][\s>]|$)/gi;
    let m;
    while ((m = re.exec(body))) cells.push(m[1]);
    if (cells.length) rows.push(cells);
  }
  return rows;
}

const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;
/**
 * Normalise a URL/host-ish string to a registrable-looking hostname:
 * lowercase, punycode, no www., no port/path. Returns null when not a valid DNS name
 * (including IP literals and things like "Mobile Application").
 */
function normaliseDomain(input) {
  if (input == null) return null;
  let s = String(input).trim();
  if (!s || /\s/.test(s.replace(/^\s+|\s+$/g, '')) && !/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s.replace(/^\/\//, '');
  let host;
  try { host = new URL(s).hostname; } catch { return null; }
  host = domainToASCII(host.toLowerCase().replace(/\.$/, ''));
  if (!host) return null;
  host = host.replace(/^www\d?\./, '');
  if (host.length > 253 || !HOST_RE.test(host)) return null;
  return host;
}

/** Canonical URL with path (no trailing slash, no query/hash) if it carries more than the bare host. */
function normaliseUrlWithPath(input) {
  let s = String(input || '').trim();
  if (!/^https?:\/\//i.test(s)) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  const host = normaliseDomain(u.href);
  if (!host) return null;
  const path = u.pathname.replace(/\/+$/, '');
  if (!path) return null;
  return `${u.protocol}//${host}${path}`;
}

const FREE_MAIL = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.in', 'yahoo.co.in', 'ymail.com', 'hotmail.com', 'outlook.com',
  'live.com', 'msn.com', 'rediffmail.com', 'rediff.com', 'icloud.com', 'me.com', 'aol.com', 'protonmail.com',
  'proton.me', 'zoho.com', 'zohomail.in', 'mail.com', 'gmx.com', 'yandex.com', 'sify.com', 'in.com', 'vsnl.com',
  'vsnl.net', 'bsnl.in', 'airtelmail.com', 'airtelmail.in', 'hotmail.co.in', 'outlook.in',
]);
function domainFromEmail(email) {
  const m = /@([^@\s]+)$/.exec(String(email || '').trim().toLowerCase());
  if (!m) return null;
  const d = normaliseDomain(m[1]);
  if (!d || FREE_MAIL.has(d)) return null;
  return d;
}

function isoDay(ms) { return new Date(ms).toISOString(); }

/**
 * Wrap parsed records into the fetch() return value, applying the sanity threshold.
 * Returns an Array of records carrying non-enumerable-ish metadata props:
 *   .replaceAllowed (bool)  false => caller MUST NOT replace its stored data with this result
 *   .stats {count, previousCount, reason}
 * When the count dropped by more than 50% vs the previous good run (ctx.state) we
 * return an EMPTY array with replaceAllowed=false rather than suspicious data.
 */
async function guardedResult(sourceId, ctx, records, opts = {}) {
  const key = `${sourceId}:lastCount`;
  const count = records.length;
  let previous = 0;
  try { previous = Number(await (ctx.state && ctx.state.get ? ctx.state.get(key) : 0)) || 0; } catch { previous = 0; }
  const maxDrop = opts.maxDrop == null ? 0.5 : opts.maxDrop;
  let replaceAllowed = true;
  let reason = null;
  if (count === 0) { replaceAllowed = false; reason = 'parsed zero records'; }
  else if (opts.partial) { replaceAllowed = false; reason = 'partial crawl (test mode)'; }
  else if (previous > 0 && count < previous * (1 - maxDrop)) {
    replaceAllowed = false;
    reason = `record count dropped from ${previous} to ${count} (>${Math.round(maxDrop * 100)}%)`;
  }
  const out = replaceAllowed || opts.partial ? records.slice() : [];
  Object.defineProperty(out, 'replaceAllowed', { value: replaceAllowed, enumerable: false });
  Object.defineProperty(out, 'stats', { value: { count, previousCount: previous, reason }, enumerable: false });
  if (replaceAllowed) {
    try { if (ctx.state && ctx.state.set) await ctx.state.set(key, count); } catch { /* best-effort */ }
  } else if (ctx.log) ctx.log('warn', `refusing to replace data: ${reason}`);
  return out;
}

function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) || undefined;
  const k = Object.keys(headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return k ? headers[k] : undefined;
}
function getSetCookies(headers) {
  if (!headers) return [];
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const v = getHeader(headers, 'set-cookie');
  return Array.isArray(v) ? v : v ? [v] : [];
}

function nowMs(ctx) { return typeof ctx.now === 'function' ? ctx.now() : (Number(ctx.now) || Date.now()); }

async function bodyText(res) {
  if (res && typeof res.text === 'string') return res.text;
  if (res && res.buffer && typeof res.buffer !== 'function') return Buffer.from(res.buffer).toString('utf8');
  if (res && typeof res.text === 'function') return res.text();
  if (res && typeof res.buffer === 'function') return Buffer.from(await res.buffer()).toString('utf8');
  throw new Error('http response has neither text() nor buffer()');
}

const BLOCK_MARKERS = [/Unauthori[sz]ed Access/i, /Unauthori[sz]ed Request Blocked/i, /Request Rejected/i, /window\["bobcmn"\]/, /Access Denied/i];
/**
 * GET/POST through the framework helper and refuse anything that is not the real page
 * (HTTP error, WAF/bot-challenge body). Returns {res, text, notModified}.
 */
async function httpText(ctx, sourceId, url, opts) {
  const res = await ctx.http(url, opts);
  if (res && res.notModified) return { res, text: '', notModified: true };
  if (!res || res.status !== 200) {
    throw new IndiaParseError(sourceId, `HTTP ${res && res.status} fetching ${url} (blocked or moved?)`);
  }
  const text = await bodyText(res);
  for (const re of BLOCK_MARKERS) {
    if (re.test(text.slice(0, 20000)) && text.length < 80000 && !/<table/i.test(text)) {
      throw new IndiaParseError(sourceId, `bot-challenge / block page returned for ${url}`);
    }
  }
  return { res, text, notModified: false };
}

module.exports = {
  IndiaParseError, decodeEntities, stripTags, tableRows, normaliseDomain, normaliseUrlWithPath, domainFromEmail,
  FREE_MAIL, isoDay, guardedResult, getHeader, getSetCookies, bodyText, httpText, nowMs,
};

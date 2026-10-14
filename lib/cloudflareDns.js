'use strict';
/**
 * Cloudflare security DNS (security.cloudflare-dns.com = 1.1.1.2 malware/phishing filtering) as a LIVE per-request
 * signal. Cached, 1.5 s timeout, fail-open FOR THE SIGNAL ONLY (an unavailable signal never marks a domain safe or unsafe).
 */
const ENDPOINT = 'https://security.cloudflare-dns.com/dns-query';

function interpret(json) {
  if (!json || typeof json !== 'object') return { available: false, reason: 'bad response' };
  const answers = Array.isArray(json.Answer) ? json.Answer : [];
  const sinkhole = answers.some(a => a && (a.data === '0.0.0.0' || a.data === '::'));
  const comment = [].concat(json.Comment || []).join(' ');
  const ede = Array.isArray(json.EDE) ? json.EDE : [];
  const edeBlocked = ede.some(e => [15, 16, 17, 18].includes(Number(e && (e.code != null ? e.code : e.info_code)))) || /EDE\((15|16|17|18)\)|blocked|filtered|censored/i.test(comment);
  const blocked = sinkhole || edeBlocked;
  return { available: true, blocked, status: json.Status, reason: blocked ? (sinkhole ? 'answer 0.0.0.0 (sinkholed)' : `extended DNS error: ${comment || 'filtered'}`) : null };
}

function createCloudflareCheck({ fetchImpl, timeoutMs = 1500, ttlMs = 10 * 60 * 1000, failTtlMs = 60 * 1000, max = 5000, now = Date.now } = {}) {
  const cache = new Map();
  return async function check(host) {
    host = String(host || '').toLowerCase();
    if (!host) return { available: false, reason: 'no host' };
    const hit = cache.get(host);
    if (hit && hit.exp > now()) return hit.v;
    const f = fetchImpl || globalThis.fetch;
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    let v;
    try {
      const r = await f(`${ENDPOINT}?name=${encodeURIComponent(host)}&type=A`, { headers: { Accept: 'application/dns-json' }, signal: ac.signal, redirect: 'error' });
      if (!r.ok) v = { available: false, reason: `HTTP ${r.status}` };
      else v = interpret(await r.json());
    } catch (e) { v = { available: false, reason: e.name === 'AbortError' ? 'timeout' : 'unreachable' }; }
    finally { clearTimeout(t); }
    v.provider = 'Cloudflare security DNS (1.1.1.2)';
    if (cache.size >= max) cache.delete(cache.keys().next().value);
    cache.set(host, { v, exp: now() + (v.available ? ttlMs : failTtlMs) });
    return v;
  };
}

module.exports = { createCloudflareCheck, interpret, ENDPOINT };

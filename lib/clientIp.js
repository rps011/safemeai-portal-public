'use strict';
/**
 * Real visitor IP behind Firebase Hosting -> Cloud Run.
 *
 * Direct to Cloud Run: X-Forwarded-For = "<client-supplied...>,<real client>" => Express (trust proxy 1) already
 * returns the real client (spoofed entries are ignored).
 * Via Firebase Hosting: Cloud Run sees Firebase's Google egress address as the last hop, so Express would return the
 * SAME Google address for every visitor (one shared rate-limit bucket and audit identity). Firebase puts the real
 * visitor in `Fastly-Client-IP`. That header is only trusted when the connecting hop is itself a Google address
 * AND the request carries Via: "Firebase Hosting"; any other caller's Fastly-Client-IP header is ignored.
 */
const net = require('net');

const FALLBACK_V4 = ['192.178.0.0/15', '66.249.64.0/19', '64.233.160.0/19', '66.102.0.0/20', '72.14.192.0/18', '74.125.0.0/16', '142.250.0.0/15', '172.217.0.0/16', '173.194.0.0/16', '209.85.128.0/17', '216.58.192.0/19', '216.239.32.0/19'];
const FALLBACK_V6 = ['2001:4860::/32', '2404:6800::/32', '2607:f8b0::/32', '2a00:1450::/32'];

const list = new net.BlockList();
let loaded = false;
function addCidr(c) {
  const [addr, bits] = c.split('/');
  try { list.addSubnet(addr, Number(bits), net.isIPv6(addr) ? 'ipv6' : 'ipv4'); } catch (_) { /* skip malformed */ }
}
FALLBACK_V4.forEach(addCidr); FALLBACK_V6.forEach(addCidr);

async function refreshGoogleRanges() {
  try {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 4000);
    const r = await fetch('https://www.gstatic.com/ipranges/goog.json', { signal: ctl.signal }); clearTimeout(t);
    if (!r.ok) return;
    const j = await r.json();
    for (const p of j.prefixes || []) addCidr(p.ipv4Prefix || p.ipv6Prefix || '');
    loaded = true;
  } catch (_) { /* keep fallback ranges */ }
}
let ready = Promise.resolve();
if (process.env.NODE_ENV !== 'test') {
  ready = refreshGoogleRanges();
  setInterval(refreshGoogleRanges, 24 * 3600 * 1000).unref();
}

function isGoogleIp(ip) {
  const s = String(ip || '').replace(/^::ffff:/, '');
  const fam = net.isIPv6(s) ? 'ipv6' : (net.isIPv4(s) ? 'ipv4' : null);
  return fam ? list.check(s, fam) : false;
}

/** Returns the client IP for an Express request (trust proxy must be 1). */
function clientIp(req) {
  const via = String(req.headers['via'] || '');
  const fastly = String(req.headers['fastly-client-ip'] || '').trim();
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
  const lastHop = xff[xff.length - 1];
  if (/firebase hosting/i.test(via) && net.isIP(fastly) && lastHop && isGoogleIp(lastHop)) return fastly;
  return req.ip;
}

/** Middleware: makes req.ip the real client everywhere (rate limiting, audit hashing, reports). */
function middleware() {
  return async (req, res, next) => {
    // A cold instance must not answer before Google's published ranges are loaded (otherwise the first requests
    // would see Firebase's egress address instead of the visitor). Bounded wait, then fall back to the built-in list.
    if (!loaded) await Promise.race([ready, new Promise(r => setTimeout(r, 2500))]);
    const ip = clientIp(req);
    if (ip !== req.ip) Object.defineProperty(req, 'ip', { value: ip, configurable: true });
    next();
  };
}

module.exports = { clientIp, isGoogleIp, middleware, _loaded: () => loaded };

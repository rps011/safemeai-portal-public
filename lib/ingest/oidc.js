'use strict';
/**
 * Verify a Google-signed OIDC identity token (as sent by Cloud Scheduler) without third-party deps.
 * Checks: RS256 signature against Google's JWKS, iss, aud, exp/iat, email_verified, and exact service-account email.
 * Fails CLOSED: if audience or SA email is not configured, nothing is accepted.
 */
const crypto = require('crypto');

const CERTS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);

function createVerifier({ audience, serviceAccountEmail, fetchImpl, now = Date.now, certsUrl = CERTS_URL, clockSkewSec = 60 } = {}) {
  let cache = { keys: null, exp: 0 };
  async function getKeys(force) {
    if (!force && cache.keys && cache.exp > now()) return cache.keys;
    const f = fetchImpl || globalThis.fetch;
    const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 4000);
    try {
      const r = await f(certsUrl, { signal: ac.signal, redirect: 'error' });
      if (!r.ok) throw new Error('certs HTTP ' + r.status);
      const j = await r.json();
      const m = /max-age=(\d+)/.exec((r.headers && r.headers.get && r.headers.get('cache-control')) || '');
      cache = { keys: j.keys || [], exp: now() + Math.min(Number(m ? m[1] : 3600), 24 * 3600) * 1000 };
      return cache.keys;
    } finally { clearTimeout(t); }
  }
  const b64 = (s) => Buffer.from(s, 'base64url');

  return async function verify(authHeader) {
    if (!audience || !serviceAccountEmail) return { ok: false, reason: 'not_configured' };
    const m = /^Bearer ([A-Za-z0-9._-]+)$/.exec(String(authHeader || ''));
    if (!m) return { ok: false, reason: 'no_token' };
    const parts = m[1].split('.');
    if (parts.length !== 3) return { ok: false, reason: 'malformed' };
    let header, payload;
    try { header = JSON.parse(b64(parts[0]).toString()); payload = JSON.parse(b64(parts[1]).toString()); } catch (_) { return { ok: false, reason: 'malformed' }; }
    if (header.alg !== 'RS256' || !header.kid) return { ok: false, reason: 'bad_alg' };
    let keys;
    try { keys = await getKeys(false); } catch (_) { return { ok: false, reason: 'certs_unavailable' }; }
    let jwk = keys.find(k => k.kid === header.kid);
    if (!jwk) { try { keys = await getKeys(true); jwk = keys.find(k => k.kid === header.kid); } catch (_) {} }
    if (!jwk) return { ok: false, reason: 'unknown_kid' };
    let valid = false;
    try {
      valid = crypto.verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), crypto.createPublicKey({ key: jwk, format: 'jwk' }), b64(parts[2]));
    } catch (_) { valid = false; }
    if (!valid) return { ok: false, reason: 'bad_signature' };
    const t = Math.floor(now() / 1000);
    if (!ISSUERS.has(payload.iss)) return { ok: false, reason: 'bad_issuer' };
    if (payload.aud !== audience) return { ok: false, reason: 'bad_audience' };
    if (typeof payload.exp !== 'number' || payload.exp + clockSkewSec < t) return { ok: false, reason: 'expired' };
    if (typeof payload.iat === 'number' && payload.iat - clockSkewSec > t) return { ok: false, reason: 'iat_future' };
    if (payload.email_verified !== true && payload.email_verified !== 'true') return { ok: false, reason: 'email_unverified' };
    if (String(payload.email || '').toLowerCase() !== serviceAccountEmail.toLowerCase()) return { ok: false, reason: 'wrong_service_account' };
    return { ok: true, email: payload.email };
  };
}

module.exports = { createVerifier };

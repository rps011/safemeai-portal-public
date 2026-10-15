'use strict';
// Token-bucket rate limiter with separate buckets per route group. Per-instance, in memory.
// For exact multi-instance limits use Cloud Armor / a load balancer (see docs/api.md).
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);

function defaultGroups(env = process.env) {
  return {
    check:   { burst: num(env.RL_CHECK_BURST, 20),   perMin: num(env.RL_CHECK_PER_MIN, 30) },
    gemini:  { burst: num(env.RL_GEMINI_BURST, 10),  perMin: num(env.RL_GEMINI_PER_MIN, 10) },
    doc:     { burst: num(env.RL_DOC_BURST, 6),      perMin: num(env.RL_DOC_PER_MIN, 6) },
    general: { burst: num(env.RL_GENERAL_BURST, 60), perMin: num(env.RL_GENERAL_PER_MIN, 120) }
  };
}

function groupFor(p) {
  if (/^\/api\/(health|system\/status|v1\/openapi\.json|docs)/.test(p)) return null; // never limited
  if (/^\/api\/(scam\/check|domain\/check|v1\/batch)/.test(p)) return 'check';
  if (/^\/api\/gemini\//.test(p)) return 'gemini';
  if (/^\/api\/document-ai\/analyze/.test(p)) return 'doc';
  if (/^\/api\//.test(p)) return 'general';
  return null;
}

function createLimiter({ groups = defaultGroups(), now = Date.now, maxEntries = 50000 } = {}) {
  const buckets = new Map();
  function consume(group, id, { cost = 1, mult = 1 } = {}) {
    const cfg = groups[group];
    if (!cfg) return { allowed: true, limit: 0, remaining: 0, resetSec: 0 };
    const cap = cfg.burst * mult, rate = (cfg.perMin * mult) / 60000; // tokens per ms
    const key = group + '|' + id, t = now();
    let b = buckets.get(key);
    if (!b) b = { tokens: cap, ts: t }; else { b.tokens = Math.min(cap, b.tokens + (t - b.ts) * rate); b.ts = t; }
    const need = Math.min(cost, cap);
    let allowed = false, retryAfterSec = 0;
    if (b.tokens >= need) { b.tokens -= need; allowed = true; }
    else retryAfterSec = Math.max(1, Math.ceil((need - b.tokens) / rate / 1000));
    buckets.delete(key); buckets.set(key, b); // keep Map in LRU-ish order for pruning
    if (buckets.size > maxEntries) { let n = Math.floor(maxEntries / 10); for (const k of buckets.keys()) { buckets.delete(k); if (--n <= 0) break; } }
    return { allowed, limit: Math.floor(cap), remaining: Math.floor(b.tokens), resetSec: Math.ceil((cap - b.tokens) / rate / 1000), retryAfterSec };
  }
  function prune() { // drop buckets that are full again (idle)
    const t = now();
    for (const [k, b] of buckets) {
      const cfg = groups[k.slice(0, k.indexOf('|'))];
      if (!cfg || t - b.ts > 120000 + (cfg.burst / cfg.perMin) * 60000) buckets.delete(k);
    }
  }
  const timer = setInterval(prune, 60000); if (timer.unref) timer.unref();
  return { consume, prune, size: () => buckets.size, groups };
}

/** Express middleware. Expects req.apiAuth ({keyId,tier,rpm}) and optional req.rlCost. */
function middleware(limiter, tiers) {
  return (req, res, next) => {
    const group = groupFor(req.path);
    if (!group || req.internalBatch) return next();
    const a = req.apiAuth || { keyId: null, tier: 'free', rpm: null };
    const mult = a.rpm ? a.rpm / 30 : ((tiers[a.tier] || tiers.free).mult);
    const id = a.keyId ? 'k:' + a.keyId : 'ip:' + (req.ip || 'unknown');
    const r = limiter.consume(group, id, { cost: req.rlCost || 1, mult });
    res.setHeader('X-RateLimit-Limit', String(r.limit));
    res.setHeader('X-RateLimit-Remaining', String(r.remaining));
    res.setHeader('X-RateLimit-Reset', String(r.resetSec));
    res.setHeader('X-RateLimit-Group', group);
    if (r.allowed) return next();
    res.setHeader('Retry-After', String(r.retryAfterSec));
    res.status(429).json({ error: 'Too many requests. Please slow down and retry shortly.', code: 'RATE_LIMITED', retryAfterSec: r.retryAfterSec });
  };
}

module.exports = { createLimiter, middleware, groupFor, defaultGroups };

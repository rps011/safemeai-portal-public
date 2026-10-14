'use strict';
/**
 * Wires store + registry + runner + OIDC verifier + in-process fallback scheduler. server.js calls createPlatform()
 * once; tests build their own instances with injected backends/fetch.
 */
const { createStore } = require('../threatStore');
const { loadSources } = require('./registry');
const { createRunner } = require('./runner');
const { createVerifier } = require('./oidc');

function createPlatform(opts = {}) {
  const log = opts.log || ((lvl, msg) => (lvl === 'warn' ? console.warn : console.log)(`[ThreatIntel] ${msg}`));
  const store = opts.store || createStore({ log });
  const loaded = opts.sources ? { sources: opts.sources, problems: [] } : loadSources({ log, disabled: [...(process.env.INGEST_SOURCES_DISABLE || '').split(','), ...(process.env.DISABLE_OPENPHISH === '1' ? ['openphish'] : [])].map(x => x.trim()).filter(Boolean) });
  const runner = createRunner({ store, sources: loaded.sources, log, fetchImpl: opts.fetchImpl, retries: opts.retries, backoffMs: opts.backoffMs, sleep: opts.sleep, now: opts.now });
  const verify = opts.verify || createVerifier({
    audience: process.env.INGEST_AUDIENCE, serviceAccountEmail: process.env.INGEST_SA_EMAIL, fetchImpl: opts.fetchImpl
  });

  let fallbackTimer = null;
  async function fallbackTick() {
    try {
      await store.refresh().catch(() => {});
      for (const s of runner.sources()) {
        if (await runner.isDue(s.id)) await runner.runOne(s.id);
      }
      await store.pruneExpired().catch(() => {});
    } catch (e) { log('warn', `fallback tick failed: ${e.message}`); }
  }

  return {
    store, runner, verify, sourceProblems: loaded.problems,
    async start() {
      await store.init();
      store.startRefreshTimer();
      if (process.env.INGEST_INPROCESS !== '0') {
        // Cloud Run scales to zero and throttles CPU between requests: this timer is only a best-effort safety net.
        // Cloud Scheduler (POST /internal/ingest/run) is the real driver.
        setTimeout(fallbackTick, Number(process.env.INGEST_INITIAL_DELAY_MS || 15000)).unref();
        fallbackTimer = setInterval(fallbackTick, Number(process.env.INGEST_TICK_MS || 30 * 60 * 1000));
        fallbackTimer.unref();
      }
    },
    stop() { if (fallbackTimer) clearInterval(fallbackTimer); store.stopRefreshTimer(); },
    fallbackTick
  };
}

/** Express handlers, mounted by server.js. Auth is mandatory; failed attempts are throttled per IP. */
function mountRoutes(app, platform, { log = console.warn } = {}) {
  const fails = new Map();
  const tooMany = (ip) => { const c = fails.get(ip); return c && c.reset > Date.now() && c.n >= 20; };
  const noteFail = (ip) => { const t = Date.now(); let c = fails.get(ip); if (!c || c.reset < t) c = { n: 0, reset: t + 60000 }; c.n++; fails.set(ip, c); if (fails.size > 5000) fails.clear(); };

  async function guard(req, res, next) {
    const ip = req.ip || 'unknown';
    res.setHeader('Cache-Control', 'no-store');
    if (tooMany(ip)) return res.status(429).json({ error: 'too_many_failed_attempts' });
    const v = await platform.verify(req.headers.authorization);
    if (!v.ok) {
      noteFail(ip);
      if (v.reason === 'not_configured') return res.status(503).json({ error: 'ingest_auth_not_configured' });
      log(`[ThreatIntel] rejected ingest call from ${ip}: ${v.reason}`);
      return res.status(401).json({ error: 'unauthorized' });
    }
    next();
  }

  app.post('/internal/ingest/run', guard, async (req, res) => {
    const source = String(req.query.source || 'all');
    const group = req.query.group ? String(req.query.group) : undefined;
    if (group && group !== 'global' && group !== 'india') return res.status(400).json({ error: 'bad_group' });
    const force = req.query.force === '1';
    try {
      let results;
      if (source === 'all') results = await platform.runner.runAll({ group, force });
      else {
        if (!platform.runner.getSource(source)) return res.status(404).json({ error: 'unknown_source' });
        results = [await platform.runner.runOne(source, { force })];
      }
      const failed = results.filter(r => r.ok === false).length;
      // 200 even if a source failed (per-source isolation; Scheduler must not hammer retries). 502 only if everything failed.
      res.status(results.length && failed === results.length ? 502 : 200).json({ ran: results.length, failed, results: results.map(r => ({ id: r.id, ok: r.ok, count: r.count, added: r.added, removed: r.removed, durationMs: r.durationMs, error: r.lastError || null })) });
    } catch (e) { res.status(500).json({ error: 'ingest_failed' }); }
  });

  app.get('/internal/ingest/status', guard, async (req, res) => {
    res.json(await platform.runner.status());
  });
}

module.exports = { createPlatform, mountRoutes };

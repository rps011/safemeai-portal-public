'use strict';
/**
 * Ingestion runner: per-source isolation, timeout, retry/backoff, run statistics, stale-feed policy.
 */
const { sanitizeRecords, createHttp, LIMITS } = require('./contract');

const sleepReal = (ms) => new Promise(r => setTimeout(r, ms));
const STATE_KEY = (id) => `run:${id}`;

/** 'every 6h' / 'every 30m' / 'every 1d' -> hours (default 24). */
function scheduleHours(s) {
  const m = /every\s+(\d+(?:\.\d+)?)\s*(m|h|d)/i.exec(String(s || ''));
  if (!m) return 24;
  const n = Number(m[1]);
  return m[2].toLowerCase() === 'm' ? n / 60 : m[2].toLowerCase() === 'd' ? n * 24 : n;
}

function createRunner({ store, sources = [], log = () => {}, now = Date.now, sleep = sleepReal, fetchImpl, retries, backoffMs, timeoutMs, staleHours, minHostIntervalMs } = {}) {
  const cfg = {
    retries: retries != null ? retries : Number(process.env.INGEST_RETRIES || 3),
    backoffMs: backoffMs != null ? backoffMs : 2000,
    timeoutMs: timeoutMs != null ? timeoutMs : Number(process.env.INGEST_SOURCE_TIMEOUT_MS || 180000),
    staleHours: staleHours != null ? staleHours : Number(process.env.INGEST_STALE_HOURS || 24),
    // shrink guard: a snapshot that loses >70% of >=50 previous records is treated as a broken fetch
    shrinkFloor: 50, shrinkRatio: 0.3
  };
  const byId = new Map(sources.map(s => [s.id, s]));
  const inFlight = new Map();
  const local = new Map(); // last known stats (also persisted)
  const hostNext = new Map(); const robotsCache = new Map(); // shared politeness state across sources

  const logFor = (id) => (level, msg) => log(level, `[ingest:${id}] ${msg}`);

  function sourceState(id) {
    return { get: (k) => store.getState(`src:${id}:${k}`), set: (k, v) => store.setState(`src:${id}:${k}`, v) };
  }

  async function attempt(src, { force }) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), src.timeoutMs || cfg.timeoutMs);
    const state = sourceState(src.id);
    const http = createHttp({ fetchImpl, stateStore: state, signal: ac.signal, now, sleep, hostNext, robotsCache, force, minIntervalMs: minHostIntervalMs });
    const ctx = { http, log: logFor(src.id), state, now: now(), signal: ac.signal, force: Boolean(force) };
    try {
      const result = await Promise.race([
        Promise.resolve().then(() => src.fetch(ctx)),
        new Promise((_, rej) => ac.signal.addEventListener('abort', () => rej(Object.assign(new Error('source timeout'), { code: 'TIMEOUT' })), { once: true }))
      ]);
      return { result, http, state };
    } finally { clearTimeout(t); }
  }

  async function runOne(id, { force = false } = {}) {
    const src = byId.get(id);
    if (!src) return { id, ok: false, error: 'unknown source' };
    if (inFlight.has(id)) return inFlight.get(id);
    const p = (async () => {
      const started = now();
      const prev = (await store.getState(STATE_KEY(id)).catch(() => null)) || {};
      const stats = { ...prev, id, name: src.name, group: src.group, license: src.license, schedule: src.schedule || null, lastAttempt: started, running: true };
      local.set(id, stats);
      let lastErr = null;
      const tries = Math.max(1, cfg.retries);
      for (let n = 1; n <= tries; n++) {
        try {
          let { result, http, state } = await attempt(src, { force });
          let unchanged = false;
          if (result == null) {
            // 'unchanged' (304). If we hold no data for this source, redo unconditionally.
            if (store.sourceCount(id) === 0 && !force) { ({ result, http, state } = await attempt(src, { force: true })); }
            if (result == null) unchanged = true;
          }
          let up = { added: 0, removed: 0, total: store.sourceCount(id) };
          let rejectedCount = 0, rejected = {};
          if (!unchanged) {
            const san = sanitizeRecords(result, { sourceId: id, now: started, maxRecords: src.maxRecords || LIMITS.defaultMaxRecords });
            rejectedCount = san.rejectedCount; rejected = san.rejected;
            if (san.records.length === 0) throw Object.assign(new Error(`source returned no valid records (${Array.isArray(result) ? result.length : 'non-array'} raw, rejected: ${JSON.stringify(san.rejected)})`), { permanent: true });
            const prevCount = store.sourceCount(id);
            const mode = src.mode === 'delta' ? 'delta' : 'snapshot';
            if (mode === 'snapshot' && prevCount >= cfg.shrinkFloor && san.records.length < prevCount * cfg.shrinkRatio) {
              throw Object.assign(new Error(`suspicious shrink: ${prevCount} -> ${san.records.length} records; keeping previous snapshot`), { permanent: true });
            }
            up = await store.upsertMany(san.records, { sourceId: id, sourceMeta: { name: src.name, group: src.group, license: src.license }, mode, now: started });
          }
          for (const [k, v] of Object.entries(http.pending)) await state.set(k, v);
          const ended = now();
          Object.assign(stats, {
            running: false, ok: true, unchanged, count: up.total, added: up.added, removed: up.removed, rejected: rejectedCount, rejectedReasons: rejected,
            durationMs: ended - started, lastSuccess: ended, lastError: null, consecutiveFailures: 0, attempts: n
          });
          await store.setState(STATE_KEY(id), stats).catch(() => {});
          logFor(id)('info', `ok count=${stats.count} added=${stats.added} removed=${stats.removed} ${unchanged ? '(unchanged) ' : ''}${stats.durationMs}ms`);
          return stats;
        } catch (e) {
          lastErr = e;
          logFor(id)('warn', `attempt ${n}/${tries} failed: ${e.code || ''} ${e.message}`);
          if (e.permanent || e.code === 'ROBOTS_DISALLOWED' || (e.status && e.status >= 400 && e.status < 500 && e.status !== 429 && e.status !== 408)) break;
          if (n < tries) await sleep(cfg.backoffMs * 2 ** (n - 1) * (0.75 + Math.random() * 0.5));
        }
      }
      Object.assign(stats, {
        running: false, ok: false, durationMs: now() - started, lastError: (lastErr && (lastErr.code === 'TIMEOUT' ? 'timeout' : lastErr.message) || 'unknown').slice(0, 300),
        consecutiveFailures: (prev.consecutiveFailures || 0) + 1
      });
      await store.setState(STATE_KEY(id), stats).catch(() => {});
      return stats;
    })().finally(() => inFlight.delete(id));
    inFlight.set(id, p);
    return p;
  }

  /** Run all (or a group). Sources run sequentially (politeness + bounded memory); failures never propagate. */
  async function runAll({ group, force } = {}) {
    const out = [];
    for (const s of byId.values()) {
      if (group && s.group !== group) continue;
      if (s.heavy) continue; // long crawls run as their own scheduled job (a bulk run must fit the request timeout)
      try { out.push(await runOne(s.id, { force })); } catch (e) { out.push({ id: s.id, ok: false, lastError: e.message }); }
    }
    return out;
  }

  function classify(st, src) {
    const t = now();
    const limit = (src.staleAfterHours || cfg.staleHours) * 3600 * 1000;
    if (!st.lastSuccess) return st.lastAttempt ? 'failed' : 'never-run';
    const age = t - st.lastSuccess;
    if (age > limit) return 'stale';
    return st.ok === false ? 'degraded' : 'ok';
  }

  /** Honest per-source status. `live` is true only for sources that succeeded within the stale window. */
  async function status() {
    const feeds = [];
    for (const s of byId.values()) {
      const persisted = (await store.getState(STATE_KEY(s.id)).catch(() => null)) || {};
      const st = { ...persisted, ...(local.get(s.id) && local.get(s.id).running ? local.get(s.id) : {}) };
      const state = classify(st, s);
      feeds.push({
        id: s.id, name: s.name, group: s.group, license: s.license, schedule: s.schedule || null,
        status: state, live: state === 'ok' || state === 'degraded', stale: state === 'stale',
        indicators: store.sourceCount(s.id), loadedInMemory: store.sourceMeta(s.id) ? new Date(store.sourceMeta(s.id).ingestedAt).toISOString() : null,
        lastAttempt: st.lastAttempt || null, lastSuccess: st.lastSuccess || null,
        ageSec: st.lastSuccess ? Math.round((now() - st.lastSuccess) / 1000) : null,
        lastError: st.lastError || null, consecutiveFailures: st.consecutiveFailures || 0,
        last: st.lastSuccess ? { count: st.count, added: st.added, removed: st.removed, durationMs: st.durationMs, rejected: st.rejected || 0, unchanged: Boolean(st.unchanged) } : null,
        running: Boolean(local.get(s.id) && local.get(s.id).running)
      });
    }
    return { generatedAt: new Date(now()).toISOString(), staleAfterHours: cfg.staleHours, feeds, store: store.stats() };
  }

  /** Is this source due to run (for the in-process fallback timer)? Uses persisted, cross-instance state. */
  async function isDue(id) {
    const s = byId.get(id); if (!s) return false;
    const st = (await store.getState(STATE_KEY(id)).catch(() => null)) || {};
    const interval = scheduleHours(s.schedule) * 3600 * 1000;
    const last = Math.max(st.lastAttempt || 0, 0);
    if (inFlight.has(id)) return false;
    return !last || now() - last >= interval;
  }

  return { runOne, runAll, status, isDue, peek: (id) => local.get(id) || null, sources: () => [...byId.values()], getSource: (id) => byId.get(id), config: cfg };
}

module.exports = { createRunner, scheduleHours };

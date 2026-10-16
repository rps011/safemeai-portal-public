'use strict';
// Tracks the last success/failure of external dependencies so /api/system/status can be truthful.
// In-memory, per instance. Never stores secrets or payloads - only timestamps and short error strings.
const state = new Map();

function note(name, ok, info) {
  const s = state.get(name) || { lastOk: 0, lastErr: 0, lastError: null, okCount: 0, errCount: 0 };
  const now = Date.now();
  if (ok) { s.lastOk = now; s.okCount++; } else { s.lastErr = now; s.errCount++; s.lastError = String(info || 'error').slice(0, 160); }
  state.set(name, s);
}
function get(name) { return state.get(name) || { lastOk: 0, lastErr: 0, lastError: null, okCount: 0, errCount: 0 }; }
const iso = t => (t ? new Date(t).toISOString() : null);

/** Build the public status document. `deps` supplies live getters from server.js. */
function build(deps = {}, env = process.env) {
  const g = get('gemini'), w = get('webRisk');
  const t = deps.threatStore || {};
  const a = (deps.audit && deps.audit.sinkStatus()) || {};
  return {
    status: 'success',
    generatedAt: new Date().toISOString(),
    engineVersion: deps.engineVersion || null,
    services: {
      cloudRun: { live: true, service: env.K_SERVICE || null, revision: env.K_REVISION || null },
      vertexGemini: {
        configured: env.DISABLE_GEMINI !== '1', provider: env.GEMINI_API_KEY ? 'Gemini API' : 'Vertex AI',
        location: env.VERTEX_LOCATION || 'asia-south1',
        lastSuccess: iso(g.lastOk), lastError: g.lastError, lastErrorAt: iso(g.lastErr),
        healthy: g.lastOk > 0 && g.lastOk >= g.lastErr
      },
      webRisk: {
        configured: Boolean(env.WEB_RISK_API_KEY || env.GOOGLE_API_KEY),
        lastOk: iso(w.lastOk), lastError: w.lastError, lastErrorAt: iso(w.lastErr),
        // Configured and no recorded failure (a fresh instance has made no call yet) counts as healthy; only a failure newer than the last success is unhealthy.
        healthy: w.lastErr === 0 || w.lastOk >= w.lastErr
      },
      documentAI: { configured: Boolean(env.DOCUMENT_AI_PROCESSOR) },
      bigQuery: { configured: Boolean(env.AUDIT_BIGQUERY_TABLE), auditSinkConfigured: Boolean(env.AUDIT_BIGQUERY_TABLE), table: env.AUDIT_BIGQUERY_TABLE || null },
      threatStore: {
        ready: Boolean(t.ready), indicators: t.totalIndicators || 0, backend: t.backend || null,
        lastRefresh: t.lastRefresh ? iso(t.lastRefresh) : null
      },
      auditSink: { stdout: true, bigQuery: Boolean(a.bigQueryEnabled), bufferedRows: a.buffered || 0, lastError: a.lastError || null }
    }
  };
}

function cached(fn, ttlMs = 30000) {
  let at = 0, val = null;
  return () => { if (!val || Date.now() - at > ttlMs) { val = fn(); at = Date.now(); } return val; };
}

module.exports = { note, get, build, cached };

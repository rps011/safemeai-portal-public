'use strict';
// Live analytics over the audit table (BigQuery, e.g. safemeai_audit.checks) plus threat-store facts.
// Every number returned is computed from real rows; if BigQuery cannot answer, we say so (available:false).
const gcp = require('./gcp');

const CACHE_MS = 60 * 1000;
const MAX_BYTES = 100 * 1024 * 1024;
const TIMEOUT_MS = 15000; // cold BigQuery jobs from Cloud Run can take several seconds

/** `dataset.table` from env, validated; returns the fully qualified, backticked name or null. */
function tableRef(env, proj) {
  const t = env.AUDIT_BIGQUERY_TABLE;
  if (!t || !/^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$/.test(t)) return null;
  if (!/^[a-z][a-z0-9-]{4,60}$/.test(proj || '')) return null;
  return '`' + proj + '.' + t + '`';
}

const BUCKET_SQL = "CASE WHEN risk_score IS NULL THEN 'UNSCORED' WHEN risk_score < 20 THEN 'SAFE' WHEN risk_score < 40 THEN 'LOW' " +
  "WHEN risk_score < 60 THEN 'MEDIUM' WHEN risk_score < 80 THEN 'HIGH' ELSE 'CRITICAL' END";

/** Fixed SQL. The only variables are the table identifier (validated) and @-parameters. */
function buildQueries(T) {
  return {
    totals: `SELECT COUNTIF(timestamp >= @t24h) AS checks_24h, COUNTIF(timestamp >= @t7d) AS checks_7d, COUNT(*) AS checks_30d,\n` +
      `  COUNT(DISTINCT client_net_hash) AS unique_networks_30d, COUNTIF(gemini_used) AS gemini_checks_30d, MIN(timestamp) AS first_check\n` +
      `FROM ${T}\nWHERE timestamp >= @t30d`,
    daily: `SELECT FORMAT_DATE('%Y-%m-%d', DATE(timestamp)) AS day, COUNT(*) AS checks\nFROM ${T}\n` +
      `WHERE timestamp >= @t14d\nGROUP BY day\nORDER BY day`,
    risk: `SELECT ${BUCKET_SQL} AS bucket, COUNT(*) AS checks\nFROM ${T}\nWHERE timestamp >= @t30d\nGROUP BY bucket`,
    endpoint: `SELECT endpoint, COUNT(*) AS checks,\n  APPROX_QUANTILES(latency_ms, 100)[SAFE_OFFSET(50)] AS p50_ms,\n` +
      `  APPROX_QUANTILES(latency_ms, 100)[SAFE_OFFSET(95)] AS p95_ms\nFROM ${T}\nWHERE timestamp >= @t30d\n` +
      `GROUP BY endpoint\nORDER BY checks DESC\nLIMIT 20`,
    inputType: `SELECT input_type, COUNT(*) AS checks\nFROM ${T}\nWHERE timestamp >= @t30d\nGROUP BY input_type\nORDER BY checks DESC\nLIMIT 10`,
    verdicts: `SELECT verdict, COUNT(*) AS checks\nFROM ${T}\nWHERE timestamp >= @t30d AND verdict IS NOT NULL\n` +
      `GROUP BY verdict\nORDER BY checks DESC\nLIMIT 10`
  };
}

const DAY = 86400000;
const num = v => (Number.isFinite(Number(v)) ? Number(v) : 0);
const numOrNull = v => (v == null || !Number.isFinite(Number(v)) ? null : Number(v));

/** Fill the last 14 UTC days so a quiet day shows as 0 instead of vanishing. */
function fillDays(rows, now) {
  const map = new Map(rows.map(r => [r.day, num(r.checks)]));
  const out = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now - i * DAY).toISOString().slice(0, 10);
    out.push({ day: d, checks: map.get(d) || 0 });
  }
  return out;
}

function createAnalytics({ env = process.env, runQuery = gcp.bigQueryQuery, getProject = gcp.projectId, now = Date.now, cacheMs = CACHE_MS } = {}) {
  let cache = null, inflight = null;

  async function compute() {
    const started = now();
    let proj;
    if (!env.AUDIT_BIGQUERY_TABLE) return { available: false, reason: 'AUDIT_BIGQUERY_TABLE is not configured on this deployment, so there is no audit data to analyse.' };
    try { proj = await getProject(); } catch (e) { return { available: false, reason: 'Google Cloud project could not be determined: ' + e.message }; }
    const T = tableRef(env, proj);
    if (!T) return { available: false, reason: 'AUDIT_BIGQUERY_TABLE is malformed (expected dataset.table).' };
    const sqls = buildQueries(T);
    const t = now();
    const ts = ms => new Date(ms).toISOString();
    const params = [
      { name: 't24h', type: 'TIMESTAMP', value: ts(t - DAY) },
      { name: 't7d', type: 'TIMESTAMP', value: ts(t - 7 * DAY) },
      { name: 't14d', type: 'TIMESTAMP', value: ts(t - 14 * DAY) },
      { name: 't30d', type: 'TIMESTAMP', value: ts(t - 30 * DAY) }
    ];
    const used = k => params.filter(p => new RegExp('@' + p.name + '\\b').test(sqls[k]));
    const keys = Object.keys(sqls);
    const results = await Promise.all(keys.map(k => runQuery({ sql: sqls[k], params: used(k), maxBytesBilled: MAX_BYTES, timeoutMs: TIMEOUT_MS })));
    const bad = results.find(r => !r || !r.available);
    if (bad) return { available: false, reason: (bad && bad.reason) || 'BigQuery returned no result' };
    const R = Object.fromEntries(keys.map((k, i) => [k, results[i].rows || []]));
    const tot = R.totals[0] || {};
    const total30 = num(tot.checks_30d);
    if (total30 === 0) {
      return { available: false, empty: true, reason: 'No checks recorded in the last 30 days yet. Run a few checks and refresh.', sql: sqls };
    }
    const pct = (n, d) => (d ? Math.round((1000 * n) / d) / 10 : 0);
    const ORDER = ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNSCORED'];
    const rmap = new Map(R.risk.map(r => [r.bucket, num(r.checks)]));
    const riskDistribution = ORDER.filter(b => b !== 'UNSCORED' || rmap.get(b)).map(b => ({ bucket: b, checks: rmap.get(b) || 0, share: pct(rmap.get(b) || 0, total30) }));
    return {
      available: true,
      window: { totalsFrom: ts(t - 30 * DAY), generatedAt: ts(t) },
      totals: {
        checks24h: num(tot.checks_24h), checks7d: num(tot.checks_7d), checks30d: total30,
        uniqueNetworks30d: num(tot.unique_networks_30d), firstCheckAt: tot.first_check || null
      },
      checksPerDay: fillDays(R.daily, t),
      riskDistribution,
      byEndpoint: R.endpoint.map(r => ({ endpoint: String(r.endpoint || 'unknown'), checks: num(r.checks), share: pct(num(r.checks), total30), p50Ms: numOrNull(r.p50_ms), p95Ms: numOrNull(r.p95_ms) })),
      byInputType: R.inputType.map(r => ({ inputType: String(r.input_type || 'unknown'), checks: num(r.checks), share: pct(num(r.checks), total30) })),
      geminiShare: { checks: num(tot.gemini_checks_30d), share: pct(num(tot.gemini_checks_30d), total30) },
      topVerdicts: R.verdicts.map(r => ({ verdict: String(r.verdict), checks: num(r.checks), share: pct(num(r.checks), total30) })),
      bytesProcessed: results.reduce((s, r) => s + (r.bytesProcessed || 0), 0),
      queryExecutionTimeMs: now() - started,
      sql: sqls
    };
  }

  /** Cached (60 s), de-duplicated BigQuery summary. Never throws. */
  async function bigQuerySummary() {
    if (cache && now() - cache.at < cacheMs) return { ...cache.value, cached: true };
    // Stale-while-revalidate: if we have an earlier GOOD result, answer instantly with it and refresh in the background.
    if (cache && cache.value && cache.value.available) {
      if (!inflight) { bigQuerySummary._refresh = refresh(); bigQuerySummary._refresh.catch(() => {}); }
      return { ...cache.value, cached: true, stale: true };
    }
    if (inflight) return inflight;
    return refresh();
  }

  function refresh() {
    if (inflight) return inflight;
    inflight = (async () => {
      let value;
      try { value = await compute(); } catch (e) { value = { available: false, reason: 'Analytics failed: ' + String(e.message || e).slice(0, 160) }; }
      // Failures are cached briefly too, so a down BigQuery is not hammered by every page view.
      cache = { at: now() - (value.available ? 0 : Math.max(0, cacheMs - 10000)), value };
      return { ...value, cached: false };
    })().finally(() => { inflight = null; });
    return inflight;
  }

  return { bigQuerySummary, _buildQueries: buildQueries, _tableRef: tableRef };
}

/** Real facts from the in-process threat store + runner status. */
function threatIntelFacts({ stats, feeds }) {
  const st = stats || { totalIndicators: 0, sources: {}, lastRefresh: 0 };
  const src = st.sources || {};
  const countOf = pred => Object.entries(src).filter(([id, v]) => pred(id, v)).reduce((s, [, v]) => s + num(v.count), 0);
  const feedList = Array.isArray(feeds) ? feeds : [];
  return {
    ready: Boolean(st.ready), backend: st.backend || null,
    totalIndicators: num(st.totalIndicators),
    lastRefresh: st.lastRefresh ? new Date(st.lastRefresh).toISOString() : null,
    sourcesLoaded: Object.keys(src).length,
    liveFeeds: feedList.filter(f => f.status === 'ok' && num(f.indicators) > 0).length, // healthy AND loaded in this instance
    feedsConfigured: feedList.length,
    indicatorsBySource: Object.entries(src).map(([id, v]) => ({ id, name: v.name, group: v.group, indicators: num(v.count), ingestedAt: v.ingestedAt ? new Date(v.ingestedAt).toISOString() : null }))
      .sort((a, b) => b.indicators - a.indicators),
    india: {
      rbiAlertListEntries: countOf(id => id === 'rbi-alert-list'),
      rbiAuthorisedPlatforms: countOf(id => id === 'rbi-authorised-etp'),
      sebiRegisteredEntities: countOf(id => id.startsWith('sebi-'))
    }
  };
}

module.exports = { createAnalytics, threatIntelFacts, buildQueries, tableRef, MAX_BYTES, TIMEOUT_MS, CACHE_MS };

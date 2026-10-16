'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const gcp = require('../lib/gcp');
const { createAnalytics, threatIntelFacts, buildQueries, tableRef } = require('../lib/analytics');

const ENV = { AUDIT_BIGQUERY_TABLE: 'safemeai_audit.checks' };
const T = '`fraudshield-daa79c8e.safemeai_audit.checks`';

function fakeRunner(overrides = {}, calls = []) {
  return async (q) => {
    calls.push(q);
    const key = Object.keys(buildQueries(T)).find(k => buildQueries(T)[k] === q.sql);
    if (overrides[key]) return overrides[key];
    const rows = {
      totals: [{ checks_24h: 5, checks_7d: 20, checks_30d: 100, unique_networks_30d: 7, gemini_checks_30d: 25, first_check: '2026-10-01T00:00:00.000Z' }],
      daily: [{ day: new Date().toISOString().slice(0, 10), checks: 5 }],
      risk: [{ bucket: 'SAFE', checks: 60 }, { bucket: 'CRITICAL', checks: 40 }],
      endpoint: [{ endpoint: '/api/scam/check', checks: 80, p50_ms: 120, p95_ms: 900 }, { endpoint: '/api/domain/check', checks: 20, p50_ms: null, p95_ms: null }],
      inputType: [{ input_type: 'message', checks: 70 }],
      verdicts: [{ verdict: 'SCAM', checks: 40 }]
    };
    return { available: true, rows: rows[key], bytesProcessed: 1000 };
  };
}
const mk = (o = {}) => createAnalytics({ env: ENV, getProject: async () => 'fraudshield-daa79c8e', ...o });

test('parses a summary from BigQuery rows', async () => {
  const s = await mk({ runQuery: fakeRunner() }).bigQuerySummary();
  assert.equal(s.available, true);
  assert.equal(s.totals.checks7d, 20);
  assert.equal(s.totals.uniqueNetworks30d, 7);
  assert.equal(s.checksPerDay.length, 14);
  assert.equal(s.checksPerDay[13].checks, 5);
  assert.deepEqual(s.riskDistribution.map(r => r.bucket), ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
  assert.equal(s.riskDistribution[0].share, 60);
  assert.equal(s.geminiShare.share, 25);
  assert.equal(s.byEndpoint[1].p95Ms, null);
  assert.equal(s.byEndpoint[0].p95Ms, 900);
  assert.ok(typeof s.queryExecutionTimeMs === 'number');
  assert.match(s.sql.totals, /FROM `fraudshield-daa79c8e\.safemeai_audit\.checks`/);
  assert.ok(!JSON.stringify(s).includes('client_net_hash"'));
});

test('SQL is parameterised: no interpolated values, every @param is supplied', async () => {
  const calls = [];
  await mk({ runQuery: fakeRunner({}, calls) }).bigQuerySummary();
  assert.equal(calls.length, 6);
  for (const c of calls) {
    assert.doesNotMatch(c.sql, /\d{4}-\d{2}-\d{2}T/, 'no literal timestamps');
    const used = [...c.sql.matchAll(/@(\w+)/g)].map(m => m[1]);
    assert.ok(used.length > 0);
    for (const u of used) assert.ok(c.params.some(p => p.name === u && p.type === 'TIMESTAMP'), u);
    assert.equal(c.maxBytesBilled, 100 * 1024 * 1024);
    assert.equal(c.timeoutMs, 15000);
  }
});

test('table reference is validated', () => {
  assert.equal(tableRef({ AUDIT_BIGQUERY_TABLE: 'a.b' }, 'my-project'), '`my-project.a.b`');
  assert.equal(tableRef({ AUDIT_BIGQUERY_TABLE: 'a.b`; DROP' }, 'my-project'), null);
  assert.equal(tableRef({ AUDIT_BIGQUERY_TABLE: 'a.b' }, 'bad project`'), null);
  assert.equal(tableRef({}, 'my-project'), null);
});

test('caches for 60 s then re-queries', async () => {
  let t = 1000000; const calls = [];
  const a = mk({ runQuery: fakeRunner({}, calls), now: () => t });
  await a.bigQuerySummary(); assert.equal(calls.length, 6);
  t += 59000; const hit = await a.bigQuerySummary(); assert.equal(calls.length, 6); assert.equal(hit.cached, true);
  t += 2000; await a.bigQuerySummary(); assert.equal(calls.length, 12);
});

test('concurrent calls share one in-flight computation', async () => {
  const calls = [];
  const a = mk({ runQuery: fakeRunner({}, calls) });
  await Promise.all([a.bigQuerySummary(), a.bigQuerySummary(), a.bigQuerySummary()]);
  assert.equal(calls.length, 6);
});

test('fails soft when not configured, unreachable or empty', async () => {
  let r = await createAnalytics({ env: {}, runQuery: async () => assert.fail('no query') }).bigQuerySummary();
  assert.equal(r.available, false); assert.match(r.reason, /AUDIT_BIGQUERY_TABLE/);

  r = await mk({ runQuery: async () => ({ available: false, reason: 'BigQuery HTTP 403' }) }).bigQuerySummary();
  assert.deepEqual([r.available, r.reason], [false, 'BigQuery HTTP 403']);
  assert.equal(r.totals, undefined);

  r = await mk({ runQuery: async () => { throw new Error('boom'); } }).bigQuerySummary();
  assert.equal(r.available, false); assert.match(r.reason, /boom/);

  r = await mk({ runQuery: fakeRunner({ totals: { available: true, rows: [{ checks_30d: 0 }] } }) }).bigQuerySummary();
  assert.equal(r.available, false); assert.equal(r.empty, true); assert.match(r.reason, /No checks/);
});

test('failure is cached only briefly', async () => {
  let t = 5000000, n = 0;
  const a = mk({ now: () => t, runQuery: async () => { n++; return { available: false, reason: 'down' }; } });
  await a.bigQuerySummary(); const first = n;
  await a.bigQuerySummary(); assert.equal(n, first);
  t += 11000; await a.bigQuerySummary(); assert.ok(n > first);
});

test('gcp.bigQueryQuery builds a parameterised jobs.query request and parses typed rows', async () => {
  const orig = global.fetch; let seen;
  global.fetch = async (url, init) => {
    if (String(url).includes('metadata.google.internal')) {
      const body = String(url).endsWith('/token') ? { access_token: 'tok', expires_in: 3600 } : null;
      return new Response(body ? JSON.stringify(body) : 'fraudshield-daa79c8e', { status: 200 });
    }
    seen = { url: String(url), body: JSON.parse(init.body), auth: init.headers.Authorization };
    return new Response(JSON.stringify({
      jobComplete: true, totalBytesProcessed: '2048', cacheHit: false,
      schema: { fields: [{ name: 'n', type: 'INTEGER' }, { name: 'b', type: 'BOOLEAN' }, { name: 's', type: 'STRING' }, { name: 'ts', type: 'TIMESTAMP' }] },
      rows: [{ f: [{ v: '42' }, { v: 'true' }, { v: 'x' }, { v: '1.7e9' }] }, { f: [{ v: null }, { v: 'false' }, { v: null }, { v: null }] }]
    }), { status: 200 });
  };
  try {
    const r = await gcp.bigQueryQuery({ sql: 'SELECT @a', params: [{ name: 'a', type: 'TIMESTAMP', value: '2026-01-01T00:00:00Z' }] });
    assert.equal(r.available, true);
    assert.deepEqual(r.rows[0], { n: 42, b: true, s: 'x', ts: new Date(1.7e9 * 1000).toISOString() });
    assert.deepEqual(r.rows[1], { n: null, b: false, s: null, ts: null });
    assert.equal(r.bytesProcessed, 2048);
    assert.equal(seen.body.location, 'asia-south1');
    assert.equal(seen.body.maximumBytesBilled, String(100 * 1024 * 1024));
    assert.equal(seen.body.timeoutMs, 5000);
    assert.equal(seen.body.parameterMode, 'NAMED');
    assert.deepEqual(seen.body.queryParameters[0], { name: 'a', parameterType: { type: 'TIMESTAMP' }, parameterValue: { value: '2026-01-01T00:00:00Z' } });
    assert.equal(seen.auth, 'Bearer tok');
  } finally { global.fetch = orig; }
});

test('gcp.bigQueryQuery reports HTTP errors and incomplete jobs honestly', async () => {
  const mkFetch = (status, json) => async (url) => String(url).includes('metadata')
    ? new Response(String(url).endsWith('/token') ? JSON.stringify({ access_token: 't', expires_in: 3600 }) : 'p', { status: 200 })
    : new Response(JSON.stringify(json), { status });
  const orig = global.fetch;
  try {
    global.fetch = mkFetch(403, { error: { message: 'Access Denied' } });
    let r = await gcp.bigQueryQuery({ sql: 'SELECT 1' });
    assert.equal(r.available, false); assert.match(r.reason, /403.*Access Denied/);
    global.fetch = mkFetch(200, { jobComplete: false });
    r = await gcp.bigQueryQuery({ sql: 'SELECT 1' });
    assert.equal(r.available, false); assert.match(r.reason, /time limit/);
  } finally { global.fetch = orig; }
});

test('threatIntelFacts summarises real store stats', () => {
  const f = threatIntelFacts({
    stats: { ready: true, backend: 'memory', lastRefresh: 1700000000000, totalIndicators: 30, sources: {
      'rbi-alert-list': { name: 'RBI', group: 'india', count: 10, ingestedAt: 1700000000000 },
      'sebi-stock-brokers': { name: 'SEBI B', group: 'india', count: 5 },
      'sebi-research-analysts': { name: 'SEBI R', group: 'india', count: 3 },
      openphish: { name: 'OP', group: 'global', count: 12 } } },
    feeds: [{ status: 'ok', indicators: 5 }, { status: 'stale', indicators: 2 }, { status: 'ok', indicators: 1 }, { status: 'ok', indicators: 0 }]
  });
  assert.equal(f.india.rbiAlertListEntries, 10);
  assert.equal(f.india.sebiRegisteredEntities, 8);
  assert.equal(f.liveFeeds, 2); assert.equal(f.feedsConfigured, 4);
  assert.equal(f.totalIndicators, 30);
  assert.equal(f.indicatorsBySource[0].id, 'openphish');
  const empty = threatIntelFacts({ stats: null, feeds: null });
  assert.equal(empty.totalIndicators, 0); assert.equal(empty.lastRefresh, null);
});

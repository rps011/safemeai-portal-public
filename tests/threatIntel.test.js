'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const express = require('express');

const C = require('../lib/ingest/contract');
const { createStore, memoryBackend, fileBackend, firestoreBackend } = require('../lib/threatStore');
const { createRunner } = require('../lib/ingest/runner');
const { createVerifier } = require('../lib/ingest/oidc');
const { createPlatform, mountRoutes } = require('../lib/ingest/platform');
const { createCloudflareCheck, interpret } = require('../lib/cloudflareDns');
const { loadSources } = require('../lib/ingest/registry');
const engine = require('../lib/domainEngine');

const NOW = Date.parse('2026-10-14T00:00:00Z');
const noSleep = async () => {};
const rec = (o) => ({ type: 'domain', value: 'evil.example.com', category: 'phishing', source: 'x', confidence: 0.9, ...o });

function fakeFetch(routes) {
  const calls = [];
  const f = async (url, opts = {}) => {
    calls.push({ url: String(url), opts });
    const r = routes[String(url)] || routes['*'];
    if (!r) throw new Error('no route ' + url);
    const x = typeof r === 'function' ? await r(String(url), opts) : r;
    const headers = new Map(Object.entries(x.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    const body = x.body == null ? Buffer.alloc(0) : Buffer.isBuffer(x.body) ? x.body : Buffer.from(String(x.body));
    return {
      ok: (x.status || 200) < 300, status: x.status || 200, headers: { get: (k) => headers.get(k.toLowerCase()) ?? null },
      arrayBuffer: async () => body, text: async () => body.toString(), json: async () => JSON.parse(body.toString())
    };
  };
  f.calls = calls;
  return f;
}

// ------------------------------------------------------------------------------------------ contract
test('normalisers accept good values and reject junk', () => {
  assert.equal(C.normaliseDomain(' *.Evil.Example.COM. '), 'evil.example.com');
  assert.equal(C.normaliseDomain('bücher.example'), 'xn--bcher-kva.example');
  for (const bad of ['', 'nodots', '1.2.3.4', 'a b.com', 'http://x.com', '-x.com', 'x'.repeat(64) + '.com', null, 5]) assert.equal(C.normaliseDomain(bad), null, String(bad));
  assert.equal(C.normaliseUrl('HTTP://Evil.com/Path#frag'), 'http://evil.com/path');
  assert.equal(C.normaliseUrl('evil.com'), 'http://evil.com');
  assert.equal(C.normaliseUrl('javascript:alert(1)'), null);
  assert.equal(C.normalisePhone('98765 43210'), '+919876543210');
  assert.equal(C.normalisePhone('+91-98765-43210'), '+919876543210');
  assert.equal(C.normalisePhone('09876543210'), '+919876543210');
  assert.equal(C.normalisePhone('12345'), null);
  assert.equal(C.normaliseUpi('Refund.Desk@ICICI'), 'refund.desk@icici');
  assert.equal(C.normaliseUpi('nope'), null);
  assert.equal(C.normaliseEntity('  Quick  Gains Pvt. Ltd!! '), 'quick gains pvt. ltd');
});

test('validateRecord / sanitizeRecords reject junk, cap size, dedupe', () => {
  assert.equal(C.validateRecord({ type: 'x' }, { sourceId: 's' }).reason, 'bad_type');
  assert.equal(C.validateRecord(rec({ category: 'Bad Cat!' }), { sourceId: 's' }).reason, 'bad_category');
  assert.equal(C.validateRecord(rec({ meta: { a: 'x'.repeat(2000) } }), { sourceId: 's' }).reason, 'meta_too_large');
  assert.equal(C.validateRecord(rec({ sourceUrl: 'javascript:1' }), { sourceId: 's' }).reason, 'bad_sourceUrl');
  const ok = C.validateRecord(rec({ confidence: 7, firstSeen: '2026-01-01T00:00:00Z' }), { sourceId: 's', now: NOW });
  assert.ok(ok.ok); assert.equal(ok.record.confidence, 1); assert.equal(ok.record.source, 's'); assert.equal(typeof ok.record.firstSeen, 'number');
  const s = C.sanitizeRecords([rec({ confidence: 0.3 }), rec({ confidence: 0.8 }), rec({ value: 'bad' })], { sourceId: 's', now: NOW });
  assert.equal(s.records.length, 1); assert.equal(s.records[0].confidence, 0.8); assert.equal(s.rejectedCount, 1);
  assert.equal(C.sanitizeRecords(null, { sourceId: 's' }).records.length, 0);
});

// ------------------------------------------------------------------------------------------ http helper
test('http: UA, robots disallow, conditional GET committed only via pending, size cap, rate limit', async () => {
  const f = fakeFetch({
    'https://a.test/robots.txt': { body: 'User-agent: *\nDisallow: /private\n' },
    'https://a.test/feed.txt': () => ({ body: 'hello', headers: { etag: '"v1"' } }),
    'https://a.test/private/x': { body: 'no' },
    'https://a.test/big': { body: Buffer.alloc(5000) }
  });
  const store = new Map();
  const sleeps = [];
  let t = 1000;
  const h = C.createHttp({ fetchImpl: f, stateStore: { get: async k => store.get(k) || null, set: async (k, v) => store.set(k, v) }, sleep: async ms => { sleeps.push(ms); t += ms; }, now: () => t, minIntervalMs: 500 });
  const r = await h('https://a.test/feed.txt');
  assert.equal(r.text, 'hello');
  assert.match(f.calls.at(-1).opts.headers['User-Agent'], /^SafeMeAI-ThreatIntel\/1\.0 \(\+/);
  assert.deepEqual(h.pending['http:https://a.test/feed.txt'], { etag: '"v1"', lastModified: null });
  await assert.rejects(h('https://a.test/private/x'), { code: 'ROBOTS_DISALLOWED' });
  await assert.rejects(h('https://a.test/big', { maxBytes: 100 }), { code: 'TOO_LARGE' });
  assert.ok(sleeps.length >= 1, 'per-host rate limit slept');
  // now with stored etag the request is conditional and 304 maps to notModified
  store.set('http:https://a.test/feed.txt', { etag: '"v1"' });
  const f2 = fakeFetch({ 'https://a.test/robots.txt': { status: 404 }, 'https://a.test/feed.txt': { status: 304 } });
  const h2 = C.createHttp({ fetchImpl: f2, stateStore: { get: async k => store.get(k) || null, set: async () => {} }, sleep: noSleep, minIntervalMs: 0 });
  const r2 = await h2('https://a.test/feed.txt');
  assert.equal(r2.notModified, true);
  assert.equal(f2.calls.at(-1).opts.headers['If-None-Match'], '"v1"');
  const f3 = fakeFetch({ 'https://a.test/robots.txt': { status: 404 }, 'https://a.test/e': { status: 500 } });
  await assert.rejects(C.createHttp({ fetchImpl: f3, sleep: noSleep, minIntervalMs: 0 })('https://a.test/e'), { status: 500 });
});

test('robots parser: longest match wins, specific agent group preferred', () => {
  const rules = C.parseRobots('User-agent: *\nDisallow: /\n\nUser-agent: SafeMeAI-ThreatIntel\nDisallow: /admin\nAllow: /admin/public\n', 'SafeMeAI-ThreatIntel');
  assert.equal(C.robotsAllows(rules, '/feed'), true);
  assert.equal(C.robotsAllows(rules, '/admin/x'), false);
  assert.equal(C.robotsAllows(rules, '/admin/public/a'), true);
});

// ------------------------------------------------------------------------------------------ store
test('store: snapshot replace, added/removed, lookups, suffixes, popularRank, state', async () => {
  const st = createStore({ backend: memoryBackend(), now: () => NOW });
  await st.init();
  let r = await st.upsertMany([rec({ value: 'a.com' }), rec({ value: 'b.com' }), rec({ type: 'phone', value: '+919876543210', category: 'fraud-report' })], { sourceId: 'x', sourceMeta: { name: 'X Feed' } });
  assert.deepEqual(r, { added: 3, removed: 0, total: 3 });
  r = await st.upsertMany([rec({ value: 'b.com' }), rec({ value: 'c.com' })], { sourceId: 'x', sourceMeta: { name: 'X Feed' } });
  assert.deepEqual([r.added, r.removed, r.total], [1, 2, 2]);
  assert.equal(st.lookup('domain', 'a.com').length, 0);
  const hit = st.lookup('domain', 'b.com')[0];
  assert.equal(hit.sourceName, 'X Feed'); assert.equal(hit.ingestedAt, NOW); assert.equal(hit.category, 'phishing');
  assert.equal(st.lookupDomainSuffixes('login.pay.c.com').length, 1);
  assert.equal(st.lookupDomainSuffixes('com').length, 0);
  await st.upsertMany([{ ...rec({ value: 'github.com', category: 'popular-site', confidence: 1 }), meta: { rank: 42 } }], { sourceId: 't', sourceMeta: { name: 'T' } });
  assert.equal(st.popularRank('github.com').rank, 42);
  assert.equal(st.lookupThreats('domain', 'github.com').length, 0);
  await st.upsertMany([rec({ value: 'd.com' })], { sourceId: 'x', mode: 'delta' });
  assert.equal(st.sourceCount('x'), 3);
  await st.setState('k', { a: 1 }); assert.deepEqual(await st.getState('k'), { a: 1 });
  assert.equal(st.stats().totalIndicators, 4);
});

test('store: bulk (compact) mode round-trips through the file backend and refresh picks up other writers', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-'));
  const a = createStore({ backend: fileBackend(dir), now: () => NOW });
  const recs = []; for (let i = 0; i < 20500; i++) recs.push(rec({ value: `d${i}.bulk.example`, source: 'bulk' }));
  recs.push({ ...rec({ value: 'rich.bulk.example', source: 'bulk' }), meta: { regulator: 'SEBI' } });
  await a.upsertMany(recs, { sourceId: 'bulk', sourceMeta: { name: 'Bulk', license: 'MIT' } });
  const b = createStore({ backend: fileBackend(dir), now: () => NOW });
  await b.init();
  assert.equal(b.sourceCount('bulk'), 20501);
  assert.equal(b.lookup('domain', 'd77.bulk.example')[0].sourceName, 'Bulk');
  assert.equal(b.lookup('domain', 'rich.bulk.example')[0].meta.regulator, 'SEBI');
  // writer replaces, reader refreshes
  await a.upsertMany([rec({ value: 'only.example.com', source: 'bulk' })], { sourceId: 'bulk', sourceMeta: { name: 'Bulk' }, now: NOW + 1000 });
  await b.refresh();
  assert.equal(b.sourceCount('bulk'), 1);
  assert.equal(b.lookup('domain', 'd77.bulk.example').length, 0);
});

test('store: pruneExpired drops expired rich records and persists', async () => {
  let now = NOW;
  const be = memoryBackend();
  const st = createStore({ backend: be, now: () => now });
  await st.upsertMany([rec({ value: 'short.com', expiresAt: NOW + 1000 }), rec({ value: 'long.com' })], { sourceId: 'x', now });
  assert.equal(st.lookup('domain', 'short.com').length, 1);
  now = NOW + 5000;
  assert.equal(st.lookup('domain', 'short.com').length, 0);
  assert.equal(await st.pruneExpired(), 1);
  assert.equal(st.sourceCount('x'), 1);
});

test('firestore backend (fake db): chunks a large snapshot, flips generation, cleans old chunks', async () => {
  const data = new Map();
  const mkdoc = (col, id) => ({
    async get() { const k = col + '/' + id; const v = data.get(k); return { exists: data.has(k), id, data: () => v }; },
    async set(v) { data.set(col + '/' + id, v); },
    async delete() { data.delete(col + '/' + id); }
  });
  const db = { collection: (col) => ({ doc: (id) => mkdoc(col, id), async get() { const docs = [...data].filter(([k]) => k.startsWith(col + '/')).map(([k, v]) => ({ id: k.slice(col.length + 1), data: () => v })); return { forEach: (f) => docs.forEach(f) }; } }) };
  const be = firestoreBackend({ db, prefix: 't' });
  const big = crypto.randomBytes(2_000_000);
  await be.saveSource('s1', big, { id: 's1', ingestedAt: 1 });
  const chunks1 = [...data.keys()].filter(k => k.startsWith('t_chunks/')).length;
  assert.equal(chunks1, 3);
  assert.deepEqual(await be.loadSource('s1'), big);
  await be.saveSource('s1', Buffer.from('small'), { id: 's1', ingestedAt: 2 });
  assert.equal([...data.keys()].filter(k => k.startsWith('t_chunks/')).length, 1);
  assert.equal((await be.loadSource('s1')).toString(), 'small');
  assert.equal((await be.loadMeta()).s1.ingestedAt, 2);
  await be.setState('src:a/b', { z: 1 }); assert.deepEqual(await be.getState('src:a/b'), { z: 1 });
  // end-to-end through createStore
  const st = createStore({ backend: be, now: () => NOW });
  await st.upsertMany([rec({ value: 'fs.example.com' })], { sourceId: 'fs' });
  const st2 = createStore({ backend: be, now: () => NOW }); await st2.init();
  assert.equal(st2.lookup('domain', 'fs.example.com').length, 1);
});

// ------------------------------------------------------------------------------------------ runner
function mkSource(over) {
  return { id: 'src-a', name: 'Source A', group: 'global', schedule: 'every 6h', license: 'test', async fetch() { return [rec({ value: 'one.example.com' }), rec({ value: 'two.example.com' })]; }, ...over };
}

test('runner: isolation, retries/backoff, stats, stale policy', async () => {
  let now = NOW;
  const store = createStore({ backend: memoryBackend(), now: () => now });
  let flaky = 0;
  const sources = [
    mkSource({ id: 'ok-1' }),
    mkSource({ id: 'boom', async fetch() { throw new Error('upstream down'); } }),
    mkSource({ id: 'flaky', async fetch() { if (++flaky < 3) throw new Error('503'); return [rec({ value: 'f.example.com' })]; } }),
    mkSource({ id: 'hang', timeoutMs: 30, async fetch() { return new Promise(() => {}); } }),
    mkSource({ id: 'bad-4xx', async fetch() { const e = new Error('nope'); e.status = 404; throw e; } })
  ];
  const sleeps = [];
  const runner = createRunner({ store, sources, now: () => now, sleep: async ms => sleeps.push(ms), retries: 3, backoffMs: 10 });
  const res = await runner.runAll();
  assert.equal(res.length, 5);
  const by = Object.fromEntries(res.map(r => [r.id, r]));
  assert.equal(by['ok-1'].ok, true); assert.equal(by['ok-1'].count, 2); assert.equal(by['ok-1'].added, 2);
  assert.equal(by.boom.ok, false); assert.equal(by.boom.lastError, 'upstream down'); assert.equal(by.boom.consecutiveFailures, 1);
  assert.equal(by.flaky.ok, true); assert.equal(by.flaky.attempts, 3);
  assert.equal(by.hang.lastError, 'timeout');
  assert.equal(flaky, 3); assert.ok(sleeps.length >= 2 + 2);
  assert.equal(store.lookup('domain', 'one.example.com').length, 1);   // others' failures did not break ok-1
  let st = await runner.status();
  const f = Object.fromEntries(st.feeds.map(x => [x.id, x]));
  assert.equal(f['ok-1'].status, 'ok'); assert.equal(f['ok-1'].live, true);
  assert.equal(f.boom.status, 'failed'); assert.equal(f.boom.live, false);
  // 25h later: no new success -> stale, NOT live
  now += 25 * 3600 * 1000;
  st = await runner.status();
  const f2 = Object.fromEntries(st.feeds.map(x => [x.id, x]));
  assert.equal(f2['ok-1'].status, 'stale'); assert.equal(f2['ok-1'].live, false); assert.equal(f2['ok-1'].stale, true);
});

test('runner: failure after success is "degraded" and keeps old data; shrink guard and empty result keep previous snapshot', async () => {
  let now = NOW; let mode = 'ok';
  const store = createStore({ backend: memoryBackend(), now: () => now });
  const many = []; for (let i = 0; i < 100; i++) many.push(rec({ value: `h${i}.example.com` }));
  const src = mkSource({ id: 'g', async fetch() { if (mode === 'fail') throw new Error('x'); if (mode === 'shrink') return many.slice(0, 5); if (mode === 'empty') return []; return many; } });
  const runner = createRunner({ store, sources: [src], now: () => now, sleep: noSleep, retries: 1 });
  assert.equal((await runner.runOne('g')).count, 100);
  now += 3600000;
  for (const m of ['fail', 'shrink', 'empty']) {
    mode = m;
    const r = await runner.runOne('g');
    assert.equal(r.ok, false, m);
    assert.equal(store.sourceCount('g'), 100, m);
  }
  const st = (await runner.status()).feeds[0];
  assert.equal(st.status, 'degraded'); assert.equal(st.live, true); assert.ok(st.lastError);
});

test('runner: null = unchanged keeps snapshot; with empty store it re-fetches unconditionally', async () => {
  const store = createStore({ backend: memoryBackend(), now: () => NOW });
  const seen = [];
  const src = mkSource({ id: 'u', async fetch(ctx) { seen.push(ctx.force); return ctx.force ? [rec({ value: 'z.example.com' })] : null; } });
  const runner = createRunner({ store, sources: [src], now: () => NOW, sleep: noSleep, retries: 1 });
  const r = await runner.runOne('u');
  assert.deepEqual(seen, [false, true]); assert.equal(r.count, 1);
  const r2 = await runner.runOne('u');
  assert.equal(r2.unchanged, true); assert.equal(r2.count, 1); assert.equal(r2.ok, true);
});

test('runner: ETag is committed only after a successful ingest', async () => {
  const store = createStore({ backend: memoryBackend(), now: () => NOW });
  let fail = true;
  const f = fakeFetch({ 'https://h.test/robots.txt': { status: 404 }, 'https://h.test/f': { body: 'a.example.com\n', headers: { etag: '"e1"' } } });
  const src = mkSource({ id: 'e', async fetch(ctx) { const r = await ctx.http('https://h.test/f'); if (fail) throw new Error('parse'); return r.text.split('\n').filter(Boolean).map(v => rec({ value: v })); } });
  const runner = createRunner({ store, sources: [src], now: () => NOW, sleep: noSleep, retries: 1, fetchImpl: f, minHostIntervalMs: 0 });
  await runner.runOne('e');
  assert.equal(await store.getState('src:e:http:https://h.test/f'), null);
  fail = false;
  await runner.runOne('e');
  assert.deepEqual(await store.getState('src:e:http:https://h.test/f'), { etag: '"e1"', lastModified: null });
});

test('registry loads shipped global sources and skips invalid modules', () => {
  const { sources } = loadSources({ disabled: [] });
  const ids = sources.map(s => s.id);
  for (const id of ['phishing-database', 'urlhaus', 'openphish', 'tranco']) assert.ok(ids.includes(id), id);
  for (const s of sources) assert.ok(s.license && s.name && s.group);
  assert.ok(!loadSources({ disabled: ['openphish'] }).sources.some(s => s.id === 'openphish'));
});

// ------------------------------------------------------------------------------------------ global sources
async function runSource(src, routes, extra = {}) {
  const store = createStore({ backend: memoryBackend(), now: () => NOW });
  const f = fakeFetch({ '*': { status: 404 }, ...routes });
  const runner = createRunner({ store, sources: [src], now: () => NOW, sleep: noSleep, retries: 1, fetchImpl: f, minHostIntervalMs: 0 });
  const stats = await runner.runOne(src.id);
  return { store, stats, f };
}

test('source phishing-database parses domains and skips comments/junk', async () => {
  const src = require('../lib/ingest/sources/global/phishingDatabase');
  const { store, stats } = await runSource(src, { [`https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt`]: { body: '# c\nbad-bank-login.xyz\n\nNOT A DOMAIN\nSub.Evil.Top\n' } });
  assert.equal(stats.ok, true); assert.equal(stats.count, 2); assert.equal(stats.rejected, 1);
  assert.equal(store.lookup('domain', 'sub.evil.top')[0].category, 'phishing');
});

test('source urlhaus sends Auth-Key when configured; urls high confidence, hosts weak', async () => {
  const src = require('../lib/ingest/sources/global/urlhaus');
  process.env.URLHAUS_AUTH_KEY = 'k123';
  try {
    const { store, stats, f } = await runSource(src, { 'https://urlhaus.abuse.ch/downloads/text_online/': { body: '# header\nhttp://203.0.113.5/bad.exe\nhttp://mal.example.org/x.apk\n' } });
    assert.equal(stats.ok, true);
    assert.equal(f.calls.find(c => c.url.includes('text_online')).opts.headers['Auth-Key'], 'k123');
    assert.equal(store.lookup('url', C.normaliseUrl('http://mal.example.org/x.apk'))[0].confidence, 0.95);
    assert.equal(store.lookup('domain', 'mal.example.org')[0].confidence, 0.5);
  } finally { delete process.env.URLHAUS_AUTH_KEY; }
});

test('source openphish yields url + domain records', async () => {
  const src = require('../lib/ingest/sources/global/openphish');
  const { store, stats } = await runSource(src, { 'https://openphish.com/feed.txt': { body: 'https://www.paypa1-login.example.top/a?b=1\nnot a url\n' } });
  assert.equal(stats.ok, true);
  assert.equal(store.lookup('domain', 'paypa1-login.example.top')[0].source, 'openphish');
  assert.equal(store.lookup('url', C.normaliseUrl('https://www.paypa1-login.example.top/a?b=1')).length, 1);
});

function makeZip(name, content) {
  const raw = Buffer.from(content); const comp = zlib.deflateRawSync(raw); const nm = Buffer.from(name);
  const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(nm.length, 26);
  const local = Buffer.concat([lh, nm, comp]);
  const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(0, 42);
  const cd = Buffer.concat([ch, nm]);
  const e = Buffer.alloc(22); e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(1, 8); e.writeUInt16LE(1, 10); e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(local.length, 16);
  return Buffer.concat([local, cd, e]);
}

test('source tranco unzips with node zlib and keeps rank (top 100k only)', async () => {
  const src = require('../lib/ingest/sources/global/tranco');
  let csv = '1,google.com\n2,facebook.com\n3,github.com\n'; for (let i = 4; i <= 100005; i++) csv += `${i},site${i}.example\n`;
  const { store, stats } = await runSource(src, { 'https://tranco-list.eu/top-1m.csv.zip': { body: makeZip('top-1m.csv', csv) } });
  assert.equal(stats.ok, true); assert.equal(stats.count, 100000);
  assert.equal(store.popularRank('github.com').rank, 3);
  assert.equal(store.popularRank('site100001.example'), null);
});

// ------------------------------------------------------------------------------------------ OIDC
test('OIDC verifier: accepts a valid Google-style token, rejects every tampering', async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
  const f = fakeFetch({ 'https://www.googleapis.com/oauth2/v3/certs': { body: JSON.stringify({ keys: [jwk] }), headers: { 'cache-control': 'public, max-age=3600' } } });
  const AUD = 'https://svc.run.app', SA = 'sched@p.iam.gserviceaccount.com';
  const verify = createVerifier({ audience: AUD, serviceAccountEmail: SA, fetchImpl: f, now: () => NOW });
  const mk = (claims, { kid = 'k1', key = privateKey, alg = 'RS256' } = {}) => {
    const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const head = b({ alg, kid, typ: 'JWT' }); const body = b({ iss: 'https://accounts.google.com', aud: AUD, email: SA, email_verified: true, iat: NOW / 1000 - 10, exp: NOW / 1000 + 3000, ...claims });
    const sig = crypto.sign('RSA-SHA256', Buffer.from(head + '.' + body), key).toString('base64url');
    return `Bearer ${head}.${body}.${sig}`;
  };
  assert.equal((await verify(mk({}))).ok, true);
  assert.equal((await verify(mk({ aud: 'https://other' }))).reason, 'bad_audience');
  assert.equal((await verify(mk({ email: 'evil@p.iam.gserviceaccount.com' }))).reason, 'wrong_service_account');
  assert.equal((await verify(mk({ exp: NOW / 1000 - 3600 }))).reason, 'expired');
  assert.equal((await verify(mk({ iss: 'https://evil.com' }))).reason, 'bad_issuer');
  assert.equal((await verify(mk({ email_verified: false }))).reason, 'email_unverified');
  assert.equal((await verify(mk({}, { key: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey }))).reason, 'bad_signature');
  assert.equal((await verify(mk({}, { kid: 'nope' }))).reason, 'unknown_kid');
  assert.equal((await verify(undefined)).reason, 'no_token');
  assert.equal((await verify('Bearer a.b')).reason, 'malformed');
  const unconf = createVerifier({ fetchImpl: f, now: () => NOW });
  assert.equal((await unconf(mk({}))).reason, 'not_configured');
});

// ------------------------------------------------------------------------------------------ routes
test('ingest routes: unauthenticated -> 401, unconfigured -> 503, authorised runs and reports status', async () => {
  const store = createStore({ backend: memoryBackend(), now: () => NOW });
  const mkApp = (verify) => {
    const platform = createPlatform({ store, sources: [mkSource({ id: 'r1' }), mkSource({ id: 'r2', group: 'india', async fetch() { throw new Error('x'); } })], verify, retries: 1, sleep: noSleep });
    const app = express(); mountRoutes(app, platform, { log: () => {} });
    return new Promise(res => { const s = app.listen(0, () => res({ s, base: `http://127.0.0.1:${s.address().port}`, platform })); });
  };
  const good = async (h) => (h === 'Bearer good' ? { ok: true } : { ok: false, reason: 'bad_signature' });
  const { s, base } = await mkApp(good);
  try {
    assert.equal((await realFetch(base + '/internal/ingest/run', { method: 'POST' })).status, 401);
    assert.equal((await realFetch(base + '/internal/ingest/status')).status, 401);
    assert.equal((await realFetch(base + '/internal/ingest/run?source=all', { method: 'POST', headers: { Authorization: 'Bearer bad' } })).status, 401);
    assert.equal((await realFetch(base + '/internal/ingest/run?source=nope', { method: 'POST', headers: { Authorization: 'Bearer good' } })).status, 404);
    const run = await realFetch(base + '/internal/ingest/run?source=all&group=global', { method: 'POST', headers: { Authorization: 'Bearer good' } });
    assert.equal(run.status, 200);
    const j = await run.json(); assert.equal(j.ran, 1); assert.equal(j.results[0].ok, true);
    const st = await (await realFetch(base + '/internal/ingest/status', { headers: { Authorization: 'Bearer good' } })).json();
    assert.equal(st.feeds.length, 2);
    assert.equal(st.feeds.find(x => x.id === 'r2').status, 'never-run');
    assert.equal((await realFetch(base + '/internal/ingest/status')).headers.get('cache-control'), 'no-store');
  } finally { s.close(); }
  const unconfigured = await mkApp(createVerifier({}));
  try { assert.equal((await realFetch(unconfigured.base + '/internal/ingest/run', { method: 'POST', headers: { Authorization: 'Bearer x.y.z' } })).status, 503); } finally { unconfigured.s.close(); }
});

// ------------------------------------------------------------------------------------------ cloudflare DNS
test('cloudflare security DNS: 0.0.0.0 / EDE = blocked; timeout and errors fail open (signal only); cached', async () => {
  assert.equal(interpret({ Status: 0, Answer: [{ data: '0.0.0.0' }] }).blocked, true);
  assert.equal(interpret({ Status: 0, Answer: [{ data: '93.184.216.34' }] }).blocked, false);
  assert.equal(interpret({ Status: 3, Comment: ['EDE(16): Censored'] }).blocked, true);
  assert.equal(interpret({ Status: 0, EDE: [{ code: 17 }] }).blocked, true);
  const f = fakeFetch({ '*': (u) => ({ body: JSON.stringify(u.includes('bad.test') ? { Status: 0, Answer: [{ data: '0.0.0.0' }] } : { Status: 0, Answer: [{ data: '1.2.3.4' }] }) }) });
  const chk = createCloudflareCheck({ fetchImpl: f });
  assert.equal((await chk('bad.test')).blocked, true);
  assert.equal((await chk('bad.test')).blocked, true);
  assert.equal(f.calls.length, 1);
  assert.match(f.calls[0].url, /^https:\/\/security\.cloudflare-dns\.com\/dns-query\?name=bad\.test&type=A$/);
  assert.equal(f.calls[0].opts.headers.Accept, 'application/dns-json');
  const slow = createCloudflareCheck({ timeoutMs: 20, fetchImpl: (u, o) => new Promise((_, rej) => o.signal.addEventListener('abort', () => rej(Object.assign(new Error('a'), { name: 'AbortError' })))) });
  const r = await slow('x.test'); assert.equal(r.available, false); assert.equal(r.reason, 'timeout');
  const e = await createCloudflareCheck({ fetchImpl: async () => { throw new Error('net'); } })('y.test'); assert.equal(e.available, false);
});

// ------------------------------------------------------------------------------------------ engine integration
const realFetch = global.fetch;
test.before(() => {
  global.fetch = async (url) => {
    const u = String(url);
    const body = (o, status = 200) => ({ ok: status < 400, status, text: async () => JSON.stringify(o) });
    if (u.startsWith('https://rdap.org/')) return body({}, 200); // no registration event => age unavailable
    throw new Error('unexpected network call: ' + u);
  };
});
test.after(() => { global.fetch = realFetch; });

async function engineWith(records, input, over = {}) {
  engine._clearCaches();
  const store = createStore({ backend: memoryBackend(), now: () => NOW });
  for (const [id, name, recs] of records) await store.upsertMany(recs.map(r => ({ ...r, source: id })), { sourceId: id, sourceMeta: { name }, now: NOW });
  const deps = {
    whitelist: new Set(['sbi.co.in', 'hdfcbank.com']), brands: [], suspiciousTlds: new Set(['top', 'xyz']), shorteners: new Set(), useGemini: false,
    threatStore: store,
    dnsCheck: async () => ({ resolved: true, status: 'NOERROR', ips: ['93.184.216.34'], ttl: 300, isFastFlux: false, isNxDomain: false }),
    sslCheck: async () => ({ supported: true, hasValidSsl: true, authorized: true, isExpired: false, isEV_OV: false, issuer: 'CA', ageDays: 200, isNewlyIssued: false }),
    ...over
  };
  return engine.assessDomain(input, deps);
}

test('engine: exact and suffix feed match hard-blocks with source attribution', async () => {
  const feeds = [['phishing-database', 'Phishing.Database', [rec({ value: 'evil-login.example.com' })]]];
  let a = await engineWith(feeds, 'https://evil-login.example.com/x');
  assert.equal(a.hardBlock, true); assert.equal(a.verdict, 'THREAT_FEED_LISTED'); assert.equal(a.riskLevel, 'CRITICAL');
  assert.match(a.flags[0], /^Listed by Phishing\.Database \(ingested 2026-10-14T00:00:00\.000Z\)/);
  a = await engineWith(feeds, 'sub.evil-login.example.com');
  assert.equal(a.hardBlock, true);
  assert.equal(a.threatFeeds[0].source, 'phishing-database');
  a = await engineWith(feeds, 'https://clean.example.com');
  assert.equal(a.hardBlock, false);
});

test('engine: URL-level feed match and weak (low-confidence) host listing is not a hard block', async () => {
  const feeds = [['urlhaus', 'URLhaus', [rec({ type: 'url', value: 'http://site.example.org/bad.apk', category: 'malware', confidence: 0.95 }), rec({ value: 'site.example.org', category: 'malware', confidence: 0.5 })]]];
  let a = await engineWith(feeds, 'http://site.example.org/bad.apk');
  assert.equal(a.verdict === 'THREAT_FEED_LISTED' || a.hardBlock, true);
  a = await engineWith(feeds, 'https://site.example.org/ok');
  assert.equal(a.hardBlock, false);
  assert.ok(a.flags.some(f => /Weak threat-feed signal: URLhaus/.test(f)));
});

test('engine: India regulator listing => CRITICAL naming the regulator', async () => {
  const feeds = [['sebi', 'SEBI unauthorised entities', [{ ...rec({ value: 'quickgains-fx.example.in', category: 'unauthorised-forex' }), meta: { regulator: 'RBI Alert List' } }]]];
  const a = await engineWith(feeds, 'https://quickgains-fx.example.in');
  assert.equal(a.verdict, 'REGULATOR_WARNING_LISTED'); assert.equal(a.riskLevel, 'CRITICAL'); assert.ok(a.riskScore >= 98);
  assert.match(a.flags[0], /^Listed by RBI Alert List \(ingested .*\): an unauthorised forex platform/);
});

test('engine: a feed listing a shared-hosting parent does not block the whole platform, exact subdomain does', async () => {
  const feeds = [['p', 'P', [rec({ value: 'github.io' }), rec({ value: 'evil.netlify.app' })]]];
  let a = await engineWith(feeds, 'https://someone.github.io');
  assert.equal(a.hardBlock, false);
  a = await engineWith(feeds, 'https://evil.netlify.app');
  assert.equal(a.hardBlock, true);
});

test('engine: Tranco top-100k makes github.com LOW ESTABLISHED; never overrides a hard block; not for subdomains/shared hosts', async () => {
  const tr = ['tranco', 'Tranco', [{ ...rec({ value: 'github.com', category: 'popular-site', confidence: 1 }), meta: { rank: 40 } }, { ...rec({ value: 'github.io', category: 'popular-site', confidence: 1 }), meta: { rank: 900 } }]];
  let a = await engineWith([], 'https://github.com/');
  assert.equal(a.verdict, 'UNVERIFIED_THIRD_PARTY_DOMAIN');
  a = await engineWith([tr], 'https://github.com/');
  assert.equal(a.verdict, 'ESTABLISHED_THIRD_PARTY_DOMAIN'); assert.equal(a.riskLevel, 'LOW'); assert.equal(a.popularRank, 40); assert.equal(a.verified, false);
  a = await engineWith([tr], 'https://evil.github.com/login');
  assert.notEqual(a.verdict, 'ESTABLISHED_THIRD_PARTY_DOMAIN');
  a = await engineWith([tr], 'https://user.github.io/');
  assert.notEqual(a.verdict, 'ESTABLISHED_THIRD_PARTY_DOMAIN');
  a = await engineWith([tr, ['p', 'Phishing.Database', [rec({ value: 'github.com' })]]], 'https://github.com/');
  assert.equal(a.hardBlock, true); assert.equal(a.riskLevel, 'CRITICAL');
});

test('engine: Tranco never grants the sovereign/verified path or hides DNS failure', async () => {
  const tr = ['tranco', 'Tranco', [{ ...rec({ value: 'popular.example.com', category: 'popular-site', confidence: 1 }), meta: { rank: 10 } }]];
  const a = await engineWith([tr], 'https://popular.example.com', { dnsCheck: async () => ({ resolved: false, status: 'NXDOMAIN', ips: [], isNxDomain: true }) });
  assert.equal(a.hardBlock, true); assert.notEqual(a.verdict, 'ESTABLISHED_THIRD_PARTY_DOMAIN');
});

test('engine: Cloudflare security DNS block counts only while public DNS resolves; fail-open when signal unavailable', async () => {
  let a = await engineWith([], 'https://fresh-bad.example.com', { securityDns: async () => ({ available: true, blocked: true, reason: 'answer 0.0.0.0 (sinkholed)' }) });
  assert.equal(a.verdict, 'DNS_SECURITY_BLOCKED'); assert.equal(a.hardBlock, true);
  assert.match(a.flags[0], /Cloudflare security DNS/);
  a = await engineWith([], 'https://fresh-bad.example.com', { securityDns: async () => ({ available: true, blocked: true }), dnsCheck: async () => ({ resolved: false, status: 'NXDOMAIN', ips: [], isNxDomain: true }) });
  assert.notEqual(a.verdict, 'DNS_SECURITY_BLOCKED');
  a = await engineWith([], 'https://fresh-ok.example.com', { securityDns: async () => { throw new Error('boom'); } });
  assert.equal(a.ok, true); assert.equal(a.hardBlock, false);
  a = await engineWith([], 'https://fresh-ok.example.com', { securityDns: async () => ({ available: false, reason: 'timeout' }) });
  assert.equal(a.hardBlock, false);
});

test('engine.lookupIndicator: phone / UPI / entity hook (normalises input, hides context categories)', async () => {
  const store = createStore({ backend: memoryBackend(), now: () => NOW });
  await store.upsertMany([
    rec({ type: 'phone', value: '+919876543210', category: 'fraud-report' }),
    rec({ type: 'upi', value: 'refund.desk@icici', category: 'fraud-report' }),
    rec({ type: 'entity', value: 'quick gains pvt. ltd', category: 'unregistered-investment' })
  ].map(r => ({ ...r, source: 'crowd' })), { sourceId: 'crowd', sourceMeta: { name: 'Crowd' } });
  const deps = { threatStore: store };
  assert.equal(engine.lookupIndicator('phone', '98765 43210', deps)[0].sourceName, 'Crowd');
  assert.equal(engine.lookupIndicator('upi', 'Refund.Desk@ICICI', deps).length, 1);
  assert.equal(engine.lookupIndicator('entity', 'Quick  Gains Pvt. Ltd!', deps).length, 1);
  assert.deepEqual(engine.lookupIndicator('phone', 'garbage', deps), []);
  assert.deepEqual(engine.lookupIndicator('phone', '9876543210', {}), []);
});

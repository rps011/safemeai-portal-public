'use strict';
const test = require('node:test');
const assert = require('node:assert');
const R = require('../lib/reports');
const engine = require('../lib/domainEngine');

const PROTECTED = new Set(['sbi.co.in', 'hdfcbank.com']);
const isProtected = h => PROTECTED.has(h) || [...PROTECTED].some(p => h.endsWith('.' + p)) || /\.(gov|bank|nic)\.in$/.test(h);

function make(over = {}) {
  let t = 1_700_000_000_000;
  const clock = { now: () => t, advance: ms => { t += ms; } };
  const api = R.createReports(Object.assign({ store: R.memoryAdapter(), now: clock.now, isProtected, secret: 'test-secret' }, over));
  // each reporter: distinct device AND distinct /24 network
  let n = 0;
  const report = (target, o = {}) => { n++; return api.submit(Object.assign({ target, scamType: 'KYC phishing', details: 'x', deviceId: 'device-' + String(n).padStart(16, '0'), ip: `203.0.${n}.9` }, o)); };
  return { api, clock, report };
}

test('normalisation: domains, phones, UPI; emails and internal hosts rejected', () => {
  assert.deepStrictEqual(R.normaliseTarget('HTTPS://WWW.Evil-KYC.xyz/login?a=1'), { ok: true, type: 'domain', value: 'evil-kyc.xyz', sharedParent: null });
  assert.strictEqual(R.normaliseTarget('+91 98201 44102').value, '+919820144102');
  assert.strictEqual(R.normaliseTarget('refund.desk92@ICICI').value, 'refund.desk92@icici');
  assert.strictEqual(R.normaliseTarget('victim@gmail.com').ok, false);
  assert.strictEqual(R.normaliseTarget('http://127.0.0.1/').ok, false);
  assert.strictEqual(R.normaliseTarget('localhost').ok, false);
  assert.strictEqual(R.normaliseTarget('ftp://evil.xyz').ok, false);
  assert.strictEqual(R.normaliseTarget('').ok, false);
});

test('PII minimisation: free text redacted, reporter identity never stored in plain', async () => {
  const { api, report } = make();
  await report('evil-kyc.xyz', { details: 'call me on 9820144102 or a@b.com aadhaar 1234 5678 9012', reporterPhone: '9999999999', reporterName: 'Ramesh' });
  const dump = JSON.stringify([...(await api._store.all('rec')), ...(await api._store.all('rep'))]);
  for (const bad of ['9820144102', 'a@b.com', '1234 5678 9012', '9999999999', 'Ramesh', '203.0.1.9', 'device-0000']) assert.ok(!dump.includes(bad), bad);
});

test('thresholds: pending -> community-reported (N) -> blocked only with spread or corroboration', async () => {
  const { api, clock, report } = make();
  let r;
  for (let i = 0; i < 2; i++) r = await report('evil-kyc.xyz');
  assert.strictEqual(r.record.status, 'RECEIVED');
  r = await report('evil-kyc.xyz');
  assert.strictEqual(r.record.status, 'COMMUNITY_REPORTED');
  for (let i = 0; i < 4; i++) r = await report('evil-kyc.xyz'); // 7 reporters, all within the same instant
  assert.strictEqual(r.record.status, 'COMMUNITY_REPORTED', 'a burst must not reach BLOCK');
  clock.advance(15 * 60 * 1000);
  r = await report('evil-kyc.xyz');
  assert.strictEqual(r.record.status, 'BLOCKED');
  const d = await api.delta(0);
  assert.ok(d.entries.some(e => e.value === 'evil-kyc.xyz' && e.level === 'block'));
});

test('engine corroboration (young domain / lookalike) blocks at N', async () => {
  const { api, report } = make({ corroborate: async () => ({ ageDays: 3, lookalike: false }) });
  let r; for (let i = 0; i < 3; i++) r = await report('brand-new-scam.top');
  assert.strictEqual(r.record.status, 'BLOCKED');
  const { report: rep2 } = make({ corroborate: async () => ({ ageDays: 400, lookalike: false }) });
  for (let i = 0; i < 3; i++) r = await rep2('middling-site.com');
  assert.strictEqual(r.record.status, 'COMMUNITY_REPORTED');
});

test('abuse: mass reports against an old established domain go to human review, never auto-block', async () => {
  const { api, clock, report } = make({ corroborate: async () => ({ ageDays: 4000, lookalike: false }) });
  let r;
  for (let i = 0; i < 10; i++) { r = await report('competitor-shop.com'); clock.advance(5 * 60 * 1000); }
  assert.strictEqual(r.record.status, 'QUEUED_FOR_REVIEW');
  assert.ok(!(await api.delta(0)).entries.some(e => e.value === 'competitor-shop.com' && e.action === 'add'));
  assert.ok((await api.reviewQueue()).some(q => q.value === 'competitor-shop.com'));
});

test('allow-list immunity: allow-listed, sovereign, shared-hosting parents and helplines are never published', async () => {
  const { api, clock, report } = make({ corroborate: async () => ({ ageDays: 1, lookalike: true }) });
  const targets = ['hdfcbank.com', 'netbanking.hdfcbank.com', 'https://sbi.co.in/login', 'fakebank.bank.in', 'cybercrime.gov.in', 'docs.google.com', 'bit.ly', '1800 111 109'];
  for (const t of targets) {
    let r;
    for (let i = 0; i < 12; i++) { r = await report(t); clock.advance(2 * 60 * 1000); }
    assert.strictEqual(r.record.status, 'QUEUED_FOR_REVIEW', t);
  }
  const d = await api.delta(0);
  assert.strictEqual(d.entries.filter(e => e.action === 'add').length, 0);
  assert.strictEqual((await api.publicFeed()).length, 0);
  // even a human cannot confirm an allow-listed domain without editing the allow-list first
  assert.strictEqual((await api.decide('domain:hdfcbank.com', 'confirm')).error, 'protected_domain');
  assert.strictEqual((await api.decide('domain:docs.google.com', 'confirm')).ok, false);
});

test('allow-list growth retroactively un-publishes a blocked value (emits remove)', async () => {
  let prot = false;
  const { api, clock, report } = make({ isProtected: h => prot || isProtected(h), corroborate: async () => ({ ageDays: 2 }) });
  for (let i = 0; i < 3; i++) await report('newbank-india.com');
  const first = await api.delta(0);
  assert.ok(first.entries.some(e => e.action === 'add'));
  prot = true; clock.advance(1000);
  await report('newbank-india.com'); // triggers re-evaluation
  const second = await api.delta(first.next);
  assert.ok(second.entries.some(e => e.action === 'remove' && e.value === 'newbank-india.com'));
});

test('dedupe + independence: same reporter, same network, repeats do not count', async () => {
  const { api } = make();
  const base = { target: 'evil-kyc.xyz', scamType: 'kyc' };
  const a = await api.submit({ ...base, deviceId: 'dev-aaaaaaaaaaaaaaaa', ip: '198.51.100.1' });
  const dup = await api.submit({ ...base, deviceId: 'dev-aaaaaaaaaaaaaaaa', ip: '198.51.100.1' });
  assert.strictEqual(dup.duplicate, true);
  // 5 other devices on the same /24 count as one network
  for (let i = 0; i < 5; i++) await api.submit({ ...base, deviceId: 'dev-bbbbbbbbbbbbbb0' + i, ip: '198.51.100.' + (10 + i) });
  const rec = await api._store.get('rec', 'domain:evil-kyc.xyz');
  assert.strictEqual(rec.independent, 1);
  assert.strictEqual(a.record.status, 'RECEIVED');
  assert.strictEqual(rec.state, 'pending');
});

test('rate limits per reporter and per network', async () => {
  const { api } = make();
  let last;
  for (let i = 0; i < 11; i++) last = await api.submit({ target: `spam${i}.xyz`, scamType: 'x', deviceId: 'dev-cccccccccccccccc', ip: '192.0.2.1' });
  assert.strictEqual(last.status, 429);
  assert.ok(last.retryAfterSec > 0);
  const { api: api2 } = make({ config: { rate: { perNetworkDay: 5 } } });
  for (let i = 0; i < 6; i++) last = await api2.submit({ target: `net${i}.xyz`, scamType: 'x', deviceId: 'dev-dddddddddddddd0' + i, ip: '192.0.2.77' });
  assert.strictEqual(last.status, 429);
});

test('burned reporters (repeatedly dismissed) stop counting', async () => {
  const { api, report } = make({ corroborate: async () => ({ ageDays: 400 }) });
  // one attacker identity (same device+network) spams 3 values that a human dismisses
  const atk = (t) => api.submit({ target: t, scamType: 'x', deviceId: 'dev-attackerattacker', ip: '45.1.1.1' });
  for (const t of ['a1.xyz', 'a2.xyz', 'a3.xyz']) { await atk(t); await api.decide('domain:' + t, 'dismiss'); }
  await atk('victim-biz.com');
  await report('victim-biz.com'); await report('victim-biz.com');
  const rec = await api._store.get('rec', 'domain:victim-biz.com');
  assert.strictEqual(rec.independent, 2, 'attacker counts for nothing');
  assert.strictEqual(rec.state, 'pending');
});

test('expiry: pending, community-reported and blocked entries age out, with remove tombstones', async () => {
  const { api, clock, report } = make({ corroborate: async () => ({ ageDays: 1 }) });
  await report('stale-pending.xyz');
  for (let i = 0; i < 3; i++) await report('stale-blocked.xyz');
  const d1 = await api.delta(0);
  assert.ok(d1.entries.some(e => e.value === 'stale-blocked.xyz' && e.action === 'add'));
  clock.advance(31 * 86400000);
  await api.sweep(true);
  assert.strictEqual((await api._store.get('rec', 'domain:stale-pending.xyz')).state, 'expired');
  assert.strictEqual((await api._store.get('rec', 'domain:stale-blocked.xyz')).state, 'blocked');
  clock.advance(200 * 86400000);
  await api.sweep(true);
  const d2 = await api.delta(d1.next);
  assert.ok(d2.entries.some(e => e.value === 'stale-blocked.xyz' && e.action === 'remove'));
  assert.ok(!d2.entries.some(e => e.value === 'stale-pending.xyz'), 'never-published values emit no tombstone');
  clock.advance(40 * 86400000);
  await api.sweep(true);
  assert.strictEqual(await api._store.get('rec', 'domain:stale-blocked.xyz'), undefined);
});

test('public feed shows only confirmed values, masks phone/UPI, never reporter data', async () => {
  const { api, report } = make();
  await report('+919820144102'); // 1 reporter: not public
  assert.strictEqual((await api.publicFeed()).length, 0);
  for (let i = 0; i < 3; i++) await report('refund.desk92@icici', { scamType: 'UPI Collect Trap' });
  const f = await api.publicFeed();
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].target, 're***@icici');
  assert.deepStrictEqual(Object.keys(f[0]).sort(), ['details', 'id', 'scamType', 'status', 'target', 'time']);
});

test('signed delta verifies; tampering and wrong key fail', async () => {
  const { api, report } = make({ corroborate: async () => ({ ageDays: 1 }) });
  for (let i = 0; i < 3; i++) await report('evil-kyc.xyz');
  const signed = R.signDelta(await api.delta(0), 0, 'k1');
  assert.ok(R.verifyDelta(signed, 'k1'));
  assert.ok(!R.verifyDelta(signed, 'k2'));
  assert.ok(!R.verifyDelta({ ...signed, payload: signed.payload.replace('evil-kyc.xyz', 'sbi.co.in') }, 'k1'));
  assert.strictEqual(R.signDelta({ entries: [] }, 0, ''), null);
});

test('engine exports used by the pipeline exist', () => {
  assert.ok(Array.isArray(engine.SHARED_HOSTING_PARENTS));
  assert.strictEqual(typeof engine.parseTarget, 'function');
});

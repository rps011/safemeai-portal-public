'use strict';
// Offline tests for the India regulator ingest sources.  Run: node --test tests/ingest-india.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const U = require('../lib/ingest/sources/india/_util');
const alert = require('../lib/ingest/sources/india/rbiAlertList');
const etp = require('../lib/ingest/sources/india/rbiAuthorisedEtp');
const ia = require('../lib/ingest/sources/india/sebiInvestmentAdvisers');
const ra = require('../lib/ingest/sources/india/sebiResearchAnalysts');
const brokers = require('../lib/ingest/sources/india/sebiStockBrokers');
const { loadSources } = require('../lib/ingest/registry');
const loaded = loadSources({ dir: path.join(__dirname, '..', 'lib', 'ingest', 'sources') });
const MINE = new Set(['rbi-alert-list', 'rbi-authorised-etp', 'sebi-investment-advisers', 'sebi-research-analysts', 'sebi-stock-brokers']);
const all = loaded.sources.filter((s) => MINE.has(s.id));
const { sanitizeRecords } = require('../lib/ingest/contract');

const fx = (n) => fs.readFileSync(path.join(__dirname, 'fixtures', 'india', n), 'utf8');
const NOW = Date.UTC(2026, 9, 14);

// ---- tiny ctx / http stub (stands in for the framework helper) ----
function makeCtx(routes, state = {}) {
  const calls = [];
  return {
    calls,
    now: NOW,
    log: () => {},
    state: { get: (k) => state[k], set: (k, v) => { state[k] = v; } },
    async http(url, opts = {}) {
      calls.push({ url, opts });
      const h = routes(url, opts);
      if (!h) { const e = new Error('HTTP 404'); e.status = 404; throw e; }
      return { status: 200, headers: {}, ...h, text: h.body };
    },
  };
}

test('registry discovers all India sources with no load problems', () => {
  assert.deepEqual(loaded.problems.filter((p) => /india[\\/](?!_)/.test(p.file) && !/seed/.test(p.file)), []);
  assert.equal(all.length, 5);
  for (const s of all) {
    assert.equal(typeof s.id, 'string');
    assert.equal(typeof s.name, 'string');
    assert.equal(s.group, 'india');
    assert.ok(s.schedule && s.license);
    assert.equal(typeof s.fetch, 'function');
    assert.match(s.schedule, /^every \d+[mhd]$/);
  }
  assert.equal(new Set(all.map((s) => s.id)).size, all.length);
});

test('normaliseDomain: lowercase, www strip, punycode, rejects junk', () => {
  assert.equal(U.normaliseDomain('https://WWW.Exness.com/'), 'exness.com');
  assert.equal(U.normaliseDomain('https://in.puprime.com '), 'in.puprime.com');
  assert.equal(U.normaliseDomain('https://www.étoro.com/en'), 'xn--toro-9oa.com');
  assert.equal(U.normaliseDomain('qfxmarkets.com/'), 'qfxmarkets.com');
  assert.equal(U.normaliseDomain('Mobile Application'), null);
  assert.equal(U.normaliseDomain('http://1.2.3.4/x'), null);
  assert.equal(U.normaliseDomain('localhost'), null);
  assert.equal(U.normaliseDomain(''), null);
  assert.equal(U.domainFromEmail('x@gmail.com'), null);
  assert.equal(U.domainFromEmail('a@Compliance.Bksec.com'), 'compliance.bksec.com');
});

test('RBI Alert List fixture parses to block records', () => {
  const recs = alert.parse(fx('rbi-alert-list.html'), { now: NOW });
  const dom = recs.filter((r) => r.type === 'domain');
  const ent = recs.filter((r) => r.type === 'entity');
  assert.ok(dom.length >= 85, `domains ${dom.length}`);
  assert.ok(ent.length >= 90, `entities ${ent.length}`);
  const ex = dom.find((r) => r.value === 'exness.com');
  assert.ok(ex);
  assert.equal(ex.category, 'unauthorised-forex');
  assert.equal(ex.meta.regulator, 'RBI');
  assert.equal(ex.meta.label, 'Listed in RBI Alert List');
  assert.equal(ex.meta.listUpdated, 'November 19, 2025');
  assert.ok(ex.confidence > 0 && ex.confidence <= 1);
  assert.equal(ex.source, 'rbi-alert-list');
  // trailing-space / trailing-slash / www variants normalised
  assert.ok(dom.some((r) => r.value === 'qfxmarkets.com'));
  assert.ok(dom.some((r) => r.value === 'fx-nice.net'));
  // sub-path -> url record
  assert.ok(recs.some((r) => r.type === 'url' && r.value === 'https://ftmo.com/en'));
  // mobile-app-only rows: entity but no domain
  const dream = ent.find((r) => /^dream trade/i.test(r.value));
  assert.ok(dream);
  assert.equal(dream.meta.channel, 'mobile-app');
  // no dupes, all valid
  assert.equal(new Set(dom.map((r) => r.value)).size, dom.length);
  for (const r of dom) assert.ok(U.normaliseDomain(r.value) === r.value, r.value);
  for (const r of recs) assert.ok(r.firstSeen && r.lastSeen && r.sourceUrl);
});

test('RBI authorised ETP fixture parses to regulated-entity records', () => {
  const recs = etp.parse(fx('rbi-etp.html'), { now: NOW });
  assert.ok(recs.length >= 6);
  for (const r of recs) assert.equal(r.category, 'regulated-entity');
  const cc = recs.find((r) => r.type === 'domain' && r.value === 'clearcorp.co.in');
  assert.ok(cc);
  assert.match(cc.meta.registrationNo, /^ETP\d+\//);
  assert.match(cc.meta.label, /^RBI-authorised ETP ETP/);
  // operators merged across ETP rows and across "Ltd." vs "Ltd" spelling
  assert.equal(recs.filter((r) => r.type === 'entity' && /clearcorp/i.test(r.value)).length, 1);
  // cancelled section B must not leak in: ETP7 is cancelled
  assert.ok(!recs.some((r) => (r.meta.registrationNos || []).includes('ETP7/CDSL/2019')));
});

test('SEBI pages parse; registration number and label are carried in meta', () => {
  const p1 = ia.parsePage(fx('sebi-ia-page1.html'));
  assert.equal(p1.total, 1050);
  assert.equal(p1.records.length, 25);
  assert.equal(p1.expected, 25);
  const recs = ia.toRecords(p1.records, { now: NOW });
  const one = recs.find((r) => r.type === 'entity' && r.value === '1 Finance Private Limited');
  assert.ok(one);
  assert.equal(one.category, 'regulated-entity');
  assert.equal(one.meta.regulator, 'SEBI');
  assert.equal(one.meta.registrationNo, 'INA000017523');
  assert.equal(one.meta.label, 'SEBI-registered Investment Adviser INA000017523');
  const d = recs.find((r) => r.type === 'domain' && r.value === '1finance.co.in');
  assert.ok(d);
  assert.equal(d.meta.derivedFrom, 'registered-email-domain');
  assert.ok(d.confidence < one.confidence);
  // no personal contact data stored
  assert.ok(!JSON.stringify(recs).match(/@/), 'e-mail address leaked');
  assert.ok(!recs.some((r) => 'email' in r.meta || 'phone' in r.meta));
  // free-mail registrants produce an entity but no domain
  const p2 = ia.parsePage(fx('sebi-ia-page2.html'));
  assert.equal(p2.from, 26);
  const r2 = ia.toRecords(p2.records, { now: NOW });
  assert.ok(!r2.some((r) => r.type === 'domain' && U.FREE_MAIL.has(r.value)));
});

test('SEBI research analyst + broker fixtures (truncated) parse; broker exchanges merged', () => {
  const r = ra.parse(fx('sebi-ra-page1.html'));
  assert.ok(r.length >= 5);
  assert.ok(r.every((x) => x.meta.registrationType === 'Research Analyst' && /^INH/.test(x.meta.registrationNo)));
  const b = brokers.toRecords([
    { name: 'X Sec', regNo: 'INZ000000001', exchange: 'NSE', validity: 'Jan 01, 2020 - Perpetual' },
    { name: 'X Sec', regNo: 'INZ000000001', exchange: 'BSE', validity: 'Jan 01, 2020 - Perpetual' },
  ], { now: NOW });
  assert.equal(b.length, 1);
  assert.deepEqual(b[0].meta.exchanges, ['NSE', 'BSE']);
});

test('SEBI: expired registrations are not positive signals; bad reg no throws', () => {
  const rec = { name: 'Old Adv', regNo: 'INA000000002', validity: 'Jan 01, 2010 - Jan 01, 2015', email: 'a@olda.com' };
  assert.equal(ia.toRecords([rec], { now: NOW }).length, 0);
  assert.throws(() => ia.toRecords([{ name: 'Bad', regNo: 'XYZ' }], { now: NOW }), /invalid registration number/);
  assert.throws(() => ia.toRecords([{ regNo: 'INA000000002' }], { now: NOW }), /without a name/);
});

test('parsers fail loudly on wrong / blocked / empty documents', () => {
  const junk = '<html><body>' + 'x'.repeat(2000) + '</body></html>';
  assert.throws(() => alert.parse(junk), U.IndiaParseError);
  assert.throws(() => etp.parse(junk), U.IndiaParseError);
  assert.throws(() => ia.parsePage(junk), /pagination banner/);
  assert.throws(() => alert.parse(''), /too-short/);
  assert.throws(() => ia.parsePage('<html><title>Unauthorized Request Blocked</title></html>'), /WAF blocked/);
  // header present but only a handful of rows -> refuse partial
  const partial = '<table><tr><td>Sr. No</td><td>Name</td><td>Website</td></tr><tr><td>1</td><td>A</td><td>https://a.com</td></tr></table>' + ' '.repeat(600);
  assert.throws(() => alert.parse(partial), /refusing partial/);
  // banner claims records but none parse
  assert.throws(() => ia.parsePage('<p>1 to 25 of 100 records</p>'), /0 parsed/);
  // unparseable website value in a data row
  const html = fx('rbi-alert-list.html').replace('https://alpari.com', 'not a url at all');
  assert.throws(() => alert.parse(html), /unparseable website/);
});

test('http layer: block pages and HTTP errors raise', async () => {
  const blocked = makeCtx(() => ({ body: '<html><head><title>Unauthorised Access </title></head><body>You are not authorized</body></html>' }));
  await assert.rejects(() => alert.fetch(blocked), /block page/);
  const nf = makeCtx(() => null);
  await assert.rejects(() => alert.fetch(nf), /HTTP 404/);
  const teapot = makeCtx(() => ({ status: 418, body: '' }));
  await assert.rejects(() => etp.fetch(teapot), /HTTP 418/);
  const nm = makeCtx(() => ({ notModified: true, status: 304 }));
  assert.equal(await alert.fetch(nm), null); // contract: null = unchanged
});

test('fetch(): RBI alert list end-to-end through ctx.http stub + sanity threshold', async () => {
  const state = {};
  const ctx = makeCtx((url) => (url === alert.URL ? { body: fx('rbi-alert-list.html') } : null), state);
  const out = await alert.fetch(ctx);
  assert.equal(out.replaceAllowed, true);
  assert.ok(out.length > 150);
  assert.equal(state['rbi-alert-list:lastCount'], out.length);

  // a later run that returns <50% of the previous count must be refused (and return nothing)
  state['rbi-alert-list:lastCount'] = out.length * 3;
  const out2 = await alert.fetch(ctx);
  assert.equal(out2.replaceAllowed, false);
  assert.equal(out2.length, 0);
  assert.match(out2.stats.reason, /dropped/);
  assert.equal(state['rbi-alert-list:lastCount'], out.length * 3, 'bad run must not overwrite baseline');
});

test('fetch(): SEBI paging uses session cookie, Referer and POST body; verifies counts', async () => {
  const page1 = fx('sebi-ia-page1.html').replaceAll('of 1050 records', 'of 50 records');
  const page2 = fx('sebi-ia-page2.html').replaceAll('of 1050 records', 'of 50 records');
  const ctx = makeCtx((url, opts) => {
    if (url === ia.URL) return { body: page1, headers: { 'set-cookie': ['JSESSIONID=ABC123; Path=/sebiweb; Secure; HttpOnly'] } };
    if (url.endsWith('/getintmfpiinfo.jsp')) {
      assert.equal(opts.method, 'POST');
      assert.match(opts.headers.Cookie, /JSESSIONID=ABC123/);
      assert.equal(opts.headers.Referer, ia.URL);
      const b = new URLSearchParams(opts.body);
      assert.equal(b.get('intmId'), '13');
      assert.equal(b.get('doDirect'), '1');
      return { body: page2 };
    }
    return null;
  });
  const out = await ia.fetch(ctx);
  assert.equal(ctx.calls.length, 2);
  assert.equal(out.replaceAllowed, true);
  const regs = new Set(out.filter((r) => r.type === 'entity').map((r) => r.meta.registrationNo));
  assert.equal(regs.size, 50);

  // WAF block on page 2 -> throws, never returns half a register
  const waf = makeCtx((url) => (url === ia.URL
    ? { body: page1, headers: {} }
    : { body: '<HTML><HEAD><TITLE>Unauthorized Request Blocked</TITLE></HEAD><BODY>x</BODY></HTML>'.padEnd(500, ' ') }));
  await assert.rejects(() => ia.fetch(waf), /WAF blocked|block page/);

  // count mismatch (banner says 75, only 2 pages of data exist) -> throws
  const mismatch = makeCtx((url) => (url === ia.URL
    ? { body: page1.replaceAll('of 50 records', 'of 75 records') }
    : { body: page2.replaceAll('of 50 records', 'of 75 records') }));
  await assert.rejects(() => ia.fetch(mismatch), /expected to start|crawled|parsed/);
});

test('fetch(): truncated test crawl can never replace stored data', async () => {
  const page1 = fx('sebi-ia-page1.html').replaceAll('of 1050 records', 'of 50 records');
  const ctx = makeCtx(() => ({ body: page1 }));
  ctx.maxPages = 1;
  const out = await ia.fetch(ctx);
  assert.equal(out.replaceAllowed, false);
});

test('records survive the framework sanitiser (contract.js) with no rejections and meta <= 1KB', () => {
  const sets = [
    alert.parse(fx('rbi-alert-list.html'), { now: NOW }),
    etp.parse(fx('rbi-etp.html'), { now: NOW }),
    ia.parse(fx('sebi-ia-page1.html')),
    ia.parse(fx('sebi-ia-page2.html')),
    ra.parse(fx('sebi-ra-page1.html')),
    brokers.parse(fx('sebi-broker-page1.html')),
  ];
  for (const recs of sets) {
    for (const r of recs) assert.ok(JSON.stringify(r.meta).length <= 1000, `${r.source} meta too large`);
    const san = sanitizeRecords(recs, { sourceId: recs[0].source, now: NOW, maxRecords: 1e6 });
    assert.equal(san.rejectedCount, 0, JSON.stringify(san.rejected));
  }
});

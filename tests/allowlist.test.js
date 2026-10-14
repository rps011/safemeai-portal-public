'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { entries } = require('../data/allowlist.json');
const engine = require('../lib/domainEngine');

const HOST = /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
const domains = entries.map(e => e.domain);

test('no duplicate entries', () => {
  const seen = new Set(); const dups = [];
  for (const d of domains) { if (seen.has(d)) dups.push(d); seen.add(d); }
  assert.deepStrictEqual(dups, []);
});

test('every entry is a lowercase valid hostname with category (and an owner for the 2026-10 additions)', () => {
  for (const e of entries) {
    assert.match(e.domain, HOST, e.domain);
    assert.strictEqual(e.domain, e.domain.toLowerCase());
    assert.ok(!e.domain.startsWith('www.'), e.domain);
    assert.ok(e.category && typeof e.category === 'string', e.domain);
    if (e.origin === '2026-10-expansion') assert.ok(e.owner, 'owner required: ' + e.domain);
  }
});

test('no entry is (or sits under) a shared-hosting / shortener parent', () => {
  for (const d of domains) {
    const hit = engine.SHARED_HOSTING_PARENTS.find(p => d === p || d.endsWith('.' + p));
    assert.ok(!hit, `${d} overlaps shared-hosting parent ${hit}`);
  }
});

test('no entry is a bare public suffix or sovereign namespace itself', () => {
  for (const d of domains) assert.ok(!/^(gov|nic|bank|co|org|ac|edu|res|fin|jud|mil)\.in$/.test(d) && !/^(com|net|org)\.in$/.test(d), d);
});

test('every legacy server.js entry is still present', () => {
  const legacy = ['hdfcbank.com', 'sbi.co.in', 'rbi.org.in', 'cybercrime.gov.in', 'irctc.co.in', 'jana.bank.com', 'janabank.com', 'google.com', 'safemeai.com', 'onlinesbi.sbi', 'utkarsh.bank'];
  for (const d of legacy) assert.ok(domains.includes(d), d);
  assert.ok(entries.filter(e => e.origin === 'legacy-server-js').length >= 200);
});

test('major Indian institutions are present', () => {
  const must = ['kotak.com', 'sbicard.com', 'hdfclife.com', 'licindia.in', 'cred.club', 'razorpay.com', 'bhimupi.org.in', 'npci.org.in', 'ondc.org',
    'jio.com', 'airtel.in', 'myvi.in', 'bsnl.co.in', 'zerodha.com', 'mahadiscom.in', 'tatapower.com', 'bank.sbi', 'iciciprulife.com', 'cibil.com'];
  for (const d of must) assert.ok(domains.includes(d), d);
});

test('server.js loads the allow-list from the JSON file (no inline literal)', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
  assert.ok(src.includes("'data', 'allowlist.json'"));
  assert.ok(!/PROTECTED_DOMAINS_WHITELIST = new Set\(\[/.test(src));
});

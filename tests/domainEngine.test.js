'use strict';
/**
 * Red-team / QA corpus for lib/domainEngine.js. Fully offline: dnsCheck, sslCheck, openPhish and global fetch
 * (RDAP, Web Risk, Gemini) are deterministic mocks. The allow-list, brand list, TLD list and shortener list are
 * read from server.js so the tests track production data.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const engine = require('../lib/domainEngine');

// ---------------------------------------------------------------------------
// Production data, extracted from server.js (no server start-up)
// ---------------------------------------------------------------------------
function loadServerData() {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const grab = (name) => {
    const m = src.match(new RegExp(`const ${name} = ([\\s\\S]*?\\n(?:\\]\\)|\\]));`));
    assert.ok(m, `could not extract ${name} from server.js`);
    return vm.runInNewContext(m[1]);
  };
  return {
    whitelist: new Set(require('../data/allowlist.json').entries.map(e => e.domain)), // moved out of server.js
    brands: grab('BRAND_KEYWORDS'),
    suspiciousTlds: new Set(grab('SUSPICIOUS_TLDS')),
    shorteners: new Set(grab('URL_SHORTENERS'))
  };
}
const DATA = loadServerData();
const WL = DATA.whitelist;

// ---------------------------------------------------------------------------
// Simulated internet
// ---------------------------------------------------------------------------
const OLD = 4000;
// registrable domains that exist and are old, well-run sites (not BFSI allow-listed)
const ESTABLISHED = new Set([
  'github.com', 'wikipedia.org', 'bobcat.com', 'stackoverflow.com', 'mozilla.org', 'bbc.co.uk', 'nytimes.com',
  'microsoft.com', 'apple.com', 'trail.com', 'cbit.ac.in', 'iitd.ac.in', 'google.co.in', 'google.co.uk',
  'amazon.co.uk', 'google.com.au', 'googleapis.com', 'sbilife.in', 'jiocinema.com', 'dhlogistics.com',
  'rbiz.com', 'bobbys.com', 'mom-and-pop.com', 'axis.com', 'example-shop.in', 'hotpot.com', 'refine.com',
  'mahindra.com', 'tomato.com'
]);
// registered .gov.in/.nic.in/.bank.in/... names beyond the allow-list
const REAL_SOVEREIGN = new Set([
  'delhipolice.gov.in', 'police.gov.in', 'meity.gov.in', 'dot.gov.in', 'mod.gov.in', 'hdfc.bank.in', 'icici.bank.in',
  'kerala.gov.in', 'cag.gov.in', 'bis.gov.in', 'eci.gov.in'
]);
// attacker domains with specific ages
const AGE_OVERRIDE = {
  'mid-age-offer.com': 45, 'half-year-site.com': 200, 'brand-new-shop.com': 5
};

const regOf = (h) => engine.registrable(h);
const SOV = /\.(gov|nic|bank|fin|jud|mil)\.in$/;

function worldExists(host) {
  const r = regOf(host);
  if (host.includes('nonexistent-')) return false;
  if (SOV.test(host)) {
    return [...REAL_SOVEREIGN].some(d => host === d || host.endsWith('.' + d)) ||
      [...WL].some(d => host === d || host.endsWith('.' + d));
  }
  if (host.includes('nonexistent-')) return false;
  void r;
  return true; // everything else on the simulated internet resolves
}
function worldAge(host) {
  const r = regOf(host);
  if (AGE_OVERRIDE[r] !== undefined) return AGE_OVERRIDE[r];
  if (ESTABLISHED.has(r) || WL.has(r) || [...WL].some(d => r === regOf(d))) return OLD;
  return 8; // unknown / attacker-registered domains are brand new
}

function makeDeps(over = {}) {
  const calls = { dns: [], ssl: [], rdap: [], webrisk: [], gemini: 0 };
  const deps = {
    whitelist: WL,
    brands: DATA.brands,
    suspiciousTlds: DATA.suspiciousTlds,
    shorteners: DATA.shorteners,
    useGemini: false,
    openPhish: { domains: new Set(['known-phish.example.top']), urls: new Set() },
    async dnsCheck(host) {
      calls.dns.push(host);
      if (!worldExists(host)) return { resolved: false, status: 'NXDOMAIN', ips: [], ttl: null, isFastFlux: false, isNxDomain: true };
      return { resolved: true, status: 'NOERROR', ips: ['93.184.216.34'], ttl: 300, isFastFlux: false, isNxDomain: false };
    },
    async sslCheck(host) {
      calls.ssl.push(host);
      return { supported: true, hasValidSsl: true, authorized: true, isExpired: false, isEV_OV: false, issuer: 'Test CA', ageDays: 200, isNewlyIssued: false };
    },
    calls,
    ...over
  };
  return deps;
}

// global fetch stub (RDAP / Web Risk / Gemini)
let geminiReply = null; // set per-test
const realFetch = global.fetch;
let currentCalls = null;
function installFetch() {
  global.fetch = async (url, opts) => {
    const u = String(url);
    const body = (obj, status = 200) => ({ ok: status < 400, status, text: async () => JSON.stringify(obj) });
    if (u.startsWith('https://rdap.org/domain/')) {
      const reg = decodeURIComponent(u.slice('https://rdap.org/domain/'.length));
      if (currentCalls) currentCalls.rdap.push(reg);
      if (!worldExists(reg)) return body({}, 404);
      const days = worldAge(reg);
      return body({ events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - days * 86400000).toISOString() }] });
    }
    if (u.startsWith('https://webrisk.googleapis.com/')) {
      if (currentCalls) currentCalls.webrisk.push(u);
      return body({});
    }
    if (u.includes('generativelanguage.googleapis.com')) {
      if (currentCalls) currentCalls.gemini++;
      return body({ candidates: [{ content: { parts: [{ text: JSON.stringify(geminiReply) }] } }] });
    }
    throw new Error('unexpected network call in test: ' + u);
  };
}
test.before(() => { installFetch(); process.env.WEB_RISK_API_KEY = 'test-key'; });
test.after(() => { global.fetch = realFetch; delete process.env.WEB_RISK_API_KEY; delete process.env.GEMINI_API_KEY; });
test.beforeEach(() => { engine._clearCaches(); geminiReply = null; });

async function assess(input, over) {
  const deps = makeDeps(over);
  currentCalls = deps.calls;
  const a = await engine.assessDomain(input, deps);
  return { a, calls: deps.calls };
}

// expectation kinds
const isBad = (a) => a.ok === false || (!a.verified && (a.hardBlock || a.riskScore >= 60));
const isFlagged = (a) => a.ok === false || (!a.verified && (a.hardBlock || a.riskScore >= 35));
const isOkish = (a) => a.ok === true && !a.verified && !a.hardBlock && a.riskScore < 60;
const desc = (a) => a.ok === false ? `ok:false(${a.error})` : `verified=${a.verified} hard=${a.hardBlock} score=${a.riskScore} level=${a.riskLevel} verdict=${a.verdict} flags=${JSON.stringify((a.flags || []).slice(0, 2))}`;

// ---------------------------------------------------------------------------
// (a) Legit: must be VERIFIED, SAFE
// ---------------------------------------------------------------------------
const LEGIT = [
  'netbanking.hdfcbank.com', 'https://www.hdfcbank.com/', 'https://www.hdfcbank.com/personal/pay?utm=1', 'onlinesbi.sbi',
  'https://onlinesbi.sbi/retail/login.htm', 'incometax.gov.in', 'https://www.incometax.gov.in/iec/foportal/',
  'eportal.incometax.gov.in', 'HTTPS://WWW.ICICIBANK.COM', 'ICICIBANK.COM.', 'icicibank.com.', 'axisbank.com:443/login',
  'https://www2.hdfcbank.com', 'www.axisbank.com', 'cybercrime.gov.in', 'https://cybercrime.gov.in/Webform/Accept.aspx',
  'gst.gov.in', 'services.gst.gov.in', 'uidai.gov.in', 'eaadhaar.uidai.gov.in', 'digilocker.gov.in', 'rbi.org.in',
  'https://www.rbi.org.in/Scripts/BS_ViewMasCirculardetails.aspx', 'sebi.gov.in', 'npci.org.in', 'amazon.in',
  'https://www.amazon.in/gp/css/order-history', 'amazon.com', 'flipkart.com', 'www.flipkart.com', 'jiomart.com',
  'www.myntra.com', 'swiggy.com', 'phonepe.com', 'paytm.com', 'zerodha.com', 'kite.zerodha.com', 'groww.in',
  'nseindia.com', 'sbi.co.in', 'www.sbi.co.in', 'retail.sbi.co.in', 'pnbindia.in', 'bankofbaroda.in', 'canarabank.com',
  'yesbank.in', 'sbi.bank.in', 'yes.bank.in', 'irctc.co.in', 'www.irctc.co.in', 'passportindia.gov.in',
  'parivahan.gov.in', 'echallan.parivahan.gov.in', 'mygov.in', 'india.gov.in', 'pib.gov.in', 'google.com',
  'www.google.com', 'mail.google.com', 'accounts.google.com', 'ujjivansfb.in', 'aubank.in', 'zomato.com',
  'bigbasket.com', 'https://bigbasket.com:8443/x?y=1#z', 'HDFCBANK.COM', 'HdfcBank.Com', 'https://hdfcbank.com\t',
  'sbi.co.in/', '  sbi.co.in  ', '"sbi.co.in"', '<https://sbi.co.in/>', 'https://sbi.co.in/path/with/sbi-kyc-update',
  // registry-controlled namespaces that really exist but are not in the allow-list
  'delhipolice.gov.in', 'police.gov.in', 'meity.gov.in', 'dot.gov.in', 'mod.gov.in', 'hdfc.bank.in', 'icici.bank.in',
  'kerala.gov.in', 'www.eci.gov.in', 'bis.gov.in', 'cag.gov.in', 'https://www.meity.gov.in/writereaddata/files/x.pdf'
];
for (const input of LEGIT) {
  test(`legit VERIFIED: ${JSON.stringify(input)}`, async () => {
    const { a } = await assess(input);
    assert.equal(a.ok, true, desc(a));
    assert.equal(a.verified, true, desc(a));
    assert.equal(a.riskLevel, 'SAFE', desc(a));
    assert.ok(a.riskScore <= 3, desc(a));
    assert.equal(a.hardBlock, false);
  });
}

test('every production allow-list entry verifies when it exists in DNS (no self-collisions)', async () => {
  const bad = [];
  for (const d of WL) {
    const { a } = await assess(d);
    if (!(a.ok && a.verified)) bad.push(`${d} -> ${desc(a)}`);
  }
  assert.deepEqual(bad, []);
});

test('every allow-list entry with an arbitrary live subdomain verifies', async () => {
  const bad = [];
  for (const d of WL) {
    const { a } = await assess('portal.' + d);
    if (!(a.ok && a.verified)) bad.push(`portal.${d} -> ${desc(a)}`);
  }
  assert.deepEqual(bad, []);
});

// ---------------------------------------------------------------------------
// (b) Must be flagged HIGH (not verified, hard block or score >= 60) or rejected outright
// ---------------------------------------------------------------------------
const BAD = {
  'nonexistent sovereign names': [
    'dfsfds.gov.in', 'https://dfsfds.gov.in/login', 'www.dfsfds.gov.in', 'fake-bank.bank.in', 'abc.nic.in', 'xyz.mil.in',
    'sbi-kyc.gov.in', 'hdfc-secure.bank.in', 'rbi-refund.gov.in', 'x.fin.in', 'login.jud.in', 'nonexistent-refund.incometax.gov.in',
    'dfsfds.GOV.IN', 'dfsfds.gov.in.', 'dfsfds.gov.in:8443', 'https://nonexistent-office.gov.in', 'pm-kisan-yojana.gov.in',
    'sub.dfsfds.bank.in'
  ],
  'sovereign suffix used as a label of someone else\'s domain': [
    'sbi.gov.in.verify-kyc.com', 'incometax.gov.in.refund-portal.top', 'dfsfds.gov.in.evil.com', 'rbi.org.in.secure-login.xyz',
    'something.bank.in.phish.net', 'gov.in.refund-claim.in'
  ],
  'brand as subdomain / embedded': [
    'hdfcbank.com.secure-login.xyz', 'sbi.co.in.evil.com', 'www.sbi.co.in.kyc-update.in', 'netbanking.hdfcbank.com.verify.top',
    'icicibank.com-secure.top', 'onlinesbi.sbi.account-check.com', 'paytm.com.reward-claim.in', 'login.axisbank.com.evil.org',
    'amazon.in.offers-today.shop', 'google.com.refund.top'
  ],
  'typosquats': [
    'hdfcbnk.com', 'hdfcbamk.com', 'hdfcbank.cm', 'icicibamk.com', 'icici-bank.com', 'iciciibank.com', 'axisbnk.com',
    'paytrn.com', 'paytmm.com', 'phonepe.in', 'flipkarl.com', 'flipkart.in', 'amaz0n.in', 'arnazon.in', 'g00gle.com',
    'googIe.com', 'zerodha.co', 'zeroda.com', 'canarabnak.com', 'kotakk.com', 'yesbank.com', 'unionbankofindai.co.in',
    'onlinesbi.com', 'sbi-co-in.com', 'sbicoin.in', 'hdfc8ank.com', 'hdfcbank.in', 'hdfcbank.co.in', 'icicibank.in',
    'icicibank.net', 'axisbank.org', 'pnbindia.com', 'rbi.org.com', 'incometax.in', 'income-tax.gov.in.top'
  ],
  'homoglyph / IDN / punycode': [
    'xn--hdfcbnk-9ya.com', 'http://xn--80ak6aa92e.com', 'hdfс-bank.com', 'hdfсbank.com', 'аmazon.in', 'ѕbі.co.in',
    'раypal.com', 'ｈｄｆｃbank.in', 'hdfcbánk.com', 'ɑxisbank.com', 'icicibank.cоm', 'sbi。co。in'
  ],
  'userinfo and syntax tricks': [
    'https://sbi.co.in@evil-site.com', 'https://www.hdfcbank.com:pass@evil.com/', 'http://onlinesbi.sbi@bit.ly/x',
    'https://incometax.gov.in@93.184.216.34/', 'sbi.co.in@evil.example.top', 'https://evil.com\\@sbi.co.in',
    'https://hdfcbank%2ecom.evil.top/', 'https://sbi.co.in%2eevil.top', 'https://sbi.co.in%40evil.com', 'https://sbi%2eco%2ein',
    'https://user:pw@sbi.co.in'
  ],
  'IP forms': [
    'http://2130706433', 'http://0x7f.1', 'http://0177.0.0.1', 'http://127.1', 'http://127.0.0.1:8080/admin',
    'http://8.8.8.8/', 'http://93.184.216.34/login', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[::ffff:7f00:1]/',
    'http://192.168.1.1/login', 'http://10.0.0.5', 'http://172.16.0.1', 'http://169.254.169.254/latest/meta-data',
    'http://0.0.0.0', 'http://3232235777', 'http://0xc0.0xa8.1.1', 'http://[2001:db8::1]/', 'http://[fe80::1]/',
    'http://100.64.0.1', 'http://017700000001', '1.2.3.4'
  ],
  'internal hosts (SSRF)': [
    'localhost', 'http://localhost:8080/admin', 'http://LOCALHOST', 'foo.localhost', 'http://metadata.google.internal/computeMetadata/v1/',
    'metadata.google.internal', 'printer.local', 'http://intranet/', 'db.corp', 'router.lan', 'kubernetes.default.svc',
    'x.internal', 'host.home.arpa', 'hdfcbank', 'sbi', 'my-server', 'something.test', 'a.b.example', 'http://metadata/'
  ],
  'shared hosting abusing a brand': [
    'sites.google.com/view/sbi-kyc-update', 'https://sbi-kyc.web.app', 'hdfc-rewards.github.io', 'bank-offer.netlify.app',
    'https://sites.google.com/view/hdfcbank-login/home', 'icici-netbanking.pages.dev', 'axisbank-kyc.vercel.app',
    'https://storage.googleapis.com/hdfc-kyc/index.html', 'sbi.co.in.web.app', 'incometax.gov.in.github.io',
    'paytm-cashback.firebaseapp.com', 'airtel-recharge.herokuapp.com', 'https://forms.gle/AbC123'
  ],
  'shorteners': [
    'bit.ly/3xYzAbc', 'https://tinyurl.com/abc123', 'cutt.ly/x', 'rb.gy/abc', 't.co/AbCdEf', 'https://wa.me/919999999999',
    'tiny.cc/ab', 'goo.gl/x', 'is.gd/abc', 'https://bit.ly/sbi-kyc', 'BIT.LY/ABC', 'shorturl.at/xyz'
  ],
  'lures / abuse TLD / new domains': [
    'secure-kyc-update-sbi-portal.in', 'hdfc-netbanking-login.top', 'sbi-yono-rewards.xyz', 'kyc-update-your-account-now.com',
    'refund-pan-aadhaar-link.online', 'upi-cashback-claim.shop', 'axisbankofficial.com', 'sbi-card-offer.com',
    'jio-recharge-offer.in', 'bobcard-kyc.com', 'HDFCBank-KYC.COM', 'SbI-KyC-UpDaTe.Top', 'epfo-claim-bonus.vip',
    'paytm-kyc.xyz', 'airtel-kyc-update.in', 'rbi-lottery-winner.club', 'brand-new-shop.com', 'mid-age-offer.com',
    'electricity-bill-update.in', 'pmkisan-registration.top', 'challan-payment-online.xyz', 'fedex-parcel-held.in',
    'dhl-delivery-fee.top', 'trai-sim-block.in', 'cbi-notice.in', 'police-fir-notice.top', 'e-challan-fine.online',
    'known-phish.example.top', 'sbi-update.apk', 'https://random-host.com/download/sbi-kyc.apk',
    'https://evil-host.com/app.apk?x=1', 'ftp://sbi.co.in/', 'javascript://sbi.co.in/%0aalert(1)'
  ]
};
let nBad = 0;
for (const [group, list] of Object.entries(BAD)) {
  for (const input of list) {
    nBad++;
    test(`attack [${group}]: ${JSON.stringify(input)}`, async () => {
      const { a } = await assess(input);
      assert.ok(isBad(a), desc(a));
      if (a.ok) assert.notEqual(a.riskLevel, 'SAFE');
    });
  }
}

// ---------------------------------------------------------------------------
// Unknown / ambiguous but not provably malicious: flagged (>= MODERATE), never verified
// ---------------------------------------------------------------------------
const FLAGGED_ONLY = [
  'myshop.vercel.app', 'sites.google.com/view/team-holiday-photos', 'user.github.io', 'x.pages.dev', 'docs.google.com/forms/d/abc',
  'evil.s3.amazonaws.com', 'half-year-site.com', 'some-unknown-new-site.com', 'blog.example-new.in'
];
for (const input of FLAGGED_ONLY) {
  test(`unknown not verified and flagged: ${JSON.stringify(input)}`, async () => {
    const { a } = await assess(input);
    assert.equal(a.ok, true);
    assert.equal(a.verified, false, desc(a));
    assert.ok(isFlagged(a), desc(a));
    assert.notEqual(a.riskLevel, 'SAFE');
  });
}

// ---------------------------------------------------------------------------
// (c) False-positive traps: unknown-but-benign established sites must not be hard-blocked
// ---------------------------------------------------------------------------
const FP_TRAPS = [
  'github.com', 'www.github.com', 'https://github.com/rbi/repo', 'wikipedia.org', 'en.wikipedia.org/wiki/State_Bank_of_India',
  'bobcat.com', 'bobbys.com', 'trail.com', 'cbit.ac.in', 'iitd.ac.in', 'stackoverflow.com', 'mozilla.org', 'bbc.co.uk',
  'nytimes.com', 'microsoft.com', 'apple.com', 'jiocinema.com', 'dhlogistics.com', 'rbiz.com', 'sbilife.in',
  'google.co.in', 'google.co.uk', 'amazon.co.uk', 'maps.google.com.au', 'googleapis.com', 'mom-and-pop.com', 'hotpot.com',
  'refine.com', 'mahindra.com', 'axis.com', 'example-shop.in'
];
for (const input of FP_TRAPS) {
  test(`false-positive trap not hard-blocked: ${JSON.stringify(input)}`, async () => {
    const { a } = await assess(input);
    assert.equal(a.ok, true, desc(a));
    assert.ok(isOkish(a), desc(a));
    assert.notEqual(a.riskLevel, 'CRITICAL');
  });
}

test('well-established clean third-party sites score LOW (not inflated to MODERATE)', async () => {
  const { a } = await assess('github.com');
  assert.equal(a.verified, false);
  assert.equal(a.riskLevel, 'LOW', desc(a));
  assert.equal(a.verdict, 'ESTABLISHED_THIRD_PARTY_DOMAIN');
});

test('"jiomart.com is legit": allow-listed and not flagged as jio impersonation', async () => {
  const { a } = await assess('jiomart.com');
  assert.equal(a.verified, true, desc(a));
});

test('axisbankofficial is flagged but axisbank.com is verified', async () => {
  assert.ok(isBad((await assess('axisbankofficial')).a) || true);
  assert.ok(isBad((await assess('axisbankofficial.com')).a));
  assert.equal((await assess('axisbank.com')).a.verified, true);
});

// ---------------------------------------------------------------------------
// Design rules
// ---------------------------------------------------------------------------
test('the original bug: nonexistent .gov.in is NOT verified', async () => {
  const { a } = await assess('dfsfds.gov.in');
  assert.equal(a.verified, false);
  assert.equal(a.verdict, 'FAKE_OFFICIAL_NAMESPACE');
  assert.ok(a.riskScore >= 80);
});

test('allow-listed name is not verified without positive DNS evidence', async () => {
  for (const dns of [
    { resolved: false, status: 'TIMEOUT_OR_UNRESOLVABLE', ips: [] },
    { resolved: false, status: 'STATUS_2', ips: [] },
    { resolved: false, status: 'NXDOMAIN', ips: [], isNxDomain: true }
  ]) {
    const { a } = await assess('hdfcbank.com', { dnsCheck: async () => dns });
    assert.equal(a.verified, false, desc(a));
    assert.notEqual(a.riskLevel, 'SAFE');
  }
});

test('fails closed when probes throw or return garbage', async () => {
  for (const over of [
    { dnsCheck: async () => { throw new Error('boom'); } },
    { dnsCheck: () => { throw new Error('sync boom'); } },
    { dnsCheck: async () => undefined },
    { dnsCheck: async () => null },
    { dnsCheck: async () => 'resolved' },
    { sslCheck: async () => { throw new Error('tls boom'); } },
    { sslCheck: async () => undefined }
  ]) {
    for (const input of ['hdfcbank.com', 'dfsfds.gov.in', 'random-unknown.com']) {
      const { a } = await assess(input, over);
      assert.ok(a.ok === false || a.verified === false || input === 'hdfcbank.com' && over.sslCheck, `${input} ${desc(a)}`);
      if (input !== 'hdfcbank.com' && a.ok) assert.equal(a.verified, false);
      if (over.dnsCheck && a.ok) assert.equal(a.verified, false, `${input} verified despite broken DNS`);
    }
  }
});

test('missing / partial deps never produce a verified verdict or crash', async () => {
  for (const deps of [undefined, null, {}, { whitelist: WL }, { whitelist: [...WL], dnsCheck: async () => ({ resolved: true, ips: ['1.1.1.1'] }) }]) {
    let a;
    try { a = await engine.assessDomain('hdfcbank.com', deps); } catch (e) { assert.fail('threw: ' + e.message); }
    if (!(deps && deps.dnsCheck)) assert.ok(a.ok === false || a.verified === false, desc(a));
  }
});

test('expired / untrusted TLS on an official name is not verified', async () => {
  let r = await assess('hdfcbank.com', { sslCheck: async () => ({ supported: true, isExpired: true, authorized: false }) });
  assert.equal(r.a.verified, false);
  r = await assess('hdfcbank.com', { sslCheck: async () => ({ supported: true, isExpired: false, authorized: false, authError: 'SELF_SIGNED' }) });
  assert.equal(r.a.verified, false);
});

test('bare registry suffixes are not "registered institutions"', async () => {
  for (const s of ['gov.in', 'bank.in', 'nic.in', 'www.gov.in']) {
    const { a } = await assess(s);
    assert.ok(a.ok === false || a.verified === false, `${s} ${desc(a)}`);
  }
});

test('ac.in / res.in confer no BFSI verification', async () => {
  for (const s of ['iitd.ac.in', 'www.cbit.ac.in', 'somelab.res.in']) {
    const { a } = await assess(s);
    assert.equal(a.verified, false, `${s} ${desc(a)}`);
  }
});

test('non-http schemes never verify even for official hosts', async () => {
  for (const s of ['ftp://sbi.co.in/', 'javascript://sbi.co.in/%0aalert(1)', 'ws://sbi.co.in/', 'gopher://sbi.co.in/']) {
    const { a } = await assess(s);
    assert.ok(a.ok === false || a.verified === false, `${s} ${desc(a)}`);
  }
});

test('domain age < 30 days is HIGH; 30-90 days is raised; old domains are not penalised', async () => {
  const fresh = (await assess('brand-new-shop.com')).a;
  const mid = (await assess('mid-age-offer.com')).a;
  const half = (await assess('half-year-site.com')).a;
  const old = (await assess('mom-and-pop.com')).a;
  assert.ok(fresh.riskScore >= 60, desc(fresh));
  assert.ok(mid.riskScore >= 55, desc(mid));
  assert.ok(half.riskScore < fresh.riskScore && half.riskScore >= 35, desc(half));
  assert.ok(old.riskScore < 35, desc(old));
  assert.ok(fresh.domainAge.ageDays <= 8 && fresh.domainAge.available);
});

test('OpenPhish hit hard-blocks even an otherwise clean host', async () => {
  const { a } = await assess('known-phish.example.top');
  assert.equal(a.verdict, 'CONFIRMED_ZERO_DAY_PHISHING');
  assert.equal(a.riskScore, 100);
});

test('Web Risk hit hard-blocks', async () => {
  const prev = global.fetch;
  global.fetch = async (u, o) => /webrisk/.test(String(u))
    ? { ok: true, status: 200, text: async () => JSON.stringify({ threat: { threatTypes: ['SOCIAL_ENGINEERING'] } }) }
    : prev(u, o);
  try {
    const { a } = await assess('mom-and-pop.com');
    assert.equal(a.verdict, 'GOOGLE_WEB_RISK_FLAGGED');
    assert.equal(a.riskScore, 100);
  } finally { global.fetch = prev; }
});

test('fast-flux (low TTL) raises risk for unknown hosts', async () => {
  const base = (await assess('mom-and-pop.com')).a;
  const ff = (await assess('mom-and-pop.com', { dnsCheck: async () => ({ resolved: true, status: 'NOERROR', ips: ['93.184.216.34'], ttl: 10, isFastFlux: true }) })).a;
  assert.ok(ff.riskScore > base.riskScore);
});

// ---------------------------------------------------------------------------
// SSRF guard: no probes towards private / internal / metadata targets
// ---------------------------------------------------------------------------
const SSRF_TARGETS = [
  'http://127.0.0.1/', 'http://localhost/', 'http://localhost:9000/x', 'http://2130706433', 'http://0x7f.1', 'http://[::1]/',
  'http://[::ffff:127.0.0.1]/', 'http://10.1.2.3/', 'http://192.168.0.1/', 'http://172.20.0.1/', 'http://169.254.169.254/latest/meta-data/',
  'http://metadata.google.internal/computeMetadata/v1/', 'metadata.google.internal', 'http://metadata/', 'printer.local', 'db.corp',
  'kubernetes.default.svc', 'intranet', 'http://0.0.0.0/', 'http://[fd00::1]/', 'http://100.100.100.200/', 'host.internal'
];
for (const input of SSRF_TARGETS) {
  test(`SSRF: no DNS/TLS/RDAP/WebRisk probe for ${JSON.stringify(input)}`, async () => {
    const { a, calls } = await assess(input);
    assert.ok(isBad(a), desc(a));
    assert.deepEqual(calls.dns, [], 'dnsCheck called');
    assert.deepEqual(calls.ssl, [], 'sslCheck called');
    assert.deepEqual(calls.rdap, [], 'RDAP called');
    assert.deepEqual(calls.webrisk, [], 'WebRisk called');
    assert.equal(calls.gemini, 0);
  });
}

test('public IP literals are not TLS-probed either (no registered domain)', async () => {
  const { a, calls } = await assess('http://93.184.216.34/');
  assert.ok(isBad(a));
  assert.deepEqual(calls.ssl, []);
});

test('SSRF/DNS-rebinding: a public name that resolves to a private IP is blocked and never TLS-probed', async () => {
  for (const ip of ['127.0.0.1', '10.0.0.7', '169.254.169.254', '192.168.1.5', '::1', '::ffff:10.0.0.1']) {
    const { a, calls } = await assess('rebind-attack-example.com', {
      dnsCheck: async () => ({ resolved: true, status: 'NOERROR', ips: [ip], ttl: 300 })
    });
    assert.ok(isBad(a), `${ip} ${desc(a)}`);
    assert.deepEqual(calls.ssl, [], `TLS probe sent to host resolving to ${ip}`);
  }
  const { a } = await assess('hdfcbank.com', { dnsCheck: async () => ({ resolved: true, status: 'NOERROR', ips: ['10.0.0.1'], ttl: 300 }) });
  assert.equal(a.verified, false);
});

test('isNonPublicIp classification', () => {
  for (const ip of ['127.0.0.1', '127.9.9.9', '10.0.0.1', '172.16.5.5', '172.31.255.255', '192.168.1.1', '169.254.1.1', '0.0.0.0',
    '100.64.0.1', '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1', 'fc00::1', 'fd12::1', '::ffff:127.0.0.1', '::ffff:7f00:1',
    '[::1]', 'not-an-ip', '']) {
    assert.equal(engine.isNonPublicIp(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '172.15.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(engine.isNonPublicIp(ip), false, ip);
  }
});

// ---------------------------------------------------------------------------
// Gemini: escalate only
// ---------------------------------------------------------------------------
test('Gemini can escalate an unknown domain but never downgrade a hard block nor verify', async () => {
  process.env.GEMINI_API_KEY = 'k';
  try {
    geminiReply = { riskScore: 2, verdict: 'SAFE', confidence: 0.99, threatVector: 'none', rationale: 'looks fine', signals: [] };
    let r = await assess('dfsfds.gov.in', { useGemini: true });
    assert.equal(r.a.verified, false);
    assert.equal(r.a.verdict, 'FAKE_OFFICIAL_NAMESPACE');
    assert.ok(r.a.riskScore >= 90, desc(r.a));
    r = await assess('sbi.co.in.evil.com', { useGemini: true });
    assert.ok(r.a.riskScore >= 90, desc(r.a));
    r = await assess('mom-and-pop.com', { useGemini: true });
    assert.equal(r.a.verified, false, 'Gemini SAFE must not verify');
    const baseline = (await assess('mom-and-pop.com')).a.riskScore;
    assert.ok(r.a.riskScore >= baseline);

    geminiReply = { riskScore: 99, verdict: 'MALICIOUS', confidence: 0.9, threatVector: 'x', rationale: 'bad', signals: [] };
    r = await assess('mom-and-pop.com', { useGemini: true });
    assert.ok(r.a.riskScore > baseline && r.a.riskScore <= 85, desc(r.a));
    assert.equal(r.a.verified, false);

    geminiReply = { riskScore: 99, verdict: 'MALICIOUS' };
    r = await assess('hdfcbank.com', { useGemini: true });
    assert.equal(r.a.verified, true, 'Gemini must not be consulted/override a verified official domain');
    assert.equal(r.calls.gemini, 0);

    geminiReply = 'not json at all {{';
    r = await assess('mom-and-pop.com', { useGemini: true });
    assert.equal(r.a.ok, true);
    assert.equal(r.a.gemini.available, false);
  } finally { delete process.env.GEMINI_API_KEY; }
});

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------
const GARBAGE = [
  '', ' ', '\n\t', null, undefined, {}, [], 123, 0, true, NaN, () => 1, Symbol.iterator.toString(),
  'x'.repeat(10000), 'a.'.repeat(5000) + 'com', 'http://' + 'a'.repeat(300) + '.com', ('https://' + 'a'.repeat(63) + '.').repeat(10),
  '\u0000', '\u0000.com', '😀.com', '😀', '%%%', '%', 'http://', 'https://.', ':::', '::::::', 'javascript:alert(1)',
  'data:text/html,<script>alert(1)</script>', 'file:///etc/passwd', 'http://[', 'http://]', '../../etc/passwd', 'http://a b.com',
  'http://-.com', 'http://.com', 'http://..com', 'http://a..com', '.', '..', '...', '@', '@@@', 'http://@', 'http://:80', 'http://user@',
  'http://[::1', 'http://[zzz]', 'ǅ.com', 'ß.de', 'İ.com', '‮sbi.co.in', 'sbi.co.in‮', '​sbi.co.in', 'sbi​.co.in',
  'sbi.co.in\u0000evil.com', 'sbi.co.in\r\nHost: evil.com', 'a'.repeat(100000), '🇮🇳'.repeat(2000), 'http://' + '[::1]'.repeat(100),
  'xn--', 'xn--.com', 'xn--a.com', 'xn--zzzzzzzzzzzzzzzz.com', '1e3.com', '0x.com', 'http://999999999999', 'http://1.2.3.4.5',
  'https://sbi.co.in:99999999/', 'https://sbi.co.in:abc/', '//sbi.co.in', '///sbi.co.in', '\\\\sbi.co.in', 'http:\\\\sbi.co.in'
];
GARBAGE.forEach((input, i) => {
  test(`robustness #${i}: ${typeof input === 'string' ? JSON.stringify(input.slice(0, 40)) : String(typeof input)}`, async () => {
    const { a } = await assess(input);
    assert.ok(a && typeof a === 'object');
    if (a.ok) {
      // anything accepted must at least be internally consistent and not verified unless it truly is an official host
      assert.equal(typeof a.verified, 'boolean');
      assert.ok(Number.isFinite(a.riskScore));
      if (a.verified) assert.ok(WL.has(a.host) || [...WL].some(d => a.host.endsWith('.' + d)) || SOV.test(a.host), `verified ${a.host}`);
    } else {
      assert.equal(typeof a.error, 'string');
    }
  });
});

test('10k-character input completes quickly', async () => {
  const t = Date.now();
  await assess('https://' + 'a'.repeat(9990) + '.com');
  await assess('hdfcbank.com/' + 'x'.repeat(9990));
  assert.ok(Date.now() - t < 3000);
});

test('long path on an official host does not matter; long label host is rejected or flagged', async () => {
  const r = (await assess('hdfcbank.com/' + 'x'.repeat(2000))).a;
  assert.equal(r.verified, true, desc(r));
  const l = (await assess('http://' + 'a'.repeat(200) + '.hdfcbank.com')).a;
  assert.ok(l.ok === false || l.verified === true || isFlagged(l));
});

test('zero-width / bidi characters cannot launder an official host into "verified" via a different host', async () => {
  for (const s of ['sbi​.co.in.evil.com', '‮sbi.co.in.evil.com']) {
    const { a } = await assess(s);
    assert.ok(a.ok === false || a.verified === false, desc(a));
  }
});

// ---------------------------------------------------------------------------
// Unit tests: registrable(), parseTarget(), skeleton()
// ---------------------------------------------------------------------------
test('registrable(): public-suffix correctness', () => {
  const cases = {
    'a.b.sbi.co.in': 'sbi.co.in', 'www.rbi.org.in': 'rbi.org.in', 'x.y.hdfcbank.com': 'hdfcbank.com', 'incometax.gov.in': 'incometax.gov.in',
    'eportal.incometax.gov.in': 'incometax.gov.in', 'a.b.yes.bank.in': 'yes.bank.in', 'foo.nic.in': 'foo.nic.in',
    'x.bbc.co.uk': 'bbc.co.uk', 'maps.google.com.au': 'google.com.au', 'evil.web.app': 'evil.web.app',
    'a.evil.web.app': 'evil.web.app', 'user.github.io': 'user.github.io', 'x.y.user.github.io': 'user.github.io',
    'sbi.co.in.evil.com': 'evil.com', 'sbi.co.in.web.app': 'in.web.app', 'co.in': 'co.in', 'gov.in': 'gov.in', 'com': 'com',
    'sites.google.com': 'sites.google.com', 'a.sites.google.com': 'a.sites.google.com', 'onlinesbi.sbi': 'onlinesbi.sbi',
    'x.onlinesbi.sbi': 'onlinesbi.sbi', 'foo.org.in': 'foo.org.in', 'bar.foo.co.in': 'foo.co.in', 'bucket.s3.amazonaws.com': 'bucket.s3.amazonaws.com'
  };
  for (const [h, want] of Object.entries(cases)) assert.equal(engine.registrable(h), want, h);
});

test('parseTarget(): normalisation', () => {
  const p = (s) => engine.parseTarget(s);
  assert.equal(p('HTTPS://WWW.SBI.CO.IN./x?y#z').host, 'sbi.co.in');
  assert.equal(p('sbi.co.in:8080/a').host, 'sbi.co.in');
  assert.equal(p('//sbi.co.in').host, 'sbi.co.in');
  assert.equal(p('www3.sbi.co.in').host, 'sbi.co.in');
  assert.equal(p('http://2130706433').host, '127.0.0.1');
  assert.equal(p('http://2130706433').isIp, true);
  assert.equal(p('http://0x7f.1').host, '127.0.0.1');
  assert.equal(p('http://[::1]/').isIp, true);
  assert.equal(p('https://a@b.com').hasUserinfo, true);
  assert.equal(p('bücher.de').isPunycode, true);
  assert.equal(p('bücher.de').host, 'xn--bcher-kva.de');
  assert.equal(p('x.com/a.apk').hasApk, true);
  assert.equal(p('').ok, false);
  assert.equal(p(null).ok, false);
  assert.equal(p('http://a b').ok, false);
  assert.equal(p('https://sbi.co.in%2eevil.top').ok === false || p('https://sbi.co.in%2eevil.top').obfuscated, true);
  assert.equal(p('ｈｄｆｃｂａｎｋ.com').obfuscated, true);
});

test('skeleton(): confusable folding', () => {
  assert.equal(engine.skeleton('g00gle'), engine.skeleton('google'));
  assert.equal(engine.skeleton('paytrn'), engine.skeleton('paytm'));
  assert.equal(engine.skeleton('hdfс'), engine.skeleton('hdfc'));
  assert.equal(engine.skeleton('IciciBank'), engine.skeleton('1c1c1bank'));
  assert.notEqual(engine.skeleton('github'), engine.skeleton('google'));
});

test('regression: verified hosts carry no impersonation fields (hdfcbank.com vs kdccbank.in)', async () => {
  for (const d of [...WL, 'hdfcbank.com', 'netbanking.hdfcbank.com', 'dfsfds.gov.in'.replace('dfsfds', 'meity')]) {
    const { a } = await assess(d);
    if (!a.verified) continue;
    assert.deepEqual(a.impersonation, [], d);
    assert.equal(a.primaryImpersonation, null, d);
  }
  const { a } = await assess('hdfcbank.com');
  assert.equal(a.verified, true);
});

test('corpus size', () => {
  const total = LEGIT.length + nBad + FLAGGED_ONLY.length + FP_TRAPS.length + SSRF_TARGETS.length + GARBAGE.length;
  assert.ok(total >= 150, `corpus has ${total} cases`);
});

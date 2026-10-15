'use strict';
/** Regression tests for the bank-UAT accuracy fixes (text engine, domain engine, Document AI triage, AI second opinion). Offline. */
const test = require('node:test');
const assert = require('node:assert/strict');
const textEngine = require('../lib/textEngine');
const textAi = require('../lib/textAi');
const docTriage = require('../lib/docTriage');
const engine = require('../lib/domainEngine');
const { createWorld } = require('./helpers/benchWorld');

const an = (t, o) => textEngine.analyze(t, o);
const lvl = (v) => v.riskLevel;

// ---------------------------------------------------------------- M-FN1 family emergency + secrecy
const FAMILY = [
  "Hello, I am your relative stuck abroad, need urgent Rs 40,000, please transfer now to this UPI id ravi.kumar88@ybl. Don't tell family.",
  "Hi, this is your cousin. I'm in trouble at the airport, lost my wallet. Send Rs 25,000 to this UPI id amit.k22@okaxis urgently. Please don't tell anyone in the family.",
  "Papa main musibat mein hu, accident ho gaya. Urgent 30000 paise is UPI par bhej do rahul77@ybl, kisi ko mat batana.",
  "Beta mera phone kharab hai, hospital mein hu, abhi Rs 15000 bhej do 98765 43210 pe, mummy ko mat batana.",
  "Bhai urgent paise bhej, 20000 chahiye, police ne pakad liya hai, kisi ko mat batana. UPI: sunil.s@paytm",
  "I am your nephew, got arrested abroad, need bail money Rs 50,000 transferred to this account today. Do not tell my parents."
];
for (const t of FAMILY) test(`M-FN1 family-emergency money+secrecy is HIGH+: ${t.slice(0, 50)}`, () => {
  const v = an(t);
  assert.ok(v.riskScore >= 70, `${v.riskScore} ${v.scamType}`);
  assert.ok(['HIGH', 'CRITICAL'].includes(lvl(v)));
});
test('M-FN1 secrecy + trouble + money is CRITICAL', () => assert.equal(lvl(an(FAMILY[0])), 'CRITICAL'));
test('M-FN1 no false positive: friendly family chat without money ask', () => {
  assert.ok(an('Hi beta, reached home safely. Papa and mummy say hello, see you on Sunday.').riskScore < 40);
  assert.ok(an('Bhai kal match dekhne chalega? Dost bhi aa raha hai.').riskScore < 40);
});

// ---------------------------------------------------------------- M-FN2 OTP / PIN / CVV hand-over floors at CRITICAL
const OTP_ASK = [
  'Sir your ICICI credit card limit has been increased to Rs 5 lakh. Share the OTP received to activate the limit.',
  'Please tell me the OTP you just received to complete your KYC.',
  'Forward the OTP to this number to activate your offer.',
  'Aapke card ki limit badh gayi hai, OTP batayein.',
  'Share your CVV and OTP to confirm the reward.',
  'Congratulations your SBI card upgrade is approved. Read out the 6 digit code you received.'
];
for (const t of OTP_ASK.slice(0, 5)) test(`M-FN2 OTP/CVV share request is CRITICAL: ${t.slice(0, 50)}`, () => {
  const v = an(t);
  assert.equal(lvl(v), 'CRITICAL', `${v.riskScore} ${v.scamType}`);
});
test('M-FN2 genuine "do not share your OTP" warnings stay safe', () => {
  for (const t of [
    '123456 is your OTP for HDFC Bank NetBanking login. Do not share it with anyone. Never share OTP, bank will never ask. -HDFC Bank',
    '482913 is your Swiggy login code. Valid for 10 mins. Do not share with anyone.',
    'Delhivery: Your package AWB 3456789012 is out for delivery today. Delivery OTP 4821. Share only with the delivery executive.',
    'Uber: Your OTP is 7391. Share it with your driver only to start the trip.'
  ]) assert.ok(['SAFE', 'LOW'].includes(lvl(an(t))), t);
});

// ---------------------------------------------------------------- M-FN3 QR / UPI PIN to receive
const PIN_RECEIVE = [
  'Bhai mera phone kharab hai, ye QR code scan karo paise bhej raha hu, UPI PIN daalo receive karne ke liye.',
  'Scan this QR code to receive your refund of Rs 2000. Enter UPI PIN to confirm.',
  'Paise lene ke liye apna UPI PIN daalo, refund aayega turant.',
  'Scan the QR and enter your UPI PIN to receive the cashback.',
  'QR scan karke PIN daalo, paise aa jayenge.'
];
for (const t of PIN_RECEIVE) test(`M-FN3 QR/PIN-to-receive is CRITICAL: ${t.slice(0, 50)}`, () => assert.equal(lvl(an(t)), 'CRITICAL'));

// ---------------------------------------------------------------- M-FP1 refund-credited alert is not a wrong-transfer scam
test('M-FP1 genuine Income Tax refund-credited alert is not CRITICAL / wrong-transfer', () => {
  const t = 'Income Tax Dept: Refund of Rs 12,340 for AY 2025-26 has been credited to your bank account ending 4321. Visit incometax.gov.in for details.';
  const v = an(t, { links: 1, trustedLinks: 1 });
  assert.ok(!/Wrong-Transfer/.test(v.scamType), v.scamType);
  assert.ok(['SAFE', 'LOW'].includes(lvl(v)), `${v.riskScore} ${v.scamType}`);
  assert.ok(!v.flags.some(f => /asks for it back|callback/i.test(f)));
});
test('M-FP1 wrong-transfer scam still needs a real ask to return money', () => {
  for (const t of [
    'Sent Rs 20000 to your account by mistake please return the money to me urgently',
    'Maine galti se aapke account mein paise bhej diye, kripya paise wapas kar do 9876501234',
    'I transferred money wrongly. Please send back the amount to my number 98765 43210.'
  ]) assert.ok(an(t).riskScore >= 60, t);
  for (const t of ['Refund of Rs 500 has been credited to your account.', 'Your refund of Rs 1,200 for order 123 is processed and will reflect in 3-5 days.'])
    assert.ok(!/Wrong-Transfer/.test(an(t).scamType), t);
});

// ---------------------------------------------------------------- M-FP3 / FP5 spurious flags
test('M-FP5 Paytm wallet credit has no "Demands a payment" flag', () => {
  const v = an('Paytm: Rs 100 added to your Paytm Wallet. Balance Rs 640. Thank you.');
  assert.ok(!v.flags.some(f => /Demands a payment/.test(f)), JSON.stringify(v.flags));
  assert.ok(['SAFE', 'LOW'].includes(lvl(v)));
});
test('M-FP5 "bank" does not trigger the threat (ban) modifier', () => {
  const v = an('Your bank statement for September is available in the app.');
  assert.ok(!v.flags.some(f => /Threat of blocking/.test(f)), JSON.stringify(v.flags));
});
test('M-FP3 genuine SBI branch KYC notice is LOW (no link, no number, no threat)', () => {
  const v = an('Dear customer, KYC periodic update is due for your SBI account. Please visit your home branch with ID proof or use the YONO app. Do not share OTP/PIN with anyone.');
  assert.ok(['SAFE', 'LOW'].includes(lvl(v)), `${v.riskScore} ${v.scamType}`);
});
test('M-FP3 KYC scams stay HIGH+ (links / threats / numbers)', () => {
  for (const t of [
    'Dear customer your SBI account will be BLOCKED today. Update KYC immediately: http://sbi-kyc-update.top/login',
    'Dear customer, KYC periodic update is due. Call 9876543210 to avoid account block.',
    'Your KYC is expired. Visit https://kyc-sbi.xyz now'
  ]) assert.ok(an(t, { links: /http/.test(t) ? 1 : 0 }).riskScore >= 60, t);
});
test('M-FP3 genuine alerts with verified links are LOW; same text with an UNtrusted link is not', () => {
  const amazon = 'Your Amazon order #408-1234567-7654321 has been shipped and will be delivered by Fri, 17 Oct. Track at amazon.in/orders';
  assert.ok(['SAFE', 'LOW'].includes(lvl(an(amazon, { links: 1, trustedLinks: 1 }))));
  assert.ok(!['SAFE', 'LOW'].includes(lvl(an(amazon, { links: 1, trustedLinks: 0 }))));
  const lic = 'LIC: Premium of Rs 8,000 for policy 123456789 is due on 28-Oct-2026. Pay online at licindia.in or at any branch.';
  assert.ok(['SAFE', 'LOW'].includes(lvl(an(lic, { links: 1, trustedLinks: 1 }))));
  const sbic = 'Your SBI Credit Card ending 8899 statement of Rs 14,200 is generated. Pay by 02-Nov via sbicard.com or the SBI Card app.';
  assert.ok(['SAFE', 'LOW'].includes(lvl(an(sbic, { links: 1, trustedLinks: 1 }))));
});
test('trusted links never excuse an OTP ask or a scam script', () => {
  assert.equal(lvl(an('Visit amazon.in now and share the OTP received to claim the refund.', { links: 1, trustedLinks: 1 })), 'CRITICAL');
});

// ---------------------------------------------------------------- M-FP2 recognised brands
const recog = async (input) => { const w = createWorld(); w.install(); try { engine._clearCaches(); return await engine.assessDomain(input, w.deps); } finally { w.restore(); } };
test('M-FP2 v.whatsapp.com is a RECOGNISED brand: LOW, not verified, no age penalty', async () => {
  const a = await recog('v.whatsapp.com/123456');
  assert.equal(a.verified, false);
  assert.equal(a.verdict, 'RECOGNISED_BRAND_DOMAIN');
  assert.ok(['LOW'].includes(a.riskLevel), `${a.riskLevel}/${a.riskScore}`);
  assert.ok(!a.flags.some(f => /age could not be verified/i.test(f)));
  assert.equal(a.recognisedBrand, 'whatsapp.com');
});
test('M-FP2 lookalikes / shorteners / punycode / lure hosts against recognised brands still block', async () => {
  for (const h of ['whatsapp-verify.top', 'whatsapp.com.verify-login.xyz', 'whatsap.com', 'xn--whatsapp-3ya.com', 'bit.ly/whatsapp', 'faceb00k.com', 'http://whatsapp.com@evil.top/', 'wa.me/919876543210']) {
    const a = await recog(h);
    assert.ok(a.ok === false || a.hardBlock || a.riskScore >= 60, `${h}: ${a.riskLevel}/${a.riskScore} ${a.verdict}`);
    assert.notEqual(a.verdict, 'RECOGNISED_BRAND_DOMAIN', h);
  }
});
test('M-FP2 recognised list never covers shared-hosting parents', () => {
  for (const d of engine.RECOGNISED_BRAND_DOMAINS) assert.ok(!engine.SHARED_HOSTING_PARENTS.includes(d), d);
  assert.equal(engine.recognisedBrandOf('evil-whatsapp.com'), null);
  assert.equal(engine.recognisedBrandOf('v.whatsapp.com'), 'whatsapp.com');
});

// ---------------------------------------------------------------- D-FP1 official name without A record
test('D-FP1 incometax.gov.in (apex NOERROR, no A, but NS/SOA) is VERIFIED via DoH existence checks', async () => {
  const a = await recog('incometax.gov.in');
  assert.equal(a.verified, true, `${a.verdict} ${JSON.stringify(a.flags)}`);
  assert.equal(a.riskLevel, 'SAFE');
  assert.ok(a.evidenceForTrust.some(e => /NS|SOA/.test(e)));
});
test('D-FP1 confirmExistence: www.<host> A record counts; NXDOMAIN stays a forgery; nothing proven -> unconfirmed', async () => {
  const base = { whitelist: new Set(['incometax.gov.in']), brands: [], suspiciousTlds: new Set(), shorteners: new Set(), useGemini: false,
    async sslCheck() { return { supported: true, authorized: true, hasValidSsl: true }; },
    async dnsCheck() { return { resolved: false, status: 'NOERROR', ips: [], ttl: null, isFastFlux: false, isNxDomain: false }; } };
  // www.<host> has an A record
  let a = await engine.assessDomain('incometax.gov.in', { ...base, dnsExists: async () => ({ exists: true, nxdomain: false, via: 'A on www' }) });
  assert.equal(a.verified, true);
  // nothing proven
  a = await engine.assessDomain('incometax.gov.in', { ...base, dnsExists: async () => ({ exists: false, nxdomain: false }) });
  assert.equal(a.verified, false); assert.equal(a.verdict, 'OFFICIAL_NAMESPACE_UNCONFIRMED');
  // NXDOMAIN
  a = await engine.assessDomain('incometax.gov.in', { ...base, dnsExists: async () => ({ exists: false, nxdomain: true }) });
  assert.equal(a.hardBlock, true); assert.equal(a.verdict, 'FAKE_OFFICIAL_NAMESPACE');
  // existence helper throwing is fail-closed (unconfirmed, no crash)
  a = await engine.assessDomain('incometax.gov.in', { ...base, dnsExists: async () => { throw new Error('boom'); } });
  assert.equal(a.verified, false);
});
test('D-FP1 confirmExistence over DoH: SOA of a PARENT zone is not proof; apex NS is', async () => {
  const real = global.fetch;
  const mk = (map) => async (url) => {
    const u = new URL(String(url)); const key = u.searchParams.get('name') + '/' + u.searchParams.get('type');
    const j = map[key] || { Status: 0 };
    return { ok: true, status: 200, text: async () => JSON.stringify(j) };
  };
  try {
    global.fetch = mk({ 'foo.gov.in/SOA': { Status: 0, Authority: [{ name: 'gov.in.', type: 6, data: 'x' }] } });
    assert.equal((await engine.confirmExistence('foo.gov.in', {})).exists, false);
    global.fetch = mk({ 'foo.gov.in/NS': { Status: 0, Answer: [{ name: 'foo.gov.in.', type: 2, data: 'ns1.' }] } });
    const r = await engine.confirmExistence('foo.gov.in', {});
    assert.equal(r.exists, true); assert.match(r.via, /NS/);
    global.fetch = mk({ 'foo.gov.in/A': { Status: 3 } });
    assert.equal((await engine.confirmExistence('foo.gov.in', {})).nxdomain, true);
    global.fetch = async () => { throw new Error('offline'); };
    assert.deepEqual(await engine.confirmExistence('foo.gov.in', {}), { exists: false, nxdomain: false });
  } finally { global.fetch = real; }
});

// ---------------------------------------------------------------- D-FP2 popular parent subdomain
test('D-FP2 timesofindia.indiatimes.com (RDAP down, low TTL, popular parent) is LOW, not MODERATE', async () => {
  const a = await recog('timesofindia.indiatimes.com');
  assert.equal(a.riskLevel, 'LOW', `${a.riskScore} ${JSON.stringify(a.flags)}`);
  assert.equal(a.verified, false);
  assert.notEqual(a.verdict, 'ESTABLISHED_THIRD_PARTY_DOMAIN');
  assert.ok(!a.flags.some(f => /age could not|Low DNS TTL/.test(f)));
});
test('D-FP2 parent standing does not excuse lure keywords or impersonation on its subdomains', async () => {
  const a = await recog('sbi-kyc-login.indiatimes.com');
  assert.ok(a.hardBlock || a.riskScore >= 35, `${a.riskLevel}/${a.riskScore}`);
});

// ---------------------------------------------------------------- Gemini: bounded, retry once, fail open
test('askGemini: retries once on 429/5xx and then succeeds; fails open on repeated errors; honours the tiny budget', async () => {
  const real = global.fetch; const realKey = process.env.GEMINI_API_KEY;
  process.env.GEMINI_API_KEY = 'k';
  let calls = 0;
  const reply = { candidates: [{ content: { parts: [{ text: JSON.stringify({ riskScore: 40, verdict: 'SUSPICIOUS', confidence: 0.7, threatVector: 'x', rationale: 'r', signals: [] }) }] } }] };
  try {
    global.fetch = async () => { calls++; return calls === 1 ? { ok: false, status: 429, text: async () => '{}' } : { ok: true, status: 200, text: async () => JSON.stringify(reply) }; };
    let g = await engine.askGemini('t', {}, { timeoutMs: 3000 });
    assert.equal(g.available, true); assert.equal(calls, 2);
    calls = 0;
    global.fetch = async () => { calls++; return { ok: false, status: 503, text: async () => '{}' }; };
    g = await engine.askGemini('t', {}, { timeoutMs: 3000 });
    assert.equal(g.available, false); assert.equal(calls, 2); assert.match(g.reason, /503/);
    calls = 0;
    g = await engine.askGemini('t', {}, { timeoutMs: 100 });
    assert.equal(g.available, false); assert.equal(calls, 0); assert.match(g.reason, /latency budget/);
    calls = 0;
    global.fetch = async () => { calls++; return { ok: false, status: 400, text: async () => '{}' }; };
    g = await engine.askGemini('t', {}, { timeoutMs: 3000 });
    assert.equal(calls, 1, 'no retry on 4xx');
  } finally { global.fetch = real; if (realKey === undefined) delete process.env.GEMINI_API_KEY; else process.env.GEMINI_API_KEY = realKey; }
});

// ---------------------------------------------------------------- AI second opinion (textAi)
const ambiguous = () => {
  const v = an('Your parcel is on hold. Please confirm your delivery slot tomorrow morning to avoid return.');
  return v;
};
const gen = (obj, extra = {}) => async (args) => { gen.last = args; return { available: true, via: 'Vertex AI', model: 'gemini-2.5-flash', text: JSON.stringify(obj), ...extra }; };
test('textAi: only mid-range (30-70) non-injection verdicts are sent; DISABLE_GEMINI respected', () => {
  assert.equal(textAi.eligible({ riskScore: 20, _meta: { category: 'unknown' } }), false);
  assert.equal(textAi.eligible({ riskScore: 85, _meta: { category: 'kyc' } }), false);
  assert.equal(textAi.eligible({ riskScore: 50, _meta: { category: 'kyc' } }), true);
  assert.equal(textAi.eligible({ riskScore: 50, _meta: { category: 'injection' } }), false);
  process.env.DISABLE_GEMINI = '1';
  try { assert.equal(textAi.eligible({ riskScore: 50, _meta: { category: 'kyc' } }), false); } finally { delete process.env.DISABLE_GEMINI; }
});
test('textAi: text is PII-redacted before it is sent', async () => {
  const v = { riskScore: 50, riskLevel: 'MEDIUM', flags: ['x'], _meta: { category: 'kyc', signals: { link: true } } };
  const raw = 'Call 9876543210 or mail ravi@gmail.com, UPI ravi@ybl, Aadhaar 2345 6789 0123, card 4111 1111 1111 1111, OTP is 482913';
  await textAi.secondOpinion(raw, v, { generate: gen({ verdict: 'SUSPICIOUS', confidence: 0.5, reason: 'r' }), levelFor: textEngine.levelFor });
  const sent = gen.last.userText;
  for (const bad of ['9876543210', 'ravi@gmail.com', 'ravi@ybl', '2345 6789 0123', '4111 1111 1111 1111', '482913']) assert.ok(!sent.includes(bad), bad + ' leaked: ' + sent);
});
test('textAi: escalates a scam opinion, labels the model honestly', async () => {
  const v = { ...ambiguous(), riskScore: 45, riskLevel: 'MEDIUM', _meta: { category: 'unknown', signals: { link: false } } };
  const o = await textAi.secondOpinion('x', v, { generate: gen({ verdict: 'SCAM', confidence: 0.9, reason: 'Classic fee trap.' }), levelFor: textEngine.levelFor });
  assert.ok(o.riskScore >= 72); assert.equal(o.riskLevel, 'HIGH');
  assert.equal(o.aiSecondOpinion.status, 'escalated');
  assert.match(o.analysisEngine, /deterministic text engine \+ Gemini \(gemini-2\.5-flash\) via Vertex AI second opinion/);
});
test('textAi: de-escalates ONLY when evidence is purely stylistic', async () => {
  const styl = { riskScore: 48, riskLevel: 'MEDIUM', flags: [], _meta: { category: 'unknown', signals: { link: false, credential: false, payment: false, mobile: false, upi: false, install: false, secrecy: false } } };
  let o = await textAi.secondOpinion('x', styl, { generate: gen({ verdict: 'LIKELY_GENUINE', confidence: 0.95, reason: 'Routine.' }), levelFor: textEngine.levelFor });
  assert.equal(o.aiSecondOpinion.status, 'de-escalated'); assert.ok(o.riskScore <= 25);
  for (const sig of ['link', 'credential', 'payment', 'mobile', 'upi', 'install', 'secrecy', 'receiveTrap', 'familyAsk']) {
    const hard = { ...styl, _meta: { category: 'unknown', signals: { ...styl._meta.signals, [sig]: true } } };
    o = await textAi.secondOpinion('x', hard, { generate: gen({ verdict: 'LIKELY_GENUINE', confidence: 0.99, reason: 'Routine.' }), levelFor: textEngine.levelFor });
    assert.equal(o.riskScore, 48, `must not de-escalate with ${sig}`);
  }
});
test('textAi: fails open (unavailable / throws / malformed / timeout) to the deterministic result', async () => {
  const v = { riskScore: 50, riskLevel: 'MEDIUM', flags: [], _meta: { category: 'unknown', signals: {} } };
  for (const g of [async () => ({ available: false, reason: 'Gemini timeout' }), async () => { throw new Error('boom'), 1; }, async () => ({ available: true, text: 'not json', model: 'm', via: 'v' }), async () => ({ available: true, text: '{"verdict":"WAT"}', model: 'm', via: 'v' })]) {
    const o = await textAi.secondOpinion('x', v, { generate: g, levelFor: textEngine.levelFor });
    assert.equal(o.riskScore, 50); assert.match(o.analysisEngine, /deterministic text engine \(Gemini second opinion/);
  }
});
test('textAi: model reason text cannot inject markup', async () => {
  const v = { riskScore: 50, riskLevel: 'MEDIUM', flags: [], _meta: { category: 'unknown', signals: { link: true } } };
  const o = await textAi.secondOpinion('x', v, { generate: gen({ verdict: 'SCAM', confidence: 0.9, reason: '<img src=x onerror=alert(1)>' }), levelFor: textEngine.levelFor });
  assert.ok(!/[<>]/.test(JSON.stringify(o.aiSecondOpinion.reason)));
});

// ---------------------------------------------------------------- Document AI triage
const HDFC_LETTER = `HDFC Bank Limited
Sanction Letter - Personal Loan
Dear Mr. Sharma, we are pleased to sanction a personal loan of Rs 3,00,000 at 11.5% p.a. for 36 months.
Pre-disbursal conditions: (1) Police verification of address as per bank policy, (2) KYC documents, (3) Customs duty receipts are not applicable.
Processing fee 1% plus GST will be deducted from the disbursed amount, as shown in the Key Fact Statement.
HDFC Bank Limited is regulated by the Reserve Bank of India. For queries visit hdfcbank.com.`;
const FORGED_WARRANT = `CENTRAL BUREAU OF INVESTIGATION - NEW DELHI
SPECIAL CYBER CRIME CELL - ORDER NO: CBI/CYB/2026/8941
SUBJECT: IMMEDIATE FREEZING ORDER & NATIONAL ARREST WARRANT UNDER PMLA ACT SEC 3/4
We have intercepted a suspicious DHL courier in your name containing 140g MDMA and 5 fake passports.
Do NOT disconnect your Skype/WhatsApp video call.
Transfer your total liquid funds of INR 4,85,000 to the RBI FINANCIAL SAFETY VERIFICATION ESCROW ACCOUNT:
UPI ID: rbi.safecustody99@okhdfcbank
Failure to comply within 2 hours will lead to physical arrest.`;
const tri = (t) => docTriage.triage(t);

test('Doc: genuine HDFC sanction letter mentioning police verification / customs duty is GENUINE_LOOKING / LOW', () => {
  const r = tri(HDFC_LETTER);
  assert.equal(r.verdict, 'GENUINE_LOOKING'); assert.equal(r.severity, 'LOW'); assert.ok(r.riskScore < 20);
});
test('Doc: forged digital-arrest warrant is LIKELY_FORGED / CRITICAL', () => {
  const r = tri(FORGED_WARRANT);
  assert.equal(r.verdict, 'LIKELY_FORGED'); assert.equal(r.severity, 'CRITICAL'); assert.ok(r.riskScore >= 90);
});
const GENUINE_DOCS = {
  'KYC form': 'KYC Application Form - Individual. Name, date of birth, address, PAN, Aadhaar (last 4 digits). Attach self-attested proof of address. Police verification may be required for some account types. Submit at your home branch.',
  'salary slip': 'Salary Slip for September 2026. Employee: A. Kumar. Basic 50,000, HRA 20,000, PF deduction 6,000, TDS 4,200. Net pay Rs 59,800 credited to A/c XX1234 on 30-09-2026.',
  'genuine court summons': 'IN THE COURT OF THE CIVIL JUDGE, PUNE. Summons in Civil Suit No. 123/2026. You are hereby summoned to appear in person on 12-11-2026 at 11 am. In default, the suit will be heard ex parte. Issued under the seal of the Court.',
  'bank statement notice': 'Customs duty on your imported equipment loan has been paid. Please visit the branch with passport for verification. RBI regulated. Supreme Court judgment on interest is attached for reference.',
  'RBI circular': 'Reserve Bank of India circular on KYC: banks must verify identity. Money laundering prevention rules apply. Customers are advised never to share OTP with anyone.',
  'EMI reminder': 'Your loan EMI of Rs 12,450 is due on 05-Nov-2026. Maintain sufficient balance. Late payment may attract charges as per the loan agreement.'
};
for (const [k, t] of Object.entries(GENUINE_DOCS)) test(`Doc: genuine ${k} is not flagged`, () => {
  const r = tri(t); assert.equal(r.verdict, 'GENUINE_LOOKING', JSON.stringify(r)); assert.equal(r.severity, 'LOW');
});
test('Doc: genuine Section 138 style legal notice demanding payment is NEEDS_REVIEW (never LIKELY_FORGED)', () => {
  const r = tri('Legal notice under Section 138 of the Negotiable Instruments Act. Your cheque no 004512 for Rs 20,000 was dishonoured. Pay the amount within 15 days failing which legal action and criminal proceedings will be initiated.');
  assert.equal(r.verdict, 'NEEDS_REVIEW'); assert.equal(r.severity, 'MEDIUM');
});
const FORGED_DOCS = [
  'This is CBI officer Sharma. A parcel with narcotics was found in your name. You are under digital arrest. Do not disconnect the call. Deposit Rs 50,000 in the safe account to clear your name.',
  'Supreme Court of India. Arrest warrant issued against you for money laundering. Pay Rs 1,00,000 fine via UPI ID: court.fine@ybl within 2 hours, keep this strictly confidential.',
  'ED notice: your account is frozen under PMLA. Transfer all funds to the RBI verification account today. Do not tell anyone, stay on the video call.',
  'Mumbai Police Cyber Cell: digital arrest in progress. Pay the settlement amount of Rs 75,000 to avoid arrest.'
];
for (const t of FORGED_DOCS) test(`Doc: forged agency notice is LIKELY_FORGED: ${t.slice(0, 45)}`, () => {
  const r = tri(t); assert.equal(r.verdict, 'LIKELY_FORGED', JSON.stringify(r.signals)); assert.ok(['CRITICAL', 'HIGH'].includes(r.severity));
});
test('Doc: predatory loan wording is LIKELY_FORGED / HIGH, genuine sanction is not', () => {
  const r = tri('Instant loan approved without documents! Pay Rs 2,999 processing fee first before disbursal. Allow access to your contacts and gallery. 7-day loan tenure.');
  assert.equal(r.verdict, 'LIKELY_FORGED'); assert.equal(r.severity, 'HIGH');
  assert.equal(tri('Your loan application is sanctioned. Processing fee 1% plus GST will be deducted from the disbursed amount.').verdict, 'GENUINE_LOOKING');
});
test('Doc: severity always follows the verdict', () => {
  for (const t of [HDFC_LETTER, FORGED_WARRANT, ...Object.values(GENUINE_DOCS), ...FORGED_DOCS]) {
    const r = tri(t); const ok = { GENUINE_LOOKING: ['LOW'], NEEDS_REVIEW: ['MEDIUM'], LIKELY_FORGED: ['HIGH', 'CRITICAL'] }[r.verdict];
    assert.ok(ok.includes(r.severity), `${r.verdict}/${r.severity}`);
  }
});
test('Doc: substring words inside other words never count (word boundaries)', () => {
  assert.equal(tri('The ED patch for the Cbilling module; escrowed items are fine; customsized shirts; policeman statue; arrested development (TV).').verdict, 'GENUINE_LOOKING');
});
test('Doc: image/PDF without a processor is honestly NOT analysed (no score, no forensics claims)', () => {
  const b = docTriage.buildResponse({ text: '[OCR unavailable: x]', filename: 'letter.png', hasFile: true, isText: false, ocr: { available: false, reason: 'no processor' }, ocrNote: 'n' });
  assert.equal(b.analysis.analysed, false); assert.equal(b.analysis.riskScore, null); assert.equal(b.analysis.authenticityScore, null);
  assert.equal(b.analysis.verdict, 'UNVERIFIED_NO_OCR'); assert.equal(b.analysis.severity, 'NOT_ANALYSED');
  assert.deepEqual(b.analysis.analysisPerformed, []); assert.equal(b.mode, 'FILE_UPLOAD_NO_OCR');
});
test('Doc: analysed response lists what ran and what did NOT run', () => {
  const b = docTriage.buildResponse({ text: HDFC_LETTER, filename: 'x', hasFile: false, isText: false, ocr: { available: false }, ocrNote: 'n' });
  assert.equal(b.analysis.analysed, true); assert.ok(b.analysis.notPerformed.some(x => /forensics/i.test(x)));
  assert.ok(b.analysis.authenticityScore <= 70, 'wording-only check never claims high authenticity');
  assert.equal(b.analysis.severity, 'LOW');
});

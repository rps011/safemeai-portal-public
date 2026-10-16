'use strict';
/**
 * Post-evaluation regression tests (second accuracy pass). Every case here is a NEW paraphrase written after the independent
 * held-out evaluation (docs/EVALUATION.md); none is copied from tests/eval. They protect the GENERAL failure classes:
 *   A  trigger-word-free loss-of-funds scams (family emergency, romance / gift, marketplace advance, fee-for-job, refund phishing,
 *      mixed-script / transliterated Hindi)           B  genuine look-alikes (OTP to a driver, official notices, no-fee loan sanction)
 *   C  domain false alarms (NIC chain, org-validated corporates, capped Gemini)   D  forged-notice triage and graded benign scores.
 * Fully offline.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorld, runMessage } = require('./helpers/benchWorld');
const textEngine = require('../lib/textEngine');
const textAi = require('../lib/textAi');
const docTriage = require('../lib/docTriage');
const engine = require('../lib/domainEngine');
const corpus = require('./fixtures/benchmark2.json').cases;

const world = createWorld();
const results = [];
test.before(async () => {
  world.install();
  for (const c of corpus) results.push(c.kind === 'message' ? await runMessage(world, c.input) : docTriage.triage(c.input));
});
test.after(() => world.restore());

test('benchmark2: corpus is present and balanced', () => {
  assert.ok(corpus.length >= 80);
  for (const k of ['message', 'document']) {
    assert.ok(corpus.some(c => c.kind === k && c.malicious), k + ' scams');
    assert.ok(corpus.some(c => c.kind === k && !c.malicious), k + ' genuine');
  }
});

for (const [i, c] of corpus.entries()) {
  test(`benchmark2 #${String(i).padStart(2, '0')} ${c.kind} ${c.malicious ? 'SCAM ' : 'LEGIT'} ${JSON.stringify(c.input.slice(0, 55))}`, () => {
    const r = results[i];
    if (c.kind === 'message') {
      if (c.malicious) assert.ok(r.score >= 60, `scam under-scored: ${r.score} ${r.verdict}`);
      else assert.ok(r.score < 40, `genuine over-scored: ${r.score} ${r.verdict} ${JSON.stringify(r.flags)}`);
    } else if (c.malicious) {
      assert.equal(r.verdict, 'LIKELY_FORGED', JSON.stringify(r.signals));
      assert.ok(r.riskScore >= 85);
    } else {
      assert.equal(r.verdict, 'GENUINE_LOOKING', JSON.stringify(r.signals));
      assert.ok(r.riskScore <= 30);
    }
  });
}

test('benchmark2: aggregate gates (no scam message below HIGH, at most 1 genuine message at MEDIUM+, no forged / genuine document confusion)', () => {
  const msgs = corpus.map((c, i) => ({ c, r: results[i] })).filter(x => x.c.kind === 'message');
  assert.equal(msgs.filter(x => x.c.malicious && x.r.score < 60).length, 0);
  assert.ok(msgs.filter(x => !x.c.malicious && x.r.score >= 40).length <= 1);
  const docs = corpus.map((c, i) => ({ c, r: results[i] })).filter(x => x.c.kind === 'document');
  assert.equal(docs.filter(x => x.c.malicious && x.r.verdict !== 'LIKELY_FORGED').length, 0);
  assert.equal(docs.filter(x => !x.c.malicious && x.r.verdict !== 'GENUINE_LOOKING').length, 0);
});

// ------------------------------------------------------------------------------------------------ A: intent signals
const an = (t, o) => textEngine.analyze(t, o);

test('A: lookalike Cyrillic / Greek letters and Devanagari digits are folded for rule matching', () => {
  assert.equal(textEngine.normalizeText('Sһаre ОТР now').t, 'share otp now');
  assert.match(textEngine.normalizeText('भेज दो ₹५०००').t, /5000/);
  // real Devanagari / Cyrillic text without Latin letters is NOT rewritten
  assert.equal(textEngine.normalizeText('नमस्ते दोस्त').t, 'नमस्ते दोस्त');
  assert.ok(an('Sbi KYC pending. А pna ОТР batao jaldi warna account band ho jayega.').riskScore >= 80);
});

test('A: transliterated Hindi payment verbs count as a money ask only beside an amount', () => {
  const sig = (t) => Boolean(an(t)._meta.signals.moneyAsk);
  for (const t of ['40,000 is number par GPay kar do', 'abhi 5000 rupaye bhej do', '₹12000 jama karo', 'Rs 7,500 UPI se bhejiye', 'paise daal do jaldi']) assert.equal(sig(t), true, t);
  for (const t of ['call karo 9876543210', 'kal milte hain, yaad rakhna', 'Order 4521 has shipped', 'Your balance is Rs 2,310']) assert.equal(sig(t), false, t);
});

test('A: "new number" + trouble/secrecy + money ask is a family-emergency scam even with no relative named', () => {
  const v = an('This is my new number, old phone broke. I am stuck at the station and need Rs 9,000 right now, GPay it. Do not call anyone at home.');
  assert.ok(v.riskScore >= 72, `${v.riskScore} ${v.scamType}`);
  assert.equal(an('Hi, this is my new number, please save it. See you at dinner.').riskScore < 40, true);
});

test('A: fee-for-job needs BOTH a job context and an affirmed fee; "no fee" assurances do not fire', () => {
  const scam = an('Your selection for the support executive job is confirmed. Pay Rs 2,500 uniform and registration charges on UPI to get the joining letter.');
  assert.ok(scam.riskScore >= 80 && /Advance-Fee/.test(scam.scamType), `${scam.riskScore} ${scam.scamType}`);
  const ok = an('Your interview is on Monday 11 AM. We never charge any registration fee. Bring your ID proof.');
  assert.ok(ok.riskScore < 40, `${ok.riskScore} ${ok.scamType}`);
});

test('A: marketplace advance / token only when it is the BUYER who asks and money is requested', () => {
  assert.ok(an('Interested in your cycle on Facebook Marketplace. I am in the Navy, send Rs 1,000 token and packing charge, my transporter will collect it.').riskScore >= 80);
  assert.ok(an('Is your cycle on Facebook Marketplace still available? I can pick it up on Saturday and pay in cash.').riskScore < 40);
});

test('A: refund + (card/bank details | click-to-verify) is phishing; a plain refund notice is not', () => {
  assert.ok(an('Your GST refund of Rs 9,100 is approved. Enter your debit card number and bank account details to receive it.').riskScore >= 80);
  assert.ok(an('Refund of Rs 750 has been credited to your bank account ending 4411. Thank you.').riskScore < 40);
});

test('A: stripNegated Romanised warnings ("OTP share na kare") are not read as an OTP request', () => {
  const v = an('Aapka bijli ka bill jama ho gaya hai. Kripya kisi ko OTP ya PIN share na kare.');
  assert.ok(v.riskScore < 40, `${v.riskScore} ${v.scamType}`);
  assert.ok(an('Aapka OTP bhejo na, refund karna hai.').riskScore >= 80);
});

test('A: "send ... on WhatsApp" without a threat is no longer read as sextortion', () => {
  assert.ok(an('Can you send me the assignment pdf on WhatsApp when you are free?').riskScore < 40);
  assert.ok(an('Send Rs 20000 or else I will upload your video on Instagram and send it to all your friends').riskScore >= 80);
});

// ------------------------------------------------------------------------------------------------ B: genuine look-alikes
test('B: OTP handed to a driver / agent in person is routine, OTP asked on a call or link is not', () => {
  assert.ok(an('Your cab is 2 mins away. Share OTP 3321 with the driver to start the ride.').riskScore < 40);
  assert.ok(an('Technician will visit today. Give the OTP 8841 to the engineer at the time of service.').riskScore < 40);
  assert.ok(an('Our agent will call you. Share the OTP with the driver on call to verify your refund.').riskScore >= 80);
  assert.ok(an('Share your OTP with our executive on WhatsApp to cancel the ride.').riskScore >= 80);
});

test('B: a notice whose only link is a verified official domain, with no OTP / number / UPI ask, is not a scam', async () => {
  const msg = 'Traffic challan of Rs 500 issued for vehicle KA01AB1234. Pay at echallan.parivahan.gov.in within 60 days or contest in court.';
  const r = await runMessage(world, msg);
  assert.ok(r.score < 40, `${r.score} ${r.verdict}`);
  // the SAME wording with a callback number, a UPI id or an unverified look-alike link keeps its score
  assert.ok((await runMessage(world, msg + ' Call 9812345678 to settle.')).score >= 60);
  assert.ok((await runMessage(world, 'Traffic challan of Rs 500 issued. Pay at echallan-parivahan-pay.xyz within 24 hours.')).score >= 60);
});

test('B: loan sanction with "Congratulations" but no fee, link or number (branch only) stays low; a fee ask does not', () => {
  assert.ok(an('Congratulations! Your car loan of Rs 6,00,000 is sanctioned. Visit your branch with documents. No charges are taken for sanction. Helpline 1800 103 1906.').riskScore < 40);
  assert.ok(an('Congratulations! Your car loan of Rs 6,00,000 is sanctioned. Pay Rs 4,000 processing fee on UPI 9812345678@ybl to release it today.').riskScore >= 80);
});

test('B: standard "SMS BLOCK <service> to <shortcode>" bank instruction is neither a threat nor a callback number', () => {
  const v = an('SBI: Rs 640 debited from A/c XX7788 on 04-Oct-26 UPI/zomato. Avl bal Rs 9,120. Not you? Call 1800 1234 or SMS BLOCK UPI to 9223966666.');
  assert.ok(v.riskScore < 40, `${v.riskScore} ${v.scamType}`);
  assert.equal(v._meta.signals.genuineTemplate !== false, true);
});

test('B: "apk" inside ordinary words (aapka) is not an app-install lure; a real .apk still is', () => {
  assert.ok(an('Aapka order kal subah tak pahunch jayega.').riskScore < 40);
  assert.ok(an('Install this apk file to claim your reward: http://claim-reward.xyz/app.apk').riskScore >= 80);
});

// ------------------------------------------------------------------------------------------------ textAi window
const gen = (obj) => async () => ({ available: true, via: 'Vertex AI', model: 'gemini-2.5-flash', text: JSON.stringify(obj) });
const lowWithAsk = () => ({ riskScore: 22, riskLevel: 'LOW', flags: ['x'], _meta: { category: 'unknown', signals: { moneyAsk: true, ask: true, link: false, credential: false, payment: false, mobile: false, upi: false, install: false, secrecy: false } } });

test('textAi: LOW score + a concrete ask is now sent for a second opinion and may be escalated', async () => {
  assert.equal(textAi.eligible(lowWithAsk()), true);
  const o = await textAi.secondOpinion('send 5000 to my friend', lowWithAsk(), { generate: gen({ verdict: 'SCAM', confidence: 0.9, reason: 'advance fee' }), levelFor: textEngine.levelFor });
  assert.equal(o.riskScore, 72); assert.equal(o.aiSecondOpinion.status, 'escalated');
});

test('textAi: LOW score with NO ask is never sent, and a SCAM opinion with no concrete signal never escalates', async () => {
  const v = lowWithAsk(); v._meta.signals = { ...v._meta.signals, ask: false, moneyAsk: false };
  assert.equal(textAi.eligible(v), false);
  const mid = { riskScore: 45, riskLevel: 'MEDIUM', flags: [], _meta: { category: 'unknown', signals: { link: false, credential: false, payment: false, mobile: false, upi: false, install: false, secrecy: false } } };
  const o = await textAi.secondOpinion('hello', mid, { generate: gen({ verdict: 'SCAM', confidence: 0.99, reason: 'x' }), levelFor: textEngine.levelFor });
  assert.equal(o.riskScore, 45); assert.match(o.aiSecondOpinion.status, /^noted/);
  assert.equal(textAi.eligible({ riskScore: 8, _meta: { category: 'unknown', signals: { ask: true } } }), false);
});

test('textAi: a standard bank transaction-alert template is never escalated by a "scam" opinion', async () => {
  const v = an('HDFC Bank: Rs 1,250.00 debited from A/c XX4821 for UPI/Swiggy. Avl bal Rs 24,310.55. Not you? Call 1800 202 6161 or SMS BLOCK UPI to 7308080808.');
  const before = v.riskScore;
  const o = await textAi.secondOpinion('x', { ...v, riskScore: Math.max(before, 50) }, { generate: gen({ verdict: 'SCAM', confidence: 0.95, reason: 'block threat' }), levelFor: textEngine.levelFor });
  assert.ok(o.riskScore < 60, `${o.riskScore} ${o.aiSecondOpinion && o.aiSecondOpinion.status}`);
});

// ------------------------------------------------------------------------------------------------ C: domains
const dnsOk = (ttl = 300) => async () => ({ resolved: true, status: 'NOERROR', ips: ['93.184.216.34'], ttl, isFastFlux: ttl < 60, isNxDomain: false });
const ovCert = (org, extra = {}) => async () => ({ supported: true, hasValidSsl: true, authorized: true, isExpired: false, isEV_OV: true, subjectOrg: org, issuer: 'DigiCert', ageDays: 200, isNewlyIssued: false, ...extra });
async function assess(host, o = {}) {
  const realFetch = global.fetch;
  global.fetch = async (url, ...rest) => {   // RDAP unavailable, everything else per the offline world
    if (String(url).startsWith('https://rdap.org/')) return { ok: false, status: 503, text: async () => '{}' };
    return realFetch(url, ...rest);
  };
  try {
    engine._clearCaches();
    return await engine.assessDomain(host, { ...world.deps, ...o, useGemini: Boolean(o.useGemini) });
  } finally { global.fetch = realFetch; }
}

test('C1: a .gov.in site with an incomplete TLS chain stays verified (caution flag only) when DNS confirms it', async () => {
  const ssl = (authError, extra = {}) => async () => ({ supported: true, authorized: false, authError, isExpired: false, isEV_OV: false, ...extra });
  const a = await assess('scheme-portal.gov.in', { dnsCheck: dnsOk(), sslCheck: ssl('UNABLE_TO_VERIFY_LEAF_SIGNATURE') });
  assert.equal(a.verified, true); assert.ok(a.riskScore <= 3); assert.ok(a.flags.some(f => /incomplete TLS certificate chain/.test(f)));
  // expired certificates and hostname mismatches are still bad
  assert.equal((await assess('scheme-portal.gov.in', { dnsCheck: dnsOk(), sslCheck: ssl('CERT_HAS_EXPIRED', { isExpired: true }) })).verified, false);
  assert.equal((await assess('scheme-portal.gov.in', { dnsCheck: dnsOk(), sslCheck: ssl('ERR_TLS_CERT_ALTNAME_INVALID') })).verified, false);
  // DNS must confirm existence; a non-existent .gov.in name stays a forgery
  const nx = await assess('scheme-portal.gov.in', { dnsCheck: async () => ({ resolved: false, status: 'NXDOMAIN', ips: [], ttl: null, isFastFlux: false, isNxDomain: true }), sslCheck: ssl('UNABLE_TO_VERIFY_LEAF_SIGNATURE') });
  assert.equal(nx.verified, false); assert.ok(nx.riskScore >= 80);
});

test('C2: an OV certificate whose organisation matches the domain removes the missing-RDAP / low-TTL penalties', async () => {
  const a = await assess('careers.zenithsoft.com', { dnsCheck: dnsOk(20), sslCheck: ovCert('Zenith Software Limited') });
  assert.equal(a.riskLevel, 'LOW', JSON.stringify(a.flags)); assert.equal(a.orgValidatedEstablished, true);
  assert.ok(!a.flags.some(f => /age could not be verified|Low DNS TTL/.test(f)));
  const b = await assess('mutualfundreg.com', { dnsCheck: dnsOk(), sslCheck: ovCert('Mutual Fund Registrars India Private Limited') });
  assert.equal(b.orgValidatedEstablished, true);
});

test('C2: positive evidence must really match - wrong org, hyphenated lure, lure keywords, new cert or young domain keep the penalties', async () => {
  const wrongOrg = await assess('zenithsoft.com', { dnsCheck: dnsOk(20), sslCheck: ovCert('Acme Traders') });
  assert.equal(wrongOrg.orgValidatedEstablished, false);
  assert.ok(wrongOrg.flags.some(f => /age could not be verified/.test(f)));
  assert.equal((await assess('zenithsoft-verify-kyc.com', { dnsCheck: dnsOk(), sslCheck: ovCert('Zenith Software Limited') })).orgValidatedEstablished, false);
  assert.equal((await assess('zenithsoft.com', { dnsCheck: dnsOk(), sslCheck: ovCert('Zenith Software Limited', { isNewlyIssued: true }) })).orgValidatedEstablished, false);
  assert.equal((await assess('zenithsoft.com', { dnsCheck: dnsOk(), sslCheck: ovCert('Zenith Software Limited', { authorized: false }) })).orgValidatedEstablished, false);
  assert.equal((await assess('zenithsoft.xyz', { dnsCheck: dnsOk(), sslCheck: ovCert('Zenith Software Limited') })).orgValidatedEstablished, false);
});

test('C2: org-validated established links are treated as trusted by the message path (no blanket HIGH for an unverified link)', async () => {
  // exercise the same trusted/risky split server.js and the bench world use
  const a = await assess('careers.zenithsoft.com', { dnsCheck: dnsOk(20), sslCheck: ovCert('Zenith Software Limited') });
  assert.equal(Boolean(a.verified || a.recognisedBrand || a.orgValidatedEstablished), true);
});

test('C3: Gemini cannot push an org-validated, matching, resolving site to HIGH (cap MEDIUM); it still can for others', async () => {
  const realFetch = global.fetch; const realKey = process.env.GEMINI_API_KEY;
  process.env.GEMINI_API_KEY = 'test-key';
  const reply = { riskScore: 98, verdict: 'MALICIOUS', confidence: 0.9, threatVector: 'x', rationale: 'impersonation of a legitimate bank', signals: [] };
  const withGemini = async (host, org) => {
    engine._clearCaches();
    global.fetch = async (url, init) => {
      const u = String(url);
      if (u.startsWith('https://rdap.org/')) return { ok: false, status: 503, text: async () => '{}' };
      if (u.includes('generativelanguage.googleapis.com')) return { ok: true, status: 200, text: async () => JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(reply) }] } }] }) };
      return realFetch(url, init);
    };
    return engine.assessDomain(host, { ...world.deps, dnsCheck: dnsOk(), sslCheck: ovCert(org), useGemini: true });
  };
  try {
    const bank = await withGemini('www.nagarcoopbank.com', 'Nagar Co-operative Bank Limited');
    assert.equal(bank.gemini.available, true, 'Gemini was consulted');
    assert.ok(bank.riskScore <= 55 && bank.riskLevel !== 'HIGH' && bank.riskLevel !== 'CRITICAL', `${bank.riskScore} ${bank.riskLevel}`);
    // control: an org that does NOT match the domain is not capped
    const other = await withGemini('www.nagarcoopbank.com', 'Acme Traders');
    assert.equal(other.gemini.available, true);
    assert.ok(other.riskScore > bank.riskScore, `${other.riskScore} > ${bank.riskScore}`);
  } finally { global.fetch = realFetch; if (realKey === undefined) delete process.env.GEMINI_API_KEY; else process.env.GEMINI_API_KEY = realKey; }
});

test('C: allow-list gained cooperative / small-finance / regional banks and large corporates, each with owner + category', () => {
  const { entries } = require('../data/allowlist.json');
  const byDomain = new Map(entries.map(e => [e.domain, e]));
  for (const d of ['saraswatbank.com', 'abhyudayabank.co.in', 'svcbank.com', 'bharatbank.com', 'nkgsb.in', 'southindianbank.com', 'iob.in', 'infosys.com', 'tcs.com', 'wipro.com', 'camsonline.com', 'ril.com']) {
    const e = byDomain.get(d); assert.ok(e, d); assert.ok(e.owner && e.category, d);
  }
});

// ------------------------------------------------------------------------------------------------ D: documents
test('D: agency + fee/penalty demand + secrecy / OTP / officer account is LIKELY_FORGED even with no "arrest" word', () => {
  const r = docTriage.triage('RESERVE BANK OF INDIA - NOTICE. A refund of Rs 9,00,000 is pending in your name. Pay Rs 6,500 as handling charges to the verification officer to release it. Do not share this with your branch.');
  assert.equal(r.verdict, 'LIKELY_FORGED'); assert.equal(r.severity, 'CRITICAL');
});

test('D: new authority names (RBI, Income-tax, SEBI, Finance Ministry, FIU) are recognised as issuers', () => {
  for (const [h, name] of [['SEBI ORDER', 'sebi'], ['FINANCIAL INTELLIGENCE UNIT NOTICE', 'fiu'], ['MINISTRY OF FINANCE NOTICE', 'finance'], ['INCOME-TAX DEPARTMENT NOTICE', 'it']]) {
    assert.equal(docTriage.triage(h + '. Your account is frozen. Transfer Rs 50,000 as clearance charges to the officer account within 4 hours. Strictly confidential.').verdict, 'LIKELY_FORGED', name);
  }
});

test('D: a demand without authority, threat or secrecy stays NEEDS_REVIEW at most, and genuine statutory notices are not flagged', () => {
  const r = docTriage.triage('Your gym membership fee is overdue. Pay Rs 1,500 at the front desk by the 10th.');
  assert.notEqual(r.verdict, 'LIKELY_FORGED');
  assert.equal(docTriage.triage('Notice under Section 154 of the Income-tax Act: rectification of the intimation dated 04-Aug-2026. You may file objections on the e-filing portal within 30 days. Ref No. CPC/2526/A1/998877.').verdict, 'GENUINE_LOOKING');
});

test('D: benign scores are graded by evidence (reference numbers, citations, official domain) instead of one flat value', () => {
  const rich = docTriage.triage('Ref No. SBI/RET/2026/4412 dated 10-Oct-2026. Statement of account under section 45 of the Banking Regulation Act. Contact your branch or visit sbi.co.in. Grievance: Nodal Officer. Sd/- Branch Manager.');
  const bare = docTriage.triage('hello please see attached');
  const urgent = docTriage.triage('Please pay Rs 500 immediately. Contact us on WhatsApp.');
  assert.equal(rich.verdict, 'GENUINE_LOOKING'); assert.ok(rich.riskScore < bare.riskScore, `${rich.riskScore} < ${bare.riskScore}`);
  assert.ok(urgent.riskScore > rich.riskScore);
  assert.ok(rich.riskScore >= 4 && urgent.riskScore <= 30);
  assert.ok(rich.signals.evidence.length >= 3);
});

test('D: predatory-loan wording "deducted upfront", "share defaulter details with contacts" and per-day charges is recognised', () => {
  const r = docTriage.triage('LOAN AGREEMENT. Rs 5,000 for 7 days. Fees of Rs 1,500 are deducted upfront from the loan. The lender may read your contacts and photos and circulate your details to your contacts if you default. Late fee 1% per day.');
  assert.equal(r.verdict, 'LIKELY_FORGED'); assert.equal(r.subtype, 'PREDATORY_LENDER');
  assert.equal(docTriage.triage('Home loan sanction: processing fee 0.5% plus GST will be deducted at the time of disbursal as stated in the Key Fact Statement.').verdict, 'GENUINE_LOOKING');
});

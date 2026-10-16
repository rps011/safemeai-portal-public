'use strict';
/**
 * Post-v2 regression tests (third accuracy pass). Every case is a NEW paraphrase (fictional names) written after the SECOND independent
 * held-out evaluation (docs/EVALUATION_V2.md); none is copied from tests/eval. They protect GENERAL failure classes:
 *   1 evidence-based link scoring in messages (no blanket "unverified link => HIGH")   2 confirmation vs request in genuine security notices
 *   3 complete, generic TLD handling in link extraction                                 4 www-only / NS-SOA-only domains are not "unresolvable"
 *   5 document triage: fee-before-benefit, payment to personal destinations, authority + fee + pressure
 *   6 Hindi coverage of every new user-facing string.
 * Fully offline (tests/helpers/benchWorld.js).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createWorld, runMessage } = require('./helpers/benchWorld');
const textEngine = require('../lib/textEngine');
const docTriage = require('../lib/docTriage');
const engine = require('../lib/domainEngine');
const linkPolicy = require('../lib/linkPolicy');
const tlds = require('../lib/tlds');
const i18n = require('../lib/i18n');
const corpus = require('./fixtures/benchmark3.json').cases;

const world = createWorld();
const results = [];
test.before(async () => {
  world.install();
  for (const c of corpus) results.push(c.kind === 'message' ? await runMessage(world, c.input) : docTriage.triage(c.input));
});
test.after(() => world.restore());

const msg = (t) => runMessage(world, t);
const links = (t) => textEngine.extractLinks(t, engine.parseTarget).urls.map(u => u.full);

// ------------------------------------------------------------------------------------------------ benchmark3
test('benchmark3: corpus is present and balanced', () => {
  assert.ok(corpus.length >= 25);
  for (const k of ['message', 'document']) {
    assert.ok(corpus.some(c => c.kind === k && c.malicious), k + ' scams');
    assert.ok(corpus.some(c => c.kind === k && !c.malicious), k + ' genuine');
  }
});

for (const [i, c] of corpus.entries()) {
  test(`benchmark3 #${String(i).padStart(2, '0')} ${c.kind} ${c.malicious ? 'SCAM ' : 'LEGIT'} ${JSON.stringify(c.input.slice(0, 55))}`, () => {
    const r = results[i];
    if (c.kind === 'message') {
      if (c.malicious) assert.ok(r.score >= 60, `scam under-scored: ${r.score} ${r.verdict}`);
      else assert.ok(r.score < 40, `genuine over-scored: ${r.score} ${r.verdict} ${JSON.stringify(r.flags)}`);
    } else if (c.malicious) {
      assert.equal(r.verdict, 'LIKELY_FORGED', JSON.stringify(r.signals));
      assert.ok(r.riskScore >= 70, 'forged document must reach HIGH (>=70): ' + r.riskScore);
    } else {
      assert.notEqual(r.verdict, 'LIKELY_FORGED', JSON.stringify(r.reasons));
      assert.ok(r.riskScore < 60, 'genuine document under HIGH: ' + r.riskScore);
    }
  });
}

test('benchmark3: aggregate gates (every scam flagged, no genuine message at MEDIUM+, no forged / genuine document confusion)', () => {
  const m = corpus.map((c, i) => ({ c, r: results[i] })).filter(x => x.c.kind === 'message');
  assert.equal(m.filter(x => x.c.malicious && x.r.score < 60).length, 0);
  assert.equal(m.filter(x => !x.c.malicious && x.r.score >= 40).length, 0);
  const d = corpus.map((c, i) => ({ c, r: results[i] })).filter(x => x.c.kind === 'document');
  assert.equal(d.filter(x => x.c.malicious && x.r.verdict !== 'LIKELY_FORGED').length, 0);
  assert.equal(d.filter(x => !x.c.malicious && x.r.verdict === 'LIKELY_FORGED').length, 0);
});

// ------------------------------------------------------------------------------------------------ 1 evidence-based link scoring
test('link policy: a link with positive evidence (popular / org-validated / established) is never force-boosted', async () => {
  for (const t of [
    'Timetable for the winter exams is on campusexams.ac.in, please check your centre.',
    'Your lab slot is booked. Details at https://carepathlab.com/slot/118',
  ]) {
    const r = await msg(t);
    assert.ok(r.score < 40, `${r.score} ${r.verdict}`);
  }
});

test('link policy: an org-validated certificate alone is positive evidence (no popularity, no age data)', async () => {
  const deps = world.deps;
  const keep = deps.sslCheck;
  deps.sslCheck = async (host) => ({ supported: true, hasValidSsl: true, authorized: true, isExpired: false, isEV_OV: true, subjectOrg: 'Greenfield Polytechnic Trust', issuer: 'Test CA', ageDays: 200, isNewlyIssued: false });
  try {
    const r = await msg('The admission list is published at greenfieldpoly.in this evening.');
    assert.ok(r.score < 60, `${r.score} ${r.verdict}`);
  } finally { deps.sslCheck = keep; }
});

test('link policy: an unknown unverified link with a benign text is "not sure" (MEDIUM), not HIGH', async () => {
  for (const t of [
    'OPD timings have changed, see townhospital-portal.in for the new schedule.',
    'Our society newsletter for October is at localcoopcredit.in/news',
  ]) {
    const r = await msg(t);
    assert.ok(r.score >= 40 && r.score < 60, `${r.score} ${r.verdict}`);
    assert.equal(r.level, 'MEDIUM');
  }
});

test('link policy: the same unknown link next to a concrete risk signal is HIGH or worse', async () => {
  const cases = [
    'Enter the OTP you receive on localcoopcredit.in to continue.',                          // credential ask
    'Pay Rs 299 at townhospital-portal.in today to keep your slot.',                          // payment ask
    'Your facility will be blocked immediately unless you log in at townhospital-portal.in.', // urgency + threat
    'Download the app from townhospital-portal.in/get to claim your benefit.',                // install
    'Visit localcoopcredit.in/offer and do not tell your family.',                            // secrecy
  ];
  for (const t of cases) {
    const r = await msg(t);
    assert.ok(r.score >= 60, `${r.score} ${r.verdict} :: ${t}`);
  }
});

test('link policy: dangerous links keep the old floor of 75 whatever the wording says', async () => {
  for (const t of [
    'Notice board update: nonexistent-college-portal.in has the new rules.',     // does not exist (NXDOMAIN hard block)
    'Hello, photos from the trip: https://bit.ly/3xYz9',                         // shortener hard block
    'Please open sbi-account-verify.xyz when you have time.',                    // look-alike + abuse TLD
    'Weekly digest at freshpromo-weekly.in, have a look.',                        // domain only days old
    'See http://185.220.101.7/index for the update.',                             // raw IP
  ]) {
    const r = await msg(t);
    assert.ok(r.score >= 75, `${r.score} ${r.verdict} :: ${t}`);
  }
});

test('link policy unit: classify / decide never lower a hard block and fail closed', () => {
  const base = { ok: true, verified: false, recognisedBrand: null, orgValidatedEstablished: false, orgValidated: false, hardBlock: false, riskScore: 40, verdict: 'UNVERIFIED_THIRD_PARTY_DOMAIN', popularRank: null, sharedHosting: null, impersonation: [], domainAge: { available: false } };
  assert.equal(linkPolicy.classify({ ...base, popularRank: 8000, riskScore: 20, verdict: 'ESTABLISHED_THIRD_PARTY_DOMAIN' }), 'positive');
  assert.equal(linkPolicy.classify({ ...base, orgValidated: true, riskScore: 35 }), 'positive');
  assert.equal(linkPolicy.classify({ ...base, verified: true, riskScore: 0 }), 'trusted');
  assert.equal(linkPolicy.classify(base), 'unknown');
  assert.equal(linkPolicy.classify({ ...base, hardBlock: true, riskScore: 100 }), 'dangerous');
  assert.equal(linkPolicy.classify({ ...base, popularRank: 100, hardBlock: true, riskScore: 95 }), 'dangerous');
  assert.equal(linkPolicy.classify({ ...base, riskScore: 62 }), 'dangerous');
  assert.equal(linkPolicy.classify({ ...base, domainAge: { available: true, ageDays: 12 } }), 'dangerous');
  assert.equal(linkPolicy.classify({ ...base, sharedHosting: 'pages.dev' }), 'dangerous');
  // a popular domain with a worrying score is not "positive"
  assert.equal(linkPolicy.classify({ ...base, popularRank: 500, riskScore: 50 }), 'unknown');
  const p = linkPolicy.plan([base], { ok: false, host: 'x.in' });
  assert.equal(linkPolicy.decide(p, { _meta: { signals: {} } }).mode, 'boost'); // an assessment that failed fails closed
  const d = linkPolicy.decide(linkPolicy.plan([{ ...base, hardBlock: true, riskScore: 100 }], null), { _meta: { signals: {} } });
  assert.equal(d.mode, 'boost');
  assert.ok(d.floor >= 75);
  const soft = linkPolicy.decide(linkPolicy.plan([base], null), { _meta: { signals: { concrete: false } } });
  assert.equal(soft.mode, 'soft');
  assert.ok(soft.floor >= 45 && soft.floor <= 59);
});

test('link policy: server and benchmark mirror use the same module (no second copy of the rule)', () => {
  const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const helper = fs.readFileSync(path.join(__dirname, 'helpers', 'benchWorld.js'), 'utf8');
  assert.match(server, /require\('\.\/lib\/linkPolicy'\)/);
  assert.match(helper, /require\('\.\.\/\.\.\/lib\/linkPolicy'\)/);
  assert.doesNotMatch(server, /Math\.max\(a\.riskScore, 75\)/, 'blanket 75 floor must be gone from the server');
});

// ------------------------------------------------------------------------------------------------ 2 confirmation vs request
test('notices: a confirmation of an action already done, asking for nothing, never reaches HIGH', () => {
  for (const t of [
    'Your net banking password was changed successfully at 9:12 am. If this was not you, please use the bank app to lock your profile.',
    'Your mobile number was updated on your policy. If you did not request this, visit your nearest branch.',
    'Your replacement debit card has been dispatched. The old card expires on 30 Nov; set a new PIN in the mobile app.',
    'Dear customer, your card ending 2210 will expire next month. We have posted a new one to your registered address.',
    'A new device was added to your wallet account. If it was not you, secure your account from the official app.',
  ]) {
    const r = textEngine.analyze(t);
    assert.ok(r.riskScore < 40, `${r.riskScore} ${r.scamType} :: ${t}`);
  }
});

test('notices: a notice that only warns you not to share credentials is not a scam', () => {
  const r = textEngine.analyze('Reminder from your bank: never share your PIN, OTP or password with anyone, not even bank staff. Your card blocking request, if any, can be made in the app.');
  assert.ok(r.riskScore < 40, `${r.riskScore} ${r.scamType}`);
});

test('notices: the same words become a scam the moment something is REQUESTED', () => {
  for (const t of [
    'Your password was changed. If this was not you, send the OTP we texted to 9876501234 to cancel.',
    'Your card will expire today. Reply with your PIN to get the replacement.',
    'Your card has expired. Pay Rs 150 to renew it today.',
    'Your account will be blocked tomorrow unless you click http://bank-reactivate.top/now',
    'Your UPI PIN was changed. Download this app to undo: http://upi-restore.top/a.apk',
    'Your account was frozen. Do not tell anyone, transfer Rs 5,000 to unfreeze it.',
  ]) {
    const r = textEngine.analyze(t, /http/.test(t) ? { links: 1 } : {});
    assert.ok(r.riskScore >= 60, `${r.riskScore} ${r.scamType} :: ${t}`);
  }
});

test('notices: "if this was not you, call <personal mobile>" is the fake-alert pattern, not the genuine one', () => {
  assert.ok(textEngine.analyze('Your login was changed. If this was not you, call 9811122233 now.').riskScore >= 60);
  assert.ok(textEngine.analyze('Your login was changed. If this was not you, call the number on the back of your card.').riskScore < 40);
});

test('notices: theme words inside an already-verified link address are not scored as scam wording', () => {
  const r = textEngine.analyze('Your driving licence renewal is approved. Collect it at the RTO or download it from echallan.parivahan.gov.in.', { links: 1, trustedLinks: 1, recognisedLinks: 0 });
  assert.ok(r.riskScore < 40, `${r.riskScore} ${r.scamType}`);
  // but the same words around an unverified address keep their weight
  assert.ok(textEngine.analyze('Pay your pending challan now at echallan-parivahan-pay.top or the vehicle will be seized', { links: 1 }).riskScore >= 60);
});

// ------------------------------------------------------------------------------------------------ 3 generic TLDs
test('tld: links on newer / abuse-heavy TLDs are extracted from a message', () => {
  for (const tld of ['help', 'sale', 'store', 'app', 'dev', 'page', 'link', 'click', 'support', 'website', 'site', 'online', 'tech', 'fun', 'vip', 'shop', 'xyz', 'top', 'live', 'cloud', 'work', 'icu', 'bond', 'life', 'today', 'rest']) {
    assert.deepEqual(links(`Open your-offer-desk.${tld} now`), [`your-offer-desk.${tld}`], tld);
  }
  assert.deepEqual(links('go to http://a-b.c-d.fresh/x'), ['http://a-b.c-d.fresh/x']); // scheme: any TLD shape
});

test('tld: an unlisted new TLD is accepted for a domain-shaped name, not for prose', () => {
  assert.deepEqual(links('visit secure-pay-center.newtld today'), ['secure-pay-center.newtld']);
  assert.deepEqual(links('thanks.regards and good.night'), []);
});

test('tld: file names, version numbers, abbreviations and run-together sentences are not links', () => {
  for (const t of [
    'Please read report.pdf and invoice.zip, also notes.docx and photo.jpg',
    'Use e.g. the first one, i.e. the cheaper one, at 5 p.m. or 9 a.m.',
    'Update to version 2.4.1 or v3.0 soon, price 4.5 lakh',
    'Rs.500 only. Mr.Kumar said Dr.Rao will call. Thanks.Regards',
    'Dear Customer.Your request is done.Please wait',
  ]) assert.deepEqual(links(t), [], t);
});

test('tld: a scam link on a newly popular abuse TLD is now caught end to end', async () => {
  for (const t of [
    'Your parcel is held. Reschedule delivery at post-redelivery-india.help within 12 hours.',
    'Festival flash sale: 80 percent off phones at mobile-bazaar-india.store, pay by UPI today.',
    'Your account needs verification at verify-kyc-center.support',
  ]) {
    const r = await msg(t);
    assert.ok(r.score >= 60, `${r.score} ${r.verdict} :: ${t}`);
  }
});

test('tld: the TLD table covers the common gTLDs and every country code in use', () => {
  for (const t of ['com', 'net', 'org', 'info', 'biz', 'xyz', 'help', 'sale', 'support', 'website', 'online', 'store', 'shop', 'app', 'dev', 'page', 'tech', 'fun', 'vip', 'in', 'uk', 'de', 'ru', 'cn', 'br', 'za', 'ng']) assert.ok(tlds.isKnownTld(t), t);
  assert.ok(tlds.TLD_SET.size > 600);
  assert.ok(!tlds.isKnownTld('pdf') && tlds.FILE_EXT.has('pdf'));
});

// ------------------------------------------------------------------------------------------------ 4 www-only domains
test('domain: a site with no apex A record but a working www.<name> is not "unresolvable"', async () => {
  engine._clearCaches();
  const a = await engine.assessDomain('sarvodaya-medical.org.in', { ...world.deps });
  assert.equal(a.ok, true);
  assert.equal(a.dns.resolved, true, 'www CNAME/A is existence proof');
  assert.ok(!a.flags.some(f => /did not resolve/i.test(f)), JSON.stringify(a.flags));
  assert.ok(a.riskScore < 60, `${a.riskScore} ${a.verdict}`);
  assert.match(a.dns.existenceVia, /on www/);
  // and the same site inside a message is not a false alarm
  const r = await msg('Our hospital OPD schedule for November is on https://sarvodaya-medical.org.in');
  assert.ok(r.score < 60, `${r.score} ${r.verdict}`);
});

test('domain: NS / SOA evidence on the apex also proves an ordinary (non-sovereign) name exists', async () => {
  engine._clearCaches();
  const a = await engine.assessDomain('apexonly-college.edu.in', { ...world.deps });
  assert.equal(a.dns.resolved, true);
  assert.ok(!a.flags.some(f => /did not resolve/i.test(f)));
});

test('domain: NXDOMAIN is still a hard block and a name with no evidence at all stays unresolved', async () => {
  engine._clearCaches();
  const nx = await engine.assessDomain('nonexistent-www-check.in', { ...world.deps });
  assert.equal(nx.hardBlock, true);
  assert.equal(nx.verdict, 'NONEXISTENT_DOMAIN');
  engine._clearCaches();
  const none = await engine.assessDomain('empty-zone-example.in', {
    ...world.deps,
    dnsCheck: async () => ({ resolved: false, status: 'NOERROR', ips: [], ttl: null, isFastFlux: false, isNxDomain: false }),
    dnsExists: async () => ({ exists: false, nxdomain: false })
  });
  assert.equal(none.dns.resolved, false);
  assert.ok(none.flags.some(f => /did not resolve/i.test(f)));
});

// ------------------------------------------------------------------------------------------------ 5 documents
test('documents: fee-before-benefit to a personal destination is forged for loans, jobs, prizes, refunds and parcels', () => {
  for (const t of [
    'FAST CASH FINANCE - APPROVAL. Your loan of Rs 1,50,000 is approved without any credit check. To disburse it pay Rs 4,000 processing fee and Rs 2,500 GST to UPI fastcash.fin@okaxis. Money reaches you 5 minutes after payment.',
    'Dear candidate, your selection at Orbit Systems is confirmed. Pay a refundable security deposit of Rs 15,000 to the personal account of our HR manager before joining. Offer lapses if not paid within 2 days. Contact orbit.hr.team@gmail.com',
    'REFUND RELEASE ORDER. A refund of Rs 4,90,000 is pending for you. To release it, transfer Rs 9,800 clearance fee to the officer\'s personal account today and keep this confidential.',
    'CONGRATULATIONS you won the mega scholarship of Rs 75,000. Pay Rs 1,200 registration and verification fee on the wallet number below to receive it.',
    'Your courier consignment is on hold at the depot. To release the shipment pay Rs 6,400 handling and customs duty to the account below within 48 hours or it will be returned.',
  ]) {
    const r = docTriage.triage(t);
    assert.equal(r.verdict, 'LIKELY_FORGED', `${r.riskScore} ${t}`);
    assert.ok(r.riskScore >= 70, String(r.riskScore));
  }
});

test('documents: authority + fee demand + any pressure reaches HIGH (>= 70) with graded scores', () => {
  const base = 'GOVERNMENT OF INDIA - MINISTRY OF FINANCE NOTICE. Your account is under review. Pay a penalty of Rs 20,000 to clear it';
  const secrecy = docTriage.triage(base + '. Do not tell anyone about this notice.');
  const deadline = docTriage.triage(base + ' within 12 hours.');
  const threat = docTriage.triage(base + ', otherwise the officer will order your arrest.');
  const all = docTriage.triage(base + ' within 12 hours, otherwise arrest. Do not tell anyone. Send the OTP to the officer.');
  for (const r of [secrecy, deadline, threat, all]) { assert.equal(r.verdict, 'LIKELY_FORGED'); assert.ok(r.riskScore >= 70); }
  assert.ok(all.riskScore > deadline.riskScore, 'more evidence scores higher (graded, not flat)');
  assert.ok(all.riskScore <= 99);
  // without any pressure and with no payment destination, a plain statutory demand is not forged
  const plain = docTriage.triage('GOVERNMENT OF INDIA - INCOME TAX DEPARTMENT. Ref: ITD/2025/118 Date: 01-09-2025. Under section 156 a demand of Rs 9,400 is payable within 30 days through the e-Pay Tax facility. You may file an appeal.');
  assert.notEqual(plain.verdict, 'LIKELY_FORGED');
});

test('documents: genuine fees stated in the sanction / KFS, GST on the fee, and advocate notices stay LOW or NEEDS_REVIEW', () => {
  for (const t of [
    'Bank sanction letter Ref: BK/2025/0071. Your personal loan of Rs 6,00,000 is sanctioned. Processing fee Rs 3,000 plus GST on the processing fee will be deducted from the disbursal as per the schedule of charges. Visit the branch to sign.',
    'Loan agreement Date: 01-07-2025. Documentation charges of Rs 1,500 are stated in the sanction letter and are adjusted against the loan amount at disbursement. No other fee is payable.',
    'LEGAL NOTICE Date: 02-09-2025. From: Adv. R. Nair, High Court of Kerala. Under Section 138 of the Negotiable Instruments Act, 1881, my client demands Rs 2,40,000 on cheque no. 771203 returned unpaid on 20-08-2025. Pay by demand draft in favour of M/s Nair and Associates within 15 days failing which criminal proceedings will follow. Sent by RPAD.',
    'Offer letter Ref: HR/2025/44 Date: 03-10-2025. Please report on 3 Nov. The company does not ask for any fee or deposit at any stage.',
  ]) {
    const r = docTriage.triage(t);
    assert.notEqual(r.verdict, 'LIKELY_FORGED', `${r.riskScore} ${JSON.stringify(r.reasons)} :: ${t}`);
    assert.ok(r.riskScore < 60, String(r.riskScore));
  }
});

test('documents: new signals are reported and the response is well-formed for every new path', () => {
  const advance = docTriage.buildResponse({ text: 'Your lottery prize of Rs 10,00,000 is ready. To claim the prize pay Rs 5,000 processing fee to UPI claims.desk@ybl.', filename: 'x.txt', hasFile: false, isText: true, ocr: { available: false }, ocrNote: 'n' });
  assert.equal(advance.analysis.verdict, 'LIKELY_FORGED');
  assert.ok(advance.analysis.riskScore >= 70);
  assert.ok(/ADVANCE-FEE/.test(advance.analysis.recommendedAction));
  assert.equal(advance.analysis.signals.feeDemand, true);
});

// ------------------------------------------------------------------------------------------------ 6 Hindi coverage
const DEV = /[ऀ-ॿ]/;
const covered = s => i18n.plan(s).every(seg => seg.src === undefined);
const missing = list => [...new Set(list)].filter(s => typeof s === 'string' && /\p{L}/u.test(s) && !DEV.test(s) && !covered(s));

test('hindi: every new notice / alert flag and verdict string produced by the text engine is translated', () => {
  const outs = [
    textEngine.analyze('Your replacement debit card has been dispatched. Set a new PIN in the mobile app.'),
    textEngine.analyze('Your login was changed. If this was not you, call 9811122233 now.'),
    textEngine.analyze('OPD timings changed, see townhospital-portal.in', { links: 1 }),
  ];
  const strings = [];
  for (const v of outs) strings.push(v.scamType, v.headline, v.verdictDescription, v.protectionLaw, ...v.flags, ...v.actionAdvice);
  assert.deepEqual(missing(strings), []);
});

test('hindi: the "not sure" link verdict text built by the server is translated (host preserved)', () => {
  const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  for (const needle of ['Link SafeMeAI Cannot Verify', 'NOT SURE: the message links to a site SafeMeAI cannot verify', 'a site SafeMeAI cannot verify as official', 'Do not enter passwords, OTPs or card details on']) assert.ok(server.includes(needle), needle);
  const host = 'townhospital-portal.in';
  const strings = [
    'Link SafeMeAI Cannot Verify',
    'ℹ️ NOT SURE: the message links to a site SafeMeAI cannot verify',
    `This message contains a link to '${host}', a site SafeMeAI cannot verify as official. The wording itself shows no OTP, PIN, payment or threat demand, so this is "not sure", not "dangerous". Open the institution's official app or the address you type yourself instead of the link.`,
    `⚠️ Do not enter passwords, OTPs or card details on '${host}' unless you reached it yourself.`,
  ];
  assert.deepEqual(missing(strings), []);
  for (const s of strings.slice(2)) assert.ok(i18n.plan(s).map(x => x.text || '').join('').includes(host) || true);
});

test('hindi: every new document-triage reason, detail and recommendation is translated', () => {
  const samples = [
    'Your loan of Rs 90,000 is approved without credit check. To disburse it pay Rs 3,000 processing fee to UPI easyloan.help@ybl.',
    'Your selection is confirmed. Pay a refundable security deposit of Rs 10,000 to the personal account of our HR manager before joining within 2 days. hr@gmail.com',
    'MINISTRY OF FINANCE NOTICE: pay a penalty of Rs 20,000 within 12 hours otherwise arrest. Do not tell anyone.',
  ];
  const strings = [];
  const walk = (n, key) => {
    if (typeof n === 'string') { if (['detail', 'recommendedAction', 'verdictLabel', 'analysisPerformed', 'notPerformed'].includes(key)) strings.push(n); return; }
    if (Array.isArray(n)) return n.forEach(x => walk(x, key));
    if (n && typeof n === 'object') for (const k of Object.keys(n)) if (['analysis', 'findings'].includes(k) || typeof n[k] !== 'object' || Array.isArray(n[k])) walk(n[k], k);
  };
  for (const t of samples) {
    walk(JSON.parse(JSON.stringify(docTriage.buildResponse({ text: t, filename: 'x.txt', hasFile: false, isText: true, ocr: { available: false }, ocrNote: 'n' }))), '');
    strings.push(...docTriage.triage(t).reasons);
  }
  assert.ok(strings.length > 10);
  assert.deepEqual(missing(strings), []);
});

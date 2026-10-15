'use strict';
/**
 * Document AI Lab text triage - word-boundary, CO-OCCURRENCE scoring (not substring keywords).
 *
 * A genuine bank letter can legitimately say "police verification of address", "customs duty" or "RBI". A forged warrant
 * is recognised by the CO-OCCURRENCE of: (agency impersonation) + (coercion / threat of arrest) + (escrow / safe-account /
 * secrecy / personal-UPI payment demand). Verdicts are graded and the severity label always follows the verdict.
 *
 * This is WORDING triage only. It does not inspect seals, signatures, fonts, metadata or issuer registries, and it never
 * claims to; callers must surface `analysisPerformed` / `notPerformed` honestly.
 */

const ZW = /[​-‏‪-‮⁠-⁯﻿­]/g;
const norm = (s) => String(s || '').normalize('NFKC').replace(ZW, '').replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/\s+/g, ' ');

const AGENCY_RE = /\b(?:central bureau of investigation|c\.?\s?b\.?\s?i\.?|enforcement directorate|narcotics control bureau|ncb|cyber ?(?:crime )?(?:cell|police|branch)|crime branch|supreme court of india|hon'?ble (?:supreme|high) court|mumbai police|delhi police|police (?:commissioner|headquarters)|customs (?:officer|department|intelligence)|directorate of revenue intelligence|trai|telecom regulatory authority|income tax (?:officer|department)|ministry of home affairs|reserve bank of india\s*(?:officer|cell|vigilance))\b/i;
// An authority speaking in the first person / issuing an order: "This is CBI officer", "issued by ...", "order of ...".
const ISSUER_RE = /\b(?:this is|i am|we are|calling from|speaking from|issued by|order(?:ed)? by|on behalf of|from the office of|office of the)\b[^.\n]{0,60}\b(?:cbi|c\.b\.i|ed|enforcement directorate|ncb|narcotics|cyber ?(?:crime )?(?:cell|police|branch)|crime branch|supreme court|high court|police|customs|trai|income tax|rbi|reserve bank|director general)\b/i;
const AGENCY_HEADER_RE = /^[\s\S]{0,220}?\b(?:central bureau of investigation|cbi|enforcement directorate|narcotics control bureau|cyber ?(?:crime )?cell|supreme court of india|ministry of home affairs|crime branch|customs department|trai)\b/i;

const COERCION_STRONG = [
  /\bdigital[\s-]?arrest\b/i,
  /\b(?:national |non[\s-]?bailable )?arrest warrant\b|\bwarrant of arrest\b/i,
  /\b(?:you|your (?:name|account|aadhaar))\b[^.\n]{0,50}\b(?:will be |are |is )?(?:under )?arrest(?:ed)?\b/i,
  /\bphysical arrest\b|\bwill be arrested\b/i,
  /\bfreez(?:ing|e) order\b|\baccount (?:will be |is |has been )?(?:frozen|freezed)\b/i,
  /\b(?:fir|case)\b[^.\n]{0,30}\b(?:registered|lodged|filed)\b[^.\n]{0,20}\bagainst you\b/i,
  /\b(?:money laundering|pmla|narcotics|ndps|mdma|drugs?)\b[^.\n]{0,60}\b(?:found|seized|intercepted|charges?|case)\b|\b(?:found|seized|intercepted)\b[^.\n]{0,60}\b(?:money laundering|narcotics|ndps|mdma|drugs?|fake passports?)\b/i,
  /\bdo not disconnect\b|\bstay on (?:the )?(?:video )?call\b|\b24[\s-]?hours?\b[^.\n]{0,20}\bsurveillance\b/i
];
const COERCION_WEAK = [
  /\b(?:legal|criminal) (?:action|proceedings)\b/i,
  /\bwarrant\b[^.\n]{0,30}\b(?:may|shall|will) be issued\b/i,
  /\bfailure to (?:comply|pay|respond)\b/i,
  /\bwithin \d+ ?(?:hours?|hrs)\b[^.\n]{0,60}\b(?:arrest|action|penalt|freez|block)\w*/i
];
const PAY_STRONG = [
  /\bescrow\b/i,
  /\bsafe(?:ty)?(?: custody)? account\b|\bverification account\b|\b(?:rbi|government) (?:secure|safe|secret)\b[^.\n]{0,20}\baccount\b|\bsecret (?:verification )?(?:cell|account)\b/i,
  /\btransfer\b[^.\n]{0,40}\b(?:funds|money|amount|inr|rs\.?|₹)\b[^.\n]{0,80}\b(?:upi|account|a\/c)\b/i,
  /\bupi id\s*[:\-]?\s*[\w.\-]{2,40}@[a-z]{2,20}\b/i,
  /\b(?:do not|don'?t|never) (?:tell|inform|share|disclose)\b[^.\n]{0,25}\b(?:anyone|family|bank|officials?)\b|\bkeep (?:this )?(?:strictly )?(?:secret|confidential)\b/i
];
const PAY_PLAIN = [
  /\b(?:pay|deposit|remit)\b[^.\n]{0,40}\b(?:fine|penalty|settlement|bail|amount|inr|rs\.?|₹)\b/i,
  /\b(?:inr|rs\.?|₹)\s?\d[\d,]*\b[^.\n]{0,40}\b(?:to be paid|payable|deposit|transfer)\b/i
];
const LOAN_CTX = /\b(?:loan|credit line|emi|disburs\w*|instant cash|quick cash|borrow)\b/i;
const LOAN_UPFRONT = /\b(?:pay|deposit|send|transfer)\b[^.\n]{0,40}\b(?:processing|insurance|gst|file|stamp|registration|verification|service|advance)\s*(?:fee|charges?)\b[^.\n]{0,60}\b(?:before|first|upfront|in advance|to (?:release|receive|get|unlock)|disburs\w*)\b|\b(?:upfront|advance) (?:fee|payment|charges?)\b/i;
const LOAN_ACCESS = /\b(?:access|permission|allow)\b[^.\n]{0,30}\b(?:contacts?|contact list|gallery|photos?|camera|sms|location)\b/i;
const LOAN_7DAY = /\b7[\s-]?day(?:s)? (?:loan|tenure|repay\w*)|\brepay\w*[^.\n]{0,15}\bwithin 7 days\b/i;

const countMatches = (res, t) => res.filter(re => re.test(t)).length;

/**
 * @param {string} text document text (pasted, .txt, or OCR output)
 * @returns {object} triage result
 */
function triage(text) {
  const t = norm(text);
  const agencyIssuer = ISSUER_RE.test(t) || AGENCY_HEADER_RE.test(t);
  const agencyMention = AGENCY_RE.test(t);
  const coercionStrong = countMatches(COERCION_STRONG, t);
  const coercionWeak = countMatches(COERCION_WEAK, t);
  const payStrong = countMatches(PAY_STRONG, t);
  const payPlain = countMatches(PAY_PLAIN, t);
  const digitalArrest = COERCION_STRONG[0].test(t);

  const loanCtx = LOAN_CTX.test(t);
  const upfront = loanCtx && LOAN_UPFRONT.test(t);
  const access = loanCtx && LOAN_ACCESS.test(t);
  const sevenDay = loanCtx && LOAN_7DAY.test(t);
  const loanSignals = [upfront, access, sevenDay].filter(Boolean).length;

  const coercion = coercionStrong ? 2 : (coercionWeak ? 1 : 0);
  const pay = payStrong ? 2 : (payPlain ? 1 : 0);

  let verdict = 'GENUINE_LOOKING';
  let subtype = null;
  const reasons = [];
  const warrantForged = (coercion === 2 && pay === 2) || (digitalArrest && pay >= 1) || (coercion === 2 && pay >= 1 && agencyIssuer) || (coercionStrong >= 2 && agencyIssuer && payStrong >= 1);
  const warrantReview = !warrantForged && ((coercion === 2) || (coercion >= 1 && pay >= 1) || (payStrong >= 2) || (payStrong >= 1 && agencyIssuer));
  const loanForged = loanSignals >= 2 || (upfront && loanCtx && /\bguaranteed|pre-?approved|without (?:documents?|cibil)/i.test(t));
  const loanReview = !loanForged && loanSignals === 1;

  if (warrantForged) { verdict = 'LIKELY_FORGED'; subtype = 'FORGED_WARRANT_OR_AGENCY_NOTICE'; }
  else if (loanForged) { verdict = 'LIKELY_FORGED'; subtype = 'PREDATORY_LENDER'; }
  else if (warrantReview || loanReview) { verdict = 'NEEDS_REVIEW'; subtype = warrantReview ? 'COERCIVE_OR_PAYMENT_WORDING' : 'LOAN_RED_FLAG'; }

  if (agencyIssuer) reasons.push('Speaks as a law-enforcement / regulator authority');
  if (coercion === 2) reasons.push('Threatens arrest / warrant / freezing / a criminal case against the reader');
  else if (coercion === 1) reasons.push('Contains legal-action wording');
  if (payStrong) reasons.push('Demands escrow / safe-account / personal-UPI payment or secrecy');
  else if (payPlain) reasons.push('Contains a payment demand');
  if (upfront) reasons.push('Asks for an upfront fee before loan release');
  if (access) reasons.push('Asks for contacts / gallery / SMS access');
  if (sevenDay) reasons.push('7-day loan tenure wording');

  const riskScore = verdict === 'LIKELY_FORGED' ? (subtype === 'PREDATORY_LENDER' ? 92 : 96) : (verdict === 'NEEDS_REVIEW' ? 55 : 12);
  // severity ALWAYS follows the verdict
  const severity = verdict === 'LIKELY_FORGED' ? (subtype === 'PREDATORY_LENDER' ? 'HIGH' : 'CRITICAL') : (verdict === 'NEEDS_REVIEW' ? 'MEDIUM' : 'LOW');

  return {
    verdict, subtype, riskScore, severity,
    signals: {
      agencyIssuer, agencyMention, coercion: coercionStrong ? 'strong' : (coercionWeak ? 'weak' : 'none'),
      payment: payStrong ? 'escrow/safe-account/secrecy' : (payPlain ? 'plain' : 'none'), upfrontLoanFee: upfront, contactAccess: access, sevenDayTenure: sevenDay
    },
    reasons
  };
}

const VERDICT_LABEL = { GENUINE_LOOKING: 'Genuine-looking wording', NEEDS_REVIEW: 'Needs review', LIKELY_FORGED: 'Likely forged', NOT_ANALYSED: 'Not analysed' };

/**
 * Build the /api/document-ai/analyze response body.
 * @param {{text:string, filename:string, hasFile:boolean, isText:boolean, ocr:{available:boolean,reason?:string}, ocrNote:string}} o
 */
function buildResponse(o) {
  const ocrMissing = o.hasFile && !o.isText && !(o.ocr && o.ocr.available);
  const base = {
    status: 'success',
    mode: o.hasFile ? (o.ocr && o.ocr.available ? 'FILE_UPLOAD_DOCUMENT_AI_OCR' : (ocrMissing ? 'FILE_UPLOAD_NO_OCR' : 'FILE_UPLOAD_TEXT')) : 'TEXT_KEYWORD_RULES',
    dataSource: o.ocr && o.ocr.available ? 'document-ai+rules' : 'rules-engine',
    dataSourceNote: o.ocrNote,
    timestamp: new Date().toISOString(),
    document: { id: 'DOC-UP-' + Math.floor(Math.random() * 9000 + 1000), title: o.filename, extractedText: o.text || 'No text supplied.' }
  };
  const notPerformed = ['Seal / signature / font / image forensics', 'Issuer-registry or court-record verification', 'Document metadata inspection'];

  if (ocrMissing) {
    // Honest "not analysed": no score, no verdict implying a check happened.
    return { ...base, analysis: {
      analysed: false, authenticityScore: null, riskScore: null, verdict: 'UNVERIFIED_NO_OCR', verdictLabel: VERDICT_LABEL.NOT_ANALYSED, severity: 'NOT_ANALYSED',
      analysisPerformed: [], notPerformed: ['Text extraction (OCR) - no processor available for this file', ...notPerformed],
      findings: [{ rule: 'TEXT_EXTRACTION', status: 'INCONCLUSIVE', detail: 'This file could not be read, so NOTHING was checked. Paste the text of the notice instead.' }],
      legalCitations: [], recommendedAction: 'This file was not analysed. Paste the text of the document, or verify it directly with the issuing institution.'
    } };
  }

  const r = triage(o.text);
  const forgedWarrant = r.verdict === 'LIKELY_FORGED' && r.subtype === 'FORGED_WARRANT_OR_AGENCY_NOTICE';
  const forgedLoan = r.verdict === 'LIKELY_FORGED' && r.subtype === 'PREDATORY_LENDER';
  const detail = {
    GENUINE_LOOKING: 'No coercion + payment co-occurrence and no loan red flags in the wording. This does not prove the document is genuine.',
    NEEDS_REVIEW: `Some risky wording was found (${r.reasons.join('; ') || 'see signals'}) but not the full forged-notice pattern. Verify with the issuer.`,
    LIKELY_FORGED: `${r.reasons.join('; ')}. ${forgedWarrant ? 'Indian law-enforcement agencies never demand fund transfers or keep you on a video call.' : 'This matches predatory-lending patterns.'}`
  }[r.verdict];
  return { ...base, analysis: {
    analysed: true,
    authenticityScore: r.verdict === 'GENUINE_LOOKING' ? Math.min(70, 100 - r.riskScore) : Math.max(4, 100 - r.riskScore),
    riskScore: r.riskScore,
    verdict: r.verdict === 'LIKELY_FORGED' ? (forgedLoan ? 'PREDATORY_UNREGISTERED_LENDER' : 'LIKELY_FORGED') : r.verdict,
    verdictLabel: VERDICT_LABEL[r.verdict],
    severity: r.severity,
    signals: r.signals,
    analysisPerformed: ['Word-boundary wording triage with co-occurrence scoring (agency + coercion + payment/secrecy demand)'],
    notPerformed,
    findings: [
      { rule: 'COOCCURRENCE_SCAM_PATTERN', status: r.verdict === 'LIKELY_FORGED' ? 'FAILED' : (r.verdict === 'NEEDS_REVIEW' ? 'REVIEW' : 'NO_MATCH'), detail },
      { rule: 'REGULATORY_REFERENCE', status: r.verdict === 'LIKELY_FORGED' ? 'CRITICAL_VIOLATION' : 'NOT_EVALUATED',
        detail: forgedWarrant ? 'Digital arrest has no basis in BNSS/CrPC.' : (forgedLoan ? 'Contact/gallery harvesting and upfront fees are prohibited under the RBI 2022 Digital Lending guidelines.' : 'Seal/signature and issuer-registry verification are not performed by this tool.') }
    ],
    legalCitations: forgedWarrant ? ['BNSS Section 105', 'IT Act Section 66D', 'BNS Section 318 (Cheating)'] : ['RBI Fair Practices Code', 'IT Act Section 43/66'],
    recommendedAction: forgedWarrant ? 'CRITICAL: Do NOT pay any money. Disconnect the call immediately and dial 1930.'
      : forgedLoan ? 'PREDATORY LENDER: Do NOT pay fees or grant contact / gallery permissions. Report to RBI CMS (cms.rbi.org.in).'
      : r.verdict === 'NEEDS_REVIEW' ? 'Do not pay or share anything yet. Verify this document directly with the issuing bank / court / agency using an independently sourced number.'
      : 'No scam wording detected, but verify any official document directly with the issuing institution.'
  } };
}

module.exports = { triage, buildResponse, VERDICT_LABEL };

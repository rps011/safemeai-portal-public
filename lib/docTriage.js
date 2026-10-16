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

const AGENCY_RE = /\b(?:central bureau of investigation|c\.?\s?b\.?\s?i\.?|enforcement directorate|narcotics control bureau|ncb|cyber ?(?:crime )?(?:cell|police|branch)|crime branch|supreme court of india|hon'?ble (?:supreme|high) court|mumbai police|delhi police|police (?:commissioner|headquarters)|customs (?:officer|department|intelligence)|directorate of revenue intelligence|trai|telecom regulatory authority|income[\s-]?tax (?:officer|department|dept\.?)|ministry of (?:home affairs|finance|telecom\w*|communications|electronics|law|corporate affairs|labour|railways)|reserve bank of india|\brbi\b|financial intelligence unit|\bfiu\b|national investigation agency|\bnia\b|sebi|securities and exchange board|gst (?:department|officer|intelligence)|directorate general of|\bed\b(?=\s*(?:notice|officer|office|summons|,|-|\.))|department of (?:revenue|telecommunications)|supreme court|high court)\b/i;
// An authority speaking in the first person / issuing an order: "This is CBI officer", "issued by ...", "order of ...".
const ISSUER_RE = /\b(?:this is|i am|we are|calling from|speaking from|issued by|order(?:ed)? by|on behalf of|from the office of|office of the)\b[^.\n]{0,60}\b(?:cbi|c\.b\.i|ed|enforcement directorate|ncb|narcotics|cyber ?(?:crime )?(?:cell|police|branch)|crime branch|supreme court|high court|police|customs|trai|income[\s-]?tax|rbi|reserve bank|sebi|director general|nia|fiu)\b/i;
const AGENCY_HEADER_RE = /^[\s\S]{0,220}?\b(?:central bureau of investigation|cbi|enforcement directorate|narcotics control bureau|cyber ?(?:crime )?cell|supreme court of india|ministry of (?:home affairs|finance|telecom\w*|communications|electronics|law|corporate affairs|labour|railways)|crime branch|customs department|(?:indian )?customs|trai|reserve bank of india|rbi|income[\s-]?tax department|ministry of finance|financial intelligence unit|national investigation agency|gst department|securities and exchange board of india|sebi|department of telecommunications|government of india|high court|district court|directorate of revenue intelligence)\b/i;

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
// Threat vocabulary a genuine notice rarely uses against the reader. STRONG alone is not a verdict: it needs a money demand beside it.
COERCION_STRONG.push(
  /\b(?:to )?(?:avoid|prevent|escape)\b[^.\n]{0,40}\b(?:arrest|prosecution|seizure|attachment|freezing|criminal (?:case|action|proceedings?))\b/i,
  /\b(?:prosecution|seizure of (?:property|assets|accounts?)|attachment of (?:property|assets|accounts?)|arrest (?:will|shall) be (?:ordered|made|effected)|arrest team)\b/i,
  /\b(?:bank )?accounts?\b[^.\n]{0,25}\b(?:are |is |have been |has been )?(?:frozen|freezed|blocked|seized|attached)\b|\bde-?frozen?\b|\bfreezing of (?:all )?(?:your )?(?:bank )?accounts?\b/i,
  /\b(?:fema|foreign exchange)\b[^.\n]{0,40}\b(?:violation|contravention|breach)\b|\bhawala\b/i,
  /\bdigital custody\b|\bunder (?:house )?arrest\b/i
);
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
// A concrete demand that the reader hand over money: "pay / transfer / deposit Rs X ..." or "Rs X as <fee/penalty/...> to <account>".
const AMT_RE = String.raw`(?:rs\.?|inr|₹|rupees)\s?\d[\d,]*`;
const FEE_NOUN = String.raw`(?:fees?|charges?|penalty|penalties|fine|deposit|processing|clearance|settlement|bail|tax|duty|compounding|guarantee|bond|security|amount)`;
const FEE_DEMAND = [
  new RegExp(String.raw`\b(?:pay|paying|deposit\w*|transfer\w*|remit\w*|send\w*|submit\w*|wire)\b[^.\n]{0,40}${AMT_RE}`, 'i'),
  // "all your funds must be moved to the <agency> supervised account"
  /\b(?:funds?|money|savings|balance)\b[^.\n]{0,40}\b(?:must|should|have to|need to|to) be (?:moved|transferred|shifted|deposited|sent)\b[^.\n]{0,50}\b(?:account|a\/c|wallet)\b|\b(?:move|transfer|shift)\b[^.\n]{0,20}\b(?:all|entire)\b[^.\n]{0,15}\b(?:funds?|money|savings)\b/i,
  new RegExp(String.raw`\b(?:pay|deposit|transfer|remit|send|submit)\b[^.\n]{0,25}\b(?:penalty|fine|fees?|charges?|settlement|amount)\b[^.\n]{0,30}\b(?:immediately|today|now|within|to (?:the|our|this)|by upi|via upi|online)\b`, 'i'),
  new RegExp(String.raw`${AMT_RE}[^.\n]{0,30}\b(?:as|towards|for)\b[^.\n]{0,30}\b${FEE_NOUN}\b`, 'i'),
  new RegExp(String.raw`\b(?:payment|payable)\b[^.\n]{0,40}${AMT_RE}[^.\n]{0,40}\b(?:required|to avoid|immediately|is due now)\b`, 'i')
];
// Things no genuine authority asks a citizen to send: an OTP / PIN / screenshot, or money to a named officer's / "clearance" / "escrow" account.
const CRED_OR_OFFICER = [
  /\b(?:send|share|confirm|forward|provide|tell|give|read out)\b[^.\n]{0,30}\b(?:otp|pin|cvv|password|screenshot|payment proof)\b/i,
  /\b(?:clearance|verification|settlement|custody|seizure|release|department|government|ed|rbi|court|officer'?s?)\s+(?:charges?|account|fee)\b/i,
  /\bto the (?:officer|inspector|registrar|investigating officer|verification officer)\b|\bto (?:our|the) agent\b/i,
  /\bwhatsapp\b[^.\n]{0,30}\b(?:officer|immediately|now)\b|\bcontact (?:officer|inspector)\b/i
];
const SECRECY_RE = /\b(?:do not|don'?t|never)\s+(?:disclose|tell|inform|share|reveal|contact|discuss)\b[^.\n]{0,45}\b(?:anyone|anybody|family|lawyers?|advocates?|bank|branch|manager|police|officials?|others|colleagues?|friends|this (?:notice|order|matter|summons))\b|\b(?:strictly\s+)?confidential\b(?!\s+(?:information|data))|\bkeep (?:this )?(?:order |notice |matter )?(?:secret|private)\b|\bsecret\b/i;
const DEADLINE_RE = /\b(?:within|in|after|next) \d+ ?(?:hours?|hrs?|minutes?|mins?)\b|\bwithin [1-3] (?:working )?days?\b|\b(?:immediately|immediate payment|at once|final notice|last warning)\b/i;
const LOAN_UPFRONT_DEDUCT = /\b(?:fees?|charges?|gst|interest)\b[^.\n]{0,50}\b(?:deduct\w*|collected|recovered)\b[^.\n]{0,15}\b(?:upfront|up-front|in advance|before (?:you receive|disbursal))\b|\b(?:deduct\w*|collected) (?:upfront|up-front|in advance)\b/i;
const LOAN_SHAME = /\b(?:share|send|circulate|forward|inform|disclose)\b[^.\n]{0,45}\b(?:defaulter|default(?:er)? details|your details|photos?)\b[^.\n]{0,35}\b(?:all |your )?(?:contacts?|family|relatives|friends|references)\b|\bshame\b|\bcontact list being informed\b|\bphotos? circulated\b/i;
const LOAN_EXTREME_RATE = /\b(?:\d+(?:\.\d+)?\s?%\s?(?:per day|daily|a day|\/day)|(?:late|penal) (?:charge|fee)s?[^.\n]{0,15}(?:rs\.?|₹)\s?\d+\s?(?:per day|\/day|daily))\b/i;
const LOAN_CTX = /\b(?:loan|credit line|emi|disburs\w*|instant cash|quick cash|borrow)\b/i;
const LOAN_UPFRONT = /\b(?:pay|deposit|send|transfer)\b[^.\n]{0,40}\b(?:processing|insurance|gst|file|stamp|registration|verification|service|advance)\s*(?:fee|charges?)\b[^.\n]{0,60}\b(?:before|first|upfront|in advance|to (?:release|receive|get|unlock)|disburs\w*)\b|\b(?:upfront|advance) (?:fee|payment|charges?)\b/i;
const LOAN_ACCESS = /\b(?:access|permission|allow)\b[^.\n]{0,30}\b(?:contacts?|contact list|gallery|photos?|camera|sms|location)\b/i;
const LOAN_7DAY = /\b7[\s-]?day(?:s)? (?:loan|tenure|repay\w*)|\brepay\w*[^.\n]{0,15}\bwithin 7 days\b/i;

// ---- fee-before-benefit and who gets the money ----
// A promised benefit (loan, refund, prize, maturity amount, parcel release, job, scholarship ...) that is released only AFTER the reader pays.
const BENEFIT_RE = /\b(?:loan|disburs\w*|sanction\w*|credit limit|refund|prize|lottery|lucky draw|reward|maturity|matured|bonus|claim amount|insurance claim|scholarship|subsidy|grant|pension|compensation|parcel|consignment|shipment|package|gift|cargo|offer letter|appointment|joining|selected|selection|placement|vacancy|recruit\w*|internship|work from home|allotment|dealership|franchise)\b/i;
const ADV_FEE_NOUN_RE = /\b(?:refundable (?:security|deposit|amount)|(?:registration|processing|insurance|clearance|verification|security|training|handling|release|courier|stamp(?: duty)?|re-?verification|legal|activation|admin\w*|noc|tds|gst|customs?|anti[- ](?:money laundering|terror)|certificate|kit|laptop|id[- ]card|uniform)\s+(?:fees?|charges?|deposit|duty|certificate fees?|clearance))\b|\b(?:fees?|charges?|deposit)\b[^.\n]{0,25}\btowards\b[^.\n]{0,40}\b(?:laptop|id[- ]card|kit|training|uniform|insurance|clearance|gst|tds|noc)\b/i;
const FEE_SEQUENCE_RE = /\b(?:to|for|before|in order to|so that)\s+(?:\w+\s+){0,4}?(?:disburs\w*|releas\w*|receiv\w*|claim\w*|unlock\w*|confirm\w*|activat\w*|process\w*|obtain|get|proceed|finali[sz]e|clear\w*|dispatch\w*|deliver\w*|collect\w*)\b|\b(?:after|on|upon|once)\s+(?:the\s+|your\s+)?(?:payment|deposit|fee)\b|\b(?:offer|selection|allotment|sanction|parcel|amount)\b[^.\n]{0,40}\b(?:lapses?|cancel+ed|forfeited|returned|destroyed|auctioned)\b[^.\n]{0,40}\b(?:payment|fee|deposit)\b/i;
// Fees a genuine lender / seller states in the document and settles in a regulated way (deducted from the disbursal, per the schedule of charges / KFS, GST on the fee).
const LEGIT_FEE_RE = /\b(?:deducted|adjusted|recovered)\b[^.\n]{0,40}\b(?:from|out of|against)\b[^.\n]{0,30}\b(?:disbursement|disbursal|loan amount|sanctioned amount|first (?:disbursement|instal+ment))\b|\bas per (?:the )?(?:schedule of charges|key fact statement|kfs|tariff|sanction terms|terms (?:and|&) conditions of (?:the )?sanction|agreement)\b|\bstated in (?:the )?(?:sanction|offer|agreement|schedule)\b|\bgst\b[^.\n]{0,25}\b(?:on|@)\b[^.\n]{0,25}\b(?:processing|fee|charges?)\b|\bno (?:processing|upfront|advance|registration) (?:fee|charges?|payment)\b|\b(?:we|bank|company|employer) (?:never|does not|do not|will not) (?:ask|charge|collect|demand)\b/i;
// The destination of the money: a personal UPI id / wallet / individual's or officer's account, or just "the account below".
const PERSONAL_DEST_RE = /\b(?:officer|manager|agent|clerk|executive|director|inspector|hr|recruiter|individual|employee|staff|representative|supervisor|accountant|registrar|official|person)(?:'s|s')?\s+(?:personal\s+|private\s+)?(?:bank\s+)?(?:a\/c|account|upi|wallet)\b|\b(?:personal|private)\s+(?:bank\s+)?(?:a\/c|account|upi|wallet|number)\b|\b(?:upi|vpa)(?: id| handle)?\s*[:\-]?\s*[\w.\-]{2,40}@[a-z]{2,20}\b|\b[\w.\-]{2,40}@(?:ybl|okhdfcbank|okaxis|oksbi|okicici|paytm|ibl|axl|upi|apl|fbl|waicici|ptyes|ptaxis|pthdfc)\b|\b(?:paytm|phonepe|gpay|google pay|bhim|mobikwik|freecharge|amazon pay)\s+(?:wallet|number|no\.?)\b|\bwallet\b[^.\n]{0,25}\b(?:transfer|pay|send|number|id)\b|\b(?:in|to) (?:the )?name of (?:mr|mrs|ms|shri|smt|sri)\b|\bto (?:our|the) (?:agent|officer|representative)\b/i;
const ACCOUNT_BELOW_RE = /\b(?:account|a\/c)\b[^.\n]{0,20}\b(?:given|mentioned|provided|shared|stated)?\s?below\b|\bbelow (?:account|a\/c)\b|\bthrough the link (?:provided|given|below)\b|\bclick (?:the )?link\b[^.\n]{0,20}\bpay/i;
// Threat words that an agency uses only in coercion scams (not statutory "attachment" / "recovery" language in genuine tax orders).
const ARREST_THREAT_RE = /\barrest(?:ed)?\b|\bwarrant of arrest\b|\bdigital custody\b|\bsurveillance\b|\bpermanently (?:blocked|barred|disconnected|deactivated)\b|\bdisconnect\w*\b/i;
const ADVOCATE_RE = /\b(?:adv\.|advocates?|counsel|attorneys?|law (?:firm|associates|chambers)|(?:&|and) associates|bar council)\b/i;
const FREE_MAIL_RE = /@(?:gmail|yahoo|outlook|hotmail|rediffmail|proton\w*)\.|\bwhatsapp (?:only|number)\b|\bon whatsapp\b/i;

const countMatches = (res, t) => res.filter(re => re.test(t)).length;

// Positive evidence a genuine document usually carries. It never proves authenticity; it only lets the benign score reflect how
// much checkable structure the wording has instead of a flat number.
const EVIDENCE = [
  ['a reference / case / policy number', /\b(?:ref(?:erence)?|case|policy|folio|account|suit|petition|order|circular|file|application|w\.p\.\(?c?\)?)\.?\s*(?:no\.?|number|#)\s*[:.]?\s*[a-z0-9][\w\/.()-]{2,}|\b[a-z]{2,6}\/\d{2,4}[-\/]\d{2,4}\b|\bno\.?\s?\d{2,}\s?(?:of|\/)\s?\d{4}\b/i],
  ['an official domain or helpline reference', /\b[a-z0-9-]+\.(?:gov\.in|nic\.in|org\.in|bank\.in|co\.in|sbi|com)\b|\b1800[\s-]?\d{2,4}[\s-]?\d{3,6}\b|\bnodal officer\b|\bombudsman\b|\bgrievance\b/i],
  ['a statutory section / rule citation', /\b(?:section|sec\.|order [ivxlc]+ rule|rule|regulation|act,? \d{4})\b[^.\n]{0,25}\b\d+[a-z]?(?:\(\d+\))?|\b(?:cpc|crpc|bnss|bns|negotiable instruments act|banking regulation act|income[- ]tax act)\b/i],
  ['a signature / system-generated / office-use block', /\bsd\/-|\bsignature\b|system[- ]generated|authori[sz]ed signatory|for office use|seal of the court|under my hand/i],
  ['a dated, structured header', /\b\d{1,2}[-\/ ](?:[a-z]{3}|\d{1,2})[-\/ ,]+\d{2,4}\b|\bdate(?:d)?\s*:/i],
  ['an explicit "never asks for OTP / PIN / password" safety line', /\b(?:will never|never|do not|does not)\s+ask\b[^.\n]{0,30}\b(?:password|pin|otp)\b/i],
  ['grievance / appeal / rectification route', /\b(?:appeal|rectification|grievance|approach the|contest|objection|redress\w*)\b/i]
];
// Mild wording that is not a verdict but should keep a benign score from being the very lowest.
const MILD = [
  ['urgent wording', DEADLINE_RE],
  ['a payment instruction', /\bpay\b[^.\n]{0,40}\b(?:rs\.?|inr|₹|amount|dues?|bill|premium)\b/i],
  ['a messaging-app / personal e-mail contact', /\bwhatsapp\b|@(?:gmail|yahoo|outlook|hotmail)\./i]
];

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
  const feeDemand = FEE_DEMAND.some(re => re.test(t));
  const credOrOfficer = countMatches(CRED_OR_OFFICER, t);
  const secrecy = SECRECY_RE.test(t);
  const deadline = DEADLINE_RE.test(t);
  const digitalArrest = COERCION_STRONG[0].test(t);
  const authority = agencyIssuer || agencyMention;

  const loanCtx = LOAN_CTX.test(t);
  const upfront = loanCtx && (LOAN_UPFRONT.test(t) || LOAN_UPFRONT_DEDUCT.test(t));
  const access = loanCtx && LOAN_ACCESS.test(t);
  const sevenDay = loanCtx && LOAN_7DAY.test(t);
  const shaming = loanCtx && LOAN_SHAME.test(t);
  const extremeRate = loanCtx && LOAN_EXTREME_RATE.test(t);
  const personalDest = PERSONAL_DEST_RE.test(t);
  const accountBelow = ACCOUNT_BELOW_RE.test(t);
  const legitFee = LEGIT_FEE_RE.test(t);
  const feeDemandAny = FEE_DEMAND.some(re => re.test(t));
  // Fee-before-benefit: the reader must pay first (security deposit, registration / processing / clearance / insurance fee ...) to receive a loan,
  // refund, prize, job, parcel or maturity amount. Genuine fees stated in the document and deducted from the disbursal do not count.
  const feeBeforeBenefit = feeDemandAny && BENEFIT_RE.test(t) && (FEE_SEQUENCE_RE.test(t) || ADV_FEE_NOUN_RE.test(t)) && !legitFee;
  const freeMail = FREE_MAIL_RE.test(t);
  const advocateIssuer = ADVOCATE_RE.test(t) && !ISSUER_RE.test(t);
  // A lawyer's notice for a genuine due: statutory + reference structure, no personal payee, no secrecy, no OTP / escrow.
  const advocateGenuine = advocateIssuer && EVIDENCE.filter(([, re]) => re.test(t)).length >= 2 && !personalDest && !secrecy && credOrOfficer === 0 && payStrong === 0 && !freeMail;
  const loanSignals0 = [upfront, access, sevenDay, shaming, extremeRate].filter(Boolean).length;
  const loanFeeFirst = loanCtx && feeBeforeBenefit;
  const loanSignals = loanSignals0 + (loanFeeFirst && !upfront ? 1 : 0);

  const coercion = coercionStrong ? 2 : (coercionWeak ? 1 : 0);
  const pay = payStrong ? 2 : (payPlain ? 1 : 0);
  // A money demand in the strict sense (not merely the word "payment"), plus the "no real authority does this" extras.
  const demand = feeDemand || payPlain > 0 || payStrong > 0;
  const hardAsk = credOrOfficer > 0 || payStrong > 0;
  const pressure = secrecy || deadline || coercion === 2;

  let verdict = 'GENUINE_LOOKING';
  let subtype = null;
  const reasons = [];
  const warrantForged = (coercion === 2 && pay === 2) || (digitalArrest && pay >= 1) || (coercion === 2 && pay >= 1 && agencyIssuer) || (coercionStrong >= 2 && agencyIssuer && payStrong >= 1) ||
    // an authority that demands money AND (threatens, or demands secrecy / an OTP / a payment to an officer or "clearance" account)
    (authority && feeDemand && coercion === 2 && (secrecy || hardAsk || deadline)) ||
    (authority && feeDemand && secrecy && (hardAsk || deadline || coercion >= 1)) ||
    (authority && feeDemand && credOrOfficer > 0 && coercion >= 1) ||
    (feeDemand && secrecy && coercion === 2);
  const warrantReview = !warrantForged && ((coercion === 2) || (coercion >= 1 && pay >= 1) || (payStrong >= 2) || (payStrong >= 1 && agencyIssuer) ||
    (authority && feeDemand) || (feeDemand && (secrecy || credOrOfficer > 0)));
  const loanForged = loanSignals >= 2 || ((upfront || loanFeeFirst) && loanCtx && (personalDest || /\bguaranteed|pre-?approved|without (?:documents?|cibil|credit (?:check|score|history)|income proof|collateral|guarantor)|no (?:documents?|cibil|credit check)/i.test(t)));
  const loanReview = !loanForged && loanSignals === 1;

  // Authority impersonation + a fee / penalty / "clearance" demand + ANY pressure (secrecy, a deadline of hours or a few days, arrest / disconnection
  // threat, an OTP or payment to an individual) is the scam shape even without escrow wording. An advocate's notice that merely cites a court is not
  // an authority speaking, so it does not take this route.
  const arrestThreat = ARREST_THREAT_RE.test(t);
  const pressureAny = secrecy || deadline || arrestThreat || credOrOfficer > 0 || personalDest;
  const authorityPressure = (authority && !advocateIssuer) && (feeDemandAny || payStrong > 0) && pressureAny && !legitFee;
  // Fee-before-benefit paid to a personal destination (or with a second red flag) in a private / unknown sender's letter.
  const advanceFeeForged = !loanCtx && feeBeforeBenefit && (personalDest || (accountBelow && (deadline || freeMail || payStrong > 0)) || (freeMail && deadline) || payStrong > 0);
  const advanceFeeReview = !advanceFeeForged && !loanCtx && feeBeforeBenefit;
  const agencyTier = authorityPressure && !warrantForged;
  if (warrantForged) { verdict = 'LIKELY_FORGED'; subtype = 'FORGED_WARRANT_OR_AGENCY_NOTICE'; }
  else if (loanForged) { verdict = 'LIKELY_FORGED'; subtype = 'PREDATORY_LENDER'; }
  else if (agencyTier) { verdict = 'LIKELY_FORGED'; subtype = 'FORGED_WARRANT_OR_AGENCY_NOTICE'; }
  else if (advanceFeeForged) { verdict = 'LIKELY_FORGED'; subtype = 'ADVANCE_FEE_LETTER'; }
  else if (warrantReview || loanReview || advanceFeeReview) { verdict = 'NEEDS_REVIEW'; subtype = warrantReview ? 'COERCIVE_OR_PAYMENT_WORDING' : (advanceFeeReview ? 'FEE_BEFORE_BENEFIT' : 'LOAN_RED_FLAG'); }

  if (agencyIssuer) reasons.push('Speaks as a law-enforcement / regulator authority');
  if (coercion === 2) reasons.push('Threatens arrest / warrant / freezing / a criminal case against the reader');
  else if (coercion === 1) reasons.push('Contains legal-action wording');
  if (payStrong) reasons.push('Demands escrow / safe-account / personal-UPI payment or secrecy');
  else if (payPlain || feeDemand) reasons.push('Contains a payment demand');
  if (feeDemand && authority) reasons.push('A government / regulator name is attached to a demand for a fee, penalty or "clearance" payment');
  if (credOrOfficer) reasons.push('Asks for an OTP / screenshot or payment to an officer or "clearance" account');
  if (secrecy && demand) reasons.push('Tells the reader to keep the demand secret');
  if (feeBeforeBenefit && !loanCtx) reasons.push('Demands a fee or deposit before the promised benefit (refund, prize, job, parcel release, maturity amount) is delivered');
  if (personalDest && (feeDemandAny || payStrong)) reasons.push('Payment is to be made to a personal UPI id, wallet or an individual\'s account');
  if (agencyTier) reasons.push('An authority name is combined with a fee demand and pressure (deadline, secrecy, OTP or arrest / disconnection threat)');
  if (upfront || loanFeeFirst) reasons.push('Asks for an upfront fee before loan release');
  if (access) reasons.push('Asks for contacts / gallery / SMS access');
  if (sevenDay) reasons.push('7-day loan tenure wording');
  if (shaming) reasons.push('Threatens to share defaulter details with the borrower\'s contacts');
  if (extremeRate) reasons.push('Per-day interest or late charges');

  // ---- graded score ----
  let riskScore, evidenceFound = [], mildFound = [];
  if (verdict === 'LIKELY_FORGED') {
    const extra = Math.min(6, (coercion === 2 ? 2 : 0) + (secrecy ? 1 : 0) + (hardAsk ? 2 : 0) + (deadline ? 1 : 0));
    if (subtype === 'PREDATORY_LENDER') riskScore = Math.min(98, 88 + loanSignals * 2 + (personalDest ? 2 : 0));
    else if (subtype === 'ADVANCE_FEE_LETTER') riskScore = Math.min(95, 80 + (personalDest ? 4 : 0) + (deadline ? 3 : 0) + (freeMail ? 3 : 0) + (payStrong ? 2 : 0) + (accountBelow ? 1 : 0) + (secrecy ? 2 : 0));
    else if (agencyTier) riskScore = Math.min(89, 72 + (secrecy ? 3 : 0) + (deadline ? 3 : 0) + (arrestThreat ? 3 : 0) + (credOrOfficer ? 3 : 0) + (personalDest ? 2 : 0) + (payStrong ? 2 : 0));
    else riskScore = Math.min(99, 90 + extra);
  } else if (verdict === 'NEEDS_REVIEW') {
    riskScore = 48 + Math.min(10, (demand ? 3 : 0) + (authority ? 2 : 0) + (secrecy ? 2 : 0) + (coercion ? 2 : 0) + (loanSignals ? 1 : 0));
  } else {
    evidenceFound = EVIDENCE.filter(([, re]) => re.test(t)).map(([n]) => n);
    mildFound = MILD.filter(([, re]) => re.test(t)).map(([n]) => n);
    const bare = norm(text).length < 80;
    riskScore = Math.max(4, Math.min(30, 16 - 2 * evidenceFound.length + 3 * mildFound.length + (authority && !evidenceFound.length ? 4 : 0) + (bare ? 4 : 0)));
  }
  // severity ALWAYS follows the verdict
  const severity = verdict === 'LIKELY_FORGED' ? ((subtype === 'PREDATORY_LENDER' || riskScore < 90) ? 'HIGH' : 'CRITICAL') : (verdict === 'NEEDS_REVIEW' ? 'MEDIUM' : 'LOW');

  return {
    verdict, subtype, riskScore, severity,
    signals: {
      agencyIssuer, agencyMention, coercion: coercionStrong ? 'strong' : (coercionWeak ? 'weak' : 'none'),
      payment: payStrong ? 'escrow/safe-account/secrecy' : ((payPlain || feeDemand) ? 'plain' : 'none'), upfrontLoanFee: upfront, contactAccess: access, sevenDayTenure: sevenDay,
      feeDemand, secrecy, credentialOrOfficerPayment: credOrOfficer > 0, shaming, extremeRate, evidence: evidenceFound, mild: mildFound
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
  const forgedAdvance = r.verdict === 'LIKELY_FORGED' && r.subtype === 'ADVANCE_FEE_LETTER';
  const detail = {
    GENUINE_LOOKING: 'No coercion + payment co-occurrence and no loan red flags in the wording. This does not prove the document is genuine.',
    NEEDS_REVIEW: `Some risky wording was found (${r.reasons.join('; ') || 'see signals'}) but not the full forged-notice pattern. Verify with the issuer.`,
    LIKELY_FORGED: `${r.reasons.join('; ')}. ${forgedWarrant ? 'Indian law-enforcement agencies never demand fund transfers or keep you on a video call.' : (forgedAdvance ? 'Genuine employers, lenders, insurers and government bodies do not ask you to pay a fee or deposit to a personal account before releasing a benefit.' : 'This matches predatory-lending patterns.')}`
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
        detail: forgedWarrant ? 'Digital arrest has no basis in BNSS/CrPC.' : (forgedLoan ? 'Contact/gallery harvesting and upfront fees are prohibited under the RBI 2022 Digital Lending guidelines.' : forgedAdvance ? 'Advance fees for loans, jobs, refunds and prizes are the core of cheating by personation; no regulator requires them.' : 'Seal/signature and issuer-registry verification are not performed by this tool.') }
    ],
    legalCitations: forgedWarrant ? ['BNSS Section 105', 'IT Act Section 66D', 'BNS Section 318 (Cheating)'] : forgedAdvance ? ['IT Act Section 66D', 'BNS Section 318 (Cheating)'] : ['RBI Fair Practices Code', 'IT Act Section 43/66'],
    recommendedAction: forgedWarrant ? 'CRITICAL: Do NOT pay any money. Disconnect the call immediately and dial 1930.'
      : forgedAdvance ? 'ADVANCE-FEE SCAM: Do NOT pay any fee, deposit or "clearance" charge to a UPI id, wallet or personal account. Verify the sender using a number or website you find yourself, and report to 1930.'
      : forgedLoan ? 'PREDATORY LENDER: Do NOT pay fees or grant contact / gallery permissions. Report to RBI CMS (cms.rbi.org.in).'
      : r.verdict === 'NEEDS_REVIEW' ? 'Do not pay or share anything yet. Verify this document directly with the issuing bank / court / agency using an independently sourced number.'
      : 'No scam wording detected, but verify any official document directly with the issuing institution.'
  } };
}

module.exports = { triage, buildResponse, VERDICT_LABEL };

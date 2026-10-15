'use strict';
/**
 * SafeMeAI multi-signal TEXT scam engine (server-side port of the Android detectors:
 * DigitalArrestDetector, UpiCollectDetector, LoanHarassmentDetector, MuleTaskDetector,
 * SextortionDetector, InvestmentScamDetector, AIAnalyzer keyword groups).
 *
 * Design:
 *  - normalise (NFKC, zero-width/bidi strip, de-spacing, de-leet, defang) so obfuscation does not evade rules
 *  - every signal is scored independently; categories accumulate, shared modifiers (urgency, threat,
 *    call-to-action, payment demand, secrecy, authority) amplify -> no first-match-wins
 *  - conservative default: an unknown message with a link / mobile number / urgency is never SAFE
 *  - SAFE is only issued to a recognised genuine transactional pattern that carries NO call-to-action
 */

const ZERO_WIDTH = /[­͏؜ᅟᅠ឴឵᠋-᠎​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]/g;

/** Lightweight normalisation used for URL extraction (keeps spacing, defangs obfuscated URLs). */
function normalizeForUrls(s) {
  let t = String(s || '').normalize('NFKC').replace(ZERO_WIDTH, '');
  t = t.replace(/\bhxxps?:\/\//gi, m => m.toLowerCase().replace('xx', 'tt'))
       .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/g, '.')
       .replace(/\[\s*dot\s*\]|\(\s*dot\s*\)/gi, '.')
       .replace(/(\w)\s+dot\s+(?=[a-z0-9-]+\s*(?:\.|\/|$|\s))/gi, '$1.')
       .replace(/(\w)\s*\[\s*:\s*\]\s*\/\//g, '$1://');
  // "bit . ly / abc" -> "bit.ly/abc" only for the well known shorteners / TLD-ish tails
  t = t.replace(/\b([a-z0-9-]{2,})\s*\.\s*(ly|gl|co|in|com|app|link|me|cc|xyz|top|click|ink|ee|to)\b(?=\s*\/)/gi, '$1.$2');
  return t;
}

const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i', '€': 'e', '£': 'l' };

/** Full normalisation for rule matching. Returns {t, deleet, squashed} (all lowercase). */
function normalizeText(s) {
  let t = String(s || '').normalize('NFKC').replace(ZERO_WIDTH, '');
  t = t.replace(/[‘’‛]/g, "'").replace(/[“”]/g, '"').replace(/[–—−]/g, '-');
  t = t.toLowerCase();
  // collapse letter-spaced words: "k y c", "k.y.c", "a-n-y-d-e-s-k", "o t p"
  t = t.replace(/(?<![a-z0-9])(?:[a-z][\s.\-_*,|]{1,2}){2,}[a-z](?![a-z0-9])/g, m => m.replace(/[\s.\-_*,|]/g, ''));
  // spaced Devanagari is rare; skip. Defang URLs.
  t = normalizeForUrls(t).toLowerCase();
  t = t.replace(/[ \t ]+/g, ' ');
  // de-leet: only inside tokens that mix letters and leet chars (keeps real numbers/amounts intact)
  const deleet = t.replace(/[a-z0-9@$!€£]{3,}/g, tok => {
    if (!/[a-z]/.test(tok) || !/[0134@$57!€£]/.test(tok)) return tok;
    if (/^\d/.test(tok) && /^\d+[a-z]{0,3}$/.test(tok)) return tok; // 5000rs, 3pm
    if (/@/.test(tok) && /^[\w.\-]+@[a-z]+$/.test(tok) && !/^[a-z]+@[a-z]+$/.test(tok)) return tok; // likely UPI id
    return tok.replace(/[0134@$57!€£]/g, c => LEET[c]);
  });
  const squashed = t.replace(/[^a-z0-9ऀ-ॿ]+/g, '');
  return { t, deleet, squashed };
}

// ---------------------------------------------------------------------------
// Signal tables.  w = weight toward category score.
// ---------------------------------------------------------------------------
const NUM = String.raw`(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}`;
const MOBILE_RE = new RegExp(String.raw`(?<![\d])(?:\+?91[\s-]?)?0?[6-9]\d{4}[\s-]?\d{5}(?![\d])`);
const TOLLFREE_RE = /\b(?:1800[\s-]?\d{2,4}[\s-]?\d{3,6}|1860[\s-]?\d{3}[\s-]?\d{4}|1930|1947|1912|112|155260|14\d{3}|139|100)\b/;

const CATS = {
  digital_arrest: {
    name: 'Digital Arrest Extortion (Central Agency Impersonation)', base: 99,
    headline: '🚨 EXTREME DANGER: Digital Arrest Cybercrime Detected!',
    desc: "Fraudsters pose as CBI / Police / Customs / ED / TRAI to frighten victims with a fake case and extort money. 'Digital arrest' does not exist in Indian law.",
    advice: ['🚨 HANG UP IMMEDIATELY. Disconnect Skype / WhatsApp video call.', '🛑 No police, court or agency arrests anyone over a video call or demands money.', '📞 Dial 1930 (National Cyber Crime Helpline) or report at cybercrime.gov.in.'],
    law: 'BNSS 2023 & IT Act Section 66D (Cheating by Impersonation)'
  },
  upi_collect: {
    name: 'UPI Collect Inversion / PIN Trap Scam', base: 96,
    headline: '⚡ CRITICAL FRAUD: Attempt to Drain Bank Account via UPI PIN / Collect Request',
    desc: "You never need a PIN, QR scan or 'approval' to RECEIVE money. Entering a UPI PIN always sends money out.",
    advice: ['🛑 DO NOT enter your UPI PIN or scan any QR to receive money.', '❌ Decline the collect request on GPay / PhonePe / Paytm.', '📞 Report the UPI ID to 1930.'],
    law: 'NPCI UPI Safety Guidelines & RBI Master Directions on Fraud Prevention'
  },
  upi_handle: {
    name: 'Fake Authority / Suspicious UPI Handle', base: 90,
    headline: '🚨 FRAUDULENT UPI HANDLE: Fake Authority or Refund Desk',
    desc: 'The UPI ID uses authority / refund / support words. Police, RBI, courts, banks and refund desks never collect money on personal UPI handles.',
    advice: ['🛑 DO NOT send money to this UPI ID.', '🛑 Decline any collect request from it.', '📞 Report this UPI ID to 1930.'],
    law: 'NPCI UPI Security Guidelines & PMLA Section 3'
  },
  kyc: {
    name: 'Banking / SIM / PAN KYC Suspension Threat', base: 94,
    headline: '⚠️ DANGER: Coercive KYC / Account or SIM Deactivation Scam',
    desc: 'Scammers threaten that your bank account, card, PAN, Aadhaar or SIM will be blocked unless you click a link, call a number or install an app.',
    advice: ['🛑 DO NOT click links or call numbers in the message.', '✅ Open your bank app or visit the branch directly.', '🛡️ Banks and telecom operators never ask for KYC via SMS links.'],
    law: 'RBI Master Direction on KYC & IT Act 66D'
  },
  electricity: {
    name: 'Fake Electricity / Utility Disconnection Scam', base: 95,
    headline: '⚠️ HIGH FRAUD RISK: Fake Utility Disconnection / Subsidy Notice',
    desc: 'Mass SMS threatening a night-time power cut (or promising free bijli) to push you into calling a scammer, paying on a link or installing an APK.',
    advice: ['🛑 Do NOT call the number or open the link.', '🛑 DISCOMs never disconnect power over SMS or a personal mobile number.', '✅ Check your bill only on the official DISCOM portal / app.'],
    law: 'Electricity Act 2003 & IT Act 66D'
  },
  loan: {
    name: 'Predatory Instant Loan / Harassment App', base: 92,
    headline: '⚠️ DANGER: Illegal Loan App / Loan Harassment Trap',
    desc: 'Unregulated loan apps take upfront fees, demand contacts/gallery access and blackmail borrowers with morphed photos and calls to relatives.',
    advice: ['🛑 Never install loan APKs from SMS / WhatsApp links.', '🛑 Never pay an upfront processing fee for a loan.', '✅ Borrow only from RBI-registered lenders. Report harassment to 1930.'],
    law: 'RBI Digital Lending Guidelines (2022) & BNS Section 351'
  },
  task_job: {
    name: 'Telegram Task / Fake Job / Money Mule Recruitment', base: 90,
    headline: "⚠️ FRAUDULENT LURE: 'Part-Time Job / Task / Review' Scam",
    desc: 'Small initial payouts bait victims into prepaid tasks and deposits, or into receiving and forwarding money, which implicates them as money mules.',
    advice: ['🛑 Exit and block the group / sender.', '🛑 Genuine employers never ask you to deposit money to work.', '📞 Report to 1930.'],
    law: 'PMLA Section 3 & IT Act 66D'
  },
  investment: {
    name: 'Investment / Crypto / Stock-Tip Fraud', base: 92,
    headline: '🚨 INVESTMENT FRAUD: Guaranteed Returns / Fake Trading Group',
    desc: "Guaranteed or daily returns, 'sure-shot' tips, VIP trading groups and 'tax to withdraw' demands are hallmarks of investment fraud. No regulated entity guarantees returns.",
    advice: ['🛑 Do not deposit money or install trading APKs from chats.', '✅ Verify advisers on the SEBI website (sebi.gov.in).', '📞 Report to 1930.'],
    law: 'SEBI Act 1992 & IT Act 66D'
  },
  sextortion: {
    name: 'Cyber Sextortion & Morphed Video Blackmail', base: 97,
    headline: '🚨 BLACKMAIL THREAT: Sextortion / Video Extortion',
    desc: 'Fraudsters threaten to leak recorded or morphed videos to your contacts unless you pay.',
    advice: ['🛑 DO NOT PAY. Payment invites repeated demands.', '🔒 Lock down social media profiles and save evidence.', '📞 Call 1930 / cybercrime.gov.in; use StopNCII.org for intimate imagery.'],
    law: 'IT Act 66E / 67A & BNS Section 308 (Extortion)'
  },
  courier: {
    name: 'Fake Courier / Customs / India Post Parcel Scam', base: 94,
    headline: '🚨 CRITICAL FRAUD: Fake Courier / Customs / Parcel Notice',
    desc: 'A parcel is said to be held, illegal or undeliverable so you will pay a fee, update an address on a link or speak to a fake officer.',
    advice: ['🛑 Do not click links or pay fees for a parcel you did not expect.', '✅ Track only on the courier’s official site / app.', '🛡️ Block the sender and report to 1930.'],
    law: 'Indian Post Office Act & IT Act 66D'
  },
  challan: {
    name: 'Fake Traffic e-Challan Phishing', base: 93,
    headline: '⚠️ HIGH FRAUD RISK: Fake Traffic Challan Notice',
    desc: 'Fake challan SMS lead to cloned payment pages. Real challans are paid only on echallan.parivahan.gov.in.',
    advice: ['🛑 Never pay a challan on a link from an SMS.', '✅ Check at https://echallan.parivahan.gov.in.', '🛡️ Delete and block.'],
    law: 'Motor Vehicles Act 2019 & IT Act 66D'
  },
  lottery: {
    name: 'Counterfeit Reward / Lottery / KBC Scam', base: 90,
    headline: '⚠️ PHISHING LURE: Fake Prize, Lottery or Reward Points',
    desc: "Unsolicited prizes require 'fees', 'tax' or card / bank details. Genuine banks never send reward-redeem links.",
    advice: ['🛑 Never pay a fee to claim a prize.', '🛑 Do not click redeem / claim links.', '🛡️ Block the sender.'],
    law: 'Lotteries (Regulation) Act & IT Act 66D'
  },
  remote_access: {
    name: 'Remote Access Screen-Takeover (AnyDesk/TeamViewer)', base: 98,
    headline: '🚨 EXTREME DANGER: Remote Access App Trap',
    desc: 'Fraudsters make victims install a screen-sharing tool to read OTPs and empty bank accounts.',
    advice: ['🛑 NEVER install AnyDesk / TeamViewer / QuickSupport on a caller’s request.', '🛑 Disconnect any active session; turn on Airplane Mode.', '📞 Call your bank and 1930 immediately.'],
    law: 'IT Act Section 43/66 (Unauthorized Access)'
  },
  credential: {
    name: 'OTP / PIN / Card Credential Theft', base: 92,
    headline: '🚨 CREDENTIAL THEFT: Message asks for OTP / PIN / CVV',
    desc: 'Nobody genuine ever asks you to share an OTP, UPI PIN, CVV or password by message or call.',
    advice: ['🛑 Never share OTP, PIN, CVV or passwords with anyone.', '✅ If in doubt, hang up and call the number printed on your card.', '📞 Report to 1930.'],
    law: 'IT Act 66C/66D & RBI Customer Liability Circular'
  },
  fake_support: {
    name: 'Fake Customer-Care / Fake Transaction Alert Callback', base: 88,
    headline: '⚠️ FAKE SUPPORT: Callback number or link in a transaction / support message',
    desc: 'Scam messages mimic debit alerts or support notices and push you to call a personal mobile number or open a link.',
    advice: ['🛑 Do not call numbers or open links in the message.', '✅ Use the customer-care number on your card or the official app.', '📞 Report to 1930.'],
    law: 'IT Act 66D (Cheating by Personation)'
  },
  qr: {
    name: 'QR Code Payment Trap', base: 90,
    headline: '⚠️ QR SCAM: Scanning a QR sends money out',
    desc: 'Scanning a QR code and entering your PIN always debits your account. It can never be used to receive money.',
    advice: ['🛑 Do not scan QR codes sent by strangers.', '🛑 Never enter UPI PIN to receive money.', '📞 Report to 1930.'],
    law: 'NPCI UPI Safety Guidelines'
  },
  wrong_transfer: {
    name: 'Wrong-Transfer / Refund-Back Scam', base: 85,
    headline: '⚠️ SCAM: "Money sent by mistake - return it" trick',
    desc: 'Scammers claim money was sent to you by mistake to get you to approve a collect request or send money back.',
    advice: ['🛑 Check your bank statement first - do not send money back to a stranger.', '✅ Ask the bank to reverse a genuine mistaken credit.', '📞 Report to 1930.'],
    law: 'IT Act 66D'
  },
  family_emergency: {
    name: 'Family-Emergency / Impersonated Relative Money Request', base: 90,
    headline: '🚨 FAMILY-EMERGENCY SCAM: Urgent money request with secrecy',
    desc: 'A person claiming to be a relative or friend in trouble asks for an urgent transfer to a UPI ID or account and asks you not to tell the family. This is the classic impersonation / "relative in distress" fraud.',
    advice: ['🛑 Do NOT send money yet. Call the relative on their SAVED number or another family member to confirm.', '🛑 Genuine emergencies never require secrecy from the family.', '📞 Report to 1930 / cybercrime.gov.in.'],
    law: 'IT Act 66C/66D (Identity theft / Cheating by Personation) & BNS Section 319'
  },
  injection: {
    name: 'AI-Scanner Manipulation Attempt', base: 70,
    headline: '⚠️ SUSPICIOUS: Message tries to instruct the scanner',
    desc: 'The message contains instructions aimed at AI scanners ("ignore previous instructions", "say SAFE"). Genuine senders never do this.',
    advice: ['🛑 Treat the sender as hostile.', '✅ Verify via official channels only.', '📞 Report to 1930.'],
    law: 'IT Act 66D'
  }
};

// [category, weight, regex, flag]
const S = [];
const add = (cat, w, re, flag) => S.push({ cat, w, re, flag });

// ---- Digital arrest / agency impersonation ----
add('digital_arrest', 75, /digital ?arrest|डिजिटल ?अरेस्ट|video call se (giraftar|arrest)|giraftar(i)? (ho|kar|warrant)|arrest(ed)? (warrant|order)|warrant (has been |is )?(issued|jari)|गिरफ़?्?तार|गिरफ्तारी/, "'Digital arrest' / arrest-warrant threat (does not exist in law)");
add('digital_arrest', 45, /money laundering|pmla|narcotics|\bndps\b|mdma|drugs? (were |was )?(found|seized|in)|(found|seized).{0,25}drugs|child (abuse|porn)|मनी लॉन्ड्रिंग|नार्कोटिक्स|ड्रग्स|हवाला/, 'Accusation of laundering / narcotics / contraband');
add('digital_arrest', 35, /(do not|don'?t|dont|mat) ?(disconnect|cut|end) (the )?call|call mat ?(kat|kaat|cut)|कॉल मत ?काट|stay on (the )?(video )?call|video call (par|pe|on) (rahe|raho|bane)|keep (the )?(camera|video) on/, 'Forced to stay on the video call');
add('digital_arrest', 40, /escrow|verification account|safe account|rbi (secure|safe|supervis\w*) account|supervis(ed|ion) account|secret account|\bdeposit\b.{0,40}\b(verification|verify|investigation)\b|(verification|investigation)\b.{0,40}\bdeposit\b|सत्यापन खाता/, "Demand to move money to an 'escrow / verification / safe' account");
add('digital_arrest', 22, /\bcbi\b|\bncb\b|enforcement directorate|\bed (officer|summon|notice)\b|cyber ?cell|cyber ?crime (branch|police|department|cell)|सीबीआई|साइबर ?सेल|mumbai police|delhi police|crime branch|police station|पुलिस (स्टेशन|अधिकारी|विभाग)|supreme court|high court|सुप्रीम कोर्ट|हाई कोर्ट|\btrai\b|customs (officer|department|ne)|income tax (officer|department)/, 'Impersonation of police / CBI / ED / court / TRAI / customs');
add('digital_arrest', 28, /aadhaa?r.{0,30}(misused|used in|linked to|involved|illegal|fraud|crime|case)|(sim|number|mobile).{0,30}(used in|involved in|linked to).{0,25}(crime|fraud|illegal|case|harass)|आधार.{0,25}(गलत|अवैध|केस|मामले)|(case|fir|complaint) (has been |is |will be )?(registered|filed|lodged)|fir (darj|दर्ज)|आपके (नाम|खिलाफ).{0,30}(केस|मामला|fir|शिकायत)|आपके नाम.{0,30}पार्सल/, 'Claim that your Aadhaar / SIM / name is tied to a crime or FIR');
add('digital_arrest', 20, /\bskype\b|surveillance|(stay|remain) (at )?home|isolate|investigation (is )?(going|ongoing|under)|जांच/, 'Coercive surveillance / isolation / investigation language');

add('digital_arrest', 60, /(your |aapka |aapke |आपका |आपके )?(son|daughter|husband|wife|brother|sister|father|mother|beta|beti|relative|बेटा|बेटी|पति|भाई)[^.\n]{0,40}(arrest|accident|custody|detained|hospital|rape|case|पकड़|गिरफ्तार|हादसा)[^.\n]{0,80}(send|pay|transfer|deposit|upi|bhej|भेज|जमा|paise|₹|rs)/, 'Family-emergency / custody extortion: relative "arrested", money demanded');
// ---- UPI collect / QR ----
add('upi_collect', 70, /(enter|share|send|type|put|daalo|dalo|डालो|डालें|बताएं|bhejo)[^.\n]{0,25}(upi ?pin|m-?pin|\bpin\b|पिन)[^.\n]{0,30}(receive|to get|paane|lene|prapt|मिलेंगे|पाने|पैसे)|(receive|get|credit|refund|cashback|paise)[^.\n]{0,30}(enter|share|put|daalo|dalo|डालो|डालें)[^.\n]{0,15}(upi ?pin|m-?pin|\bpin\b|पिन)|pin (daalo|dalo|dalen)[^.\n]{0,20}(paise|aayenge|aayega)|paise lene ke liye (upi |m)?pin|पैसे (लेने|पाने) के लिए (यूपीआई )?पिन/, 'Asks for UPI PIN to RECEIVE money (impossible - PIN only sends money)');
add('upi_collect', 65, /collect request|collect req|money request|payment request|request money|approve (the |this |my )?(request|collect|payment)|accept (the |this |my )?(request|collect|payment)|(request|collect).{0,25}(approve|accept)|रिक्वेस्ट.{0,20}(एक्सेप्ट|स्वीकार|अप्रूव)|request (accept|approve) kar/, 'Asks you to approve / accept a UPI collect request');
add('upi_collect', 55, /pay (rs\.?|₹)?\s?\d*\s?to receive|refund only if you pay|refund ke liye (₹|rs\.?)? ?1\b|scan (karke|kar ke) paise|कैशबैक.{0,25}(पिन|स्कैन)|रिफंड.{0,25}(पिन|स्कैन|एक्सेप्ट)/, "'Pay to receive' / token-payment refund trick");
add('upi_collect', 25, /refund (approved|initiated|pending|processed|is ready|will be)|cashback (credited|ready|pending|of)|reverse payment|refund desk|gpay refund|phonepe refund|रिफंड/, 'Refund / cashback bait');
add('upi_collect', 70, /(upi ?pin|m-?pin|\bpin\b|पिन)[^.\n]{0,20}(daalo|dalo|daal do|dalen|daliye|enter|डालो|डालें|share|bhejo|dijiye)[^.\n]{0,40}(receive|paane|lene|prapt|karne ke liye|paise|पाने|लेने|रिसीव)/, 'Asks for UPI PIN to RECEIVE money (impossible - PIN only sends money)');
add('qr', 55, /scan (this |the |my |below |attached )?(qr|code|barcode)|qr ?(code )?(scan|to (receive|get|claim|refund))|क्यूआर.{0,20}(स्कैन)|स्कैन (करें|करो|कीजिए)/, 'Asks you to scan a QR code');
add('upi_collect', 30, /\bm-?pin\b|upi ?pin|यूपीआई ?पिन|एमपिन/, 'Mentions UPI PIN / MPIN', );

// ---- KYC / SIM / PAN / account block ----
add('kyc', 40, /\bkyc\b|केवाईसी|ckyc/, 'KYC mentioned');
add('kyc', 55, /(account|a\/c|card|sim|number|pan|aadhaar|aadhar|netbanking|net banking|wallet|upi|paytm|fastag|demat|mobile service|connection|services?)[^.\n]{0,40}(block|suspend|deactivat|disconnect|freez|frozen|clos(e|ed|ure)|expire|invalid|lapse|terminat|inactive|restrict|cancel|band ho|ब्लॉक|बंद|निलंबित|समाप्त)|(block|suspend|deactivat|disconnect|freez|expire|lapse|terminat|cancel)[^.\n]{0,25}(account|a\/c|card|sim|number|pan|aadhaar|aadhar|netbanking|wallet|upi|fastag)/, 'Threat that account / card / SIM / PAN will be blocked or expire');
add('kyc', 40, /(pan|aadhaa?r|आधार|पैन)[^.\n]{0,25}(update|link|verify|expire|invalid|lapse|अपडेट|लिंक|सत्यापित)|(update|link|verify|अपडेट|लिंक)[^.\n]{0,15}(pan|aadhaa?r|आधार|पैन)/, 'Asks to update / link PAN or Aadhaar');
add('kyc', 40, /(mobile|sim|phone) number[^.\n]{0,30}(disconnect|block|suspend|deactivat)|sim (will be |is )?(block|deactivat|disconnect|suspend)|trai[^.\n]{0,40}(notice|disconnect|block|illegal|complaint)|(your )?number (will be )?(disconnect|suspend|block)(ed)?|सिम.{0,15}(बंद|ब्लॉक)|नंबर.{0,20}(बंद|ब्लॉक)/, 'SIM / mobile-number disconnection threat');
add('kyc', 25, /(update|verify|complete|renew|submit|re-?do|karo|karein|kare|करें|कराएं|कीजिए|करो).{0,20}(kyc|केवाईसी|pan|aadhaa?r|account|details|documents?|identity)|avoid (deactivation|suspension|block\w*)|verify identity/, 'Pushes urgent KYC / identity re-verification');
add('kyc', 20, /dear (customer|user|sir|madam|valued|account holder)|प्रिय (ग्राहक|उपयोगकर्ता)|ग्राहक महोदय/, 'Generic greeting (mass-mailed)');
add('kyc', 25, /(netbanking|net banking|internet banking|credit card|debit card|rewards?|reward points).{0,40}(expire|lapse|block|redeem)|(expire|lapse).{0,40}(reward|points)/, 'Reward points / banking access about to expire');

// ---- Electricity / utility ----
add('electricity', 22, /electricity|bijli|बिजली|power (supply|connection)|\bdiscom\b|\bmseb\b|\bbses\b|\btneb\b|\bbescom\b|\bmeter\b|मीटर/, 'Electricity / utility theme');
add('electricity', 60, /(electricity|bijli|बिजली|power|connection|meter|supply|कनेक्शन)[^.\n]{0,60}(disconnect|cut|kat|band|off|tonight|suspend|terminat|कट|कटेगा|कटने|काट|बंद|रात)|(disconnect|cut|कट|काट)[^.\n]{0,40}(electricity|bijli|बिजली|power|connection|कनेक्शन)|bill[^.\n]{0,40}(unpaid|not (been )?(updated|paid)|pending|overdue|बकाया|अपडेट)[^.\n]{0,60}(disconnect|cut|tonight|kat|कट|बंद)/, 'Night-time / imminent power-cut threat');
add('electricity', 40, /(electricity|bijli|बिजली|power)[^.\n]{0,40}(officer|ऑफिसर|अधिकारी|executive|engineer|jen\b)|(officer|executive|engineer|अधिकारी)[^.\n]{0,40}(call|contact|संपर्क)/, 'Asks you to call an "electricity officer" on a personal number');
add('electricity', 55, /(free|muft|मुफ्त|मुफ़्त)[^.\n]{0,25}(bijli|electricity|units?|power|बिजली)|(bijli|electricity|बिजली)[^.\n]{0,25}(free|muft|subsid|yojana|योजना|मुफ्त)|pm (surya|bijli)|solar subsidy/, 'Fake free-electricity / subsidy scheme bait');
add('electricity', 25, /tonight|9[:.]?30 ?(pm|baje)|आज रात|aaj raat|raat (ko|tak)|by (8|9|10|11)(:\d\d)? ?(pm|p\.m)/, 'Specific night-time deadline');

// ---- Predatory loan / harassment ----
add('loan', 30, /instant loan|quick loan|easy loan|personal loan|pre-?approved loan|loan (approved|sanction|offer|app|ready)|sanctioned|\blone? (mil|milega|approved)|लोन|कर्ज|ऋण|no cibil|without cibil|cibil (not|nahi)|no documents?|bina document/, 'Unsolicited instant / pre-approved loan offer');
add('loan', 55, /(processing|insurance|gst|file|stamp|registration|documentation|verification|upfront|advance|service) (fee|charge|amount|payment)s?[^.\n]{0,60}(loan|disburs|release|credited)|(loan|disburs)[^.\n]{0,60}(processing|insurance|gst|file|stamp|registration|upfront|advance) (fee|charge)|loan[^.\n]{0,60}(pay|deposit|send|bhej|भेज|जमा)[^.\n]{0,25}(₹|rs\.?|inr|\d{3,})|लोन.{0,40}(फीस|शुल्क|चार्ज)/, 'Upfront fee demanded before loan disbursal');
add('loan', 70, /call (your |all )?(contacts|relatives|family|friends)|contacts? (ko|list)[^.\n]{0,20}(call|bhej|message)|(photo|photos|picture|video)[^.\n]{0,30}(bhej|send|viral|leak|circulate)[^.\n]{0,25}(contacts|family|relatives|friends|rishtedaar)|morphed (photo|picture)|gallery photo|family ko (bhej|bata|send)|recovery agent|loan app (will )?leak|defaulter|नंबर.{0,25}(वायरल|रिश्तेदार)|रिश्तेदारों|कॉन्टैक्ट्स/, 'Loan-recovery harassment / blackmail language');
add('loan', 35, /(contact|contacts|gallery|photos?|camera|sms|location)[^.\n]{0,20}(access|permission|allow)|allow (access|permission)|7[- ]?(day|din)s? (loan|tenure|repay)|repay(ment)? (in |within )?7 days/, 'Intrusive app permissions / 7-day tenure');

// ---- Task / job / mule ----
add('task_job', 30, /part[- ]?time|work from home|\bwfh\b|ghar baithe|घर बैठे|online (job|work|task)|data entry|telecaller|हायरिंग|नौकरी|जॉब|वर्क फ्रॉम होम|पार्ट टाइम/, 'Unsolicited job / work-from-home offer');
add('task_job', 45, /(earn|income|salary|kamao|kamaye|कमाएं|कमाओ|कमाई|payment|payout|paid)[^.\n]{0,25}(₹|rs\.?|inr)?\s?\d[\d,]*\s?(\/|per|a|se|to|-|–)?\s?(day|daily|din|hour|week|roz|रोज|प्रतिदिन|दिन)|(₹|rs\.?)\s?\d[\d,]*\s?(\/|per|a)\s?(day|daily|hour)|daily (income|payout|salary|payment|earning)|रोज(़)? ?(₹|रु)?\s?\d{3,}|हर दिन.{0,15}\d{3,}/, 'Unrealistic daily income promise');
add('task_job', 45, /(kamayen|kamao|kamaye|kamai|kamana)[^.\n]{0,30}\d{3,}|\d{3,}\s*(rupay|rupee|rupaye|rs\.?|rupees)[^.\n]{0,10}(roz|daily|din|har din)|(video|videos|reel|reels)s? (like|subscribe|rate|review) (karna|karo|karein)|sirf (like|video|review)/, 'Hinglish daily-earning / like-video task bait');
add('task_job', 35, /telegram|whatsapp group|t\.me\/|join (our |my |the )?(group|channel)|टेलीग्राम|व्हाट्सएप ग्रुप/, 'Funnels you into Telegram / WhatsApp group');
add('task_job', 45, /(like|subscribe|rate|review|follow|share|watch)[^.\n]{0,20}(youtube|videos?|hotels?|products?|channel|reels?|maps|google)|task job|telegram task|\btasks?\b|google maps review|hotel (rating|review)|लाइक|सब्सक्राइब|रेटिंग/, 'Paid like / subscribe / review "task" work');
add('task_job', 65, /(prepaid|merchant|vip|deposit|recharge|advance|stake)[^.\n]{0,25}(task|order|level|deposit)|(deposit|invest|pay|send)[^.\n]{0,40}(task|to (unlock|activate|withdraw)|get (commission|profit|bonus))|prepaid task|merchant task|मर्चेंट|डिपॉजिट|जमा करें.{0,25}(कमीशन|टास्क)/, 'Asks for deposit / prepaid task money to unlock earnings');
add('task_job', 70, /(receive|accept) (and |&)?(forward|transfer|send)|forward the amount|keep (5|10|2|3|1)\s?%|commission (of )?(\d+\s?%|rakh|milega|mile)|commission rakh lo|paise receive karke|account (mein|me) (aayega|aaye)[^.\n]{0,15}(bhej|forward)|apna (bank )?account (de|do|dena|rent|kiraye)|rent (your|ur) (bank )?account|account rent|खाता.{0,20}(किराए|कमीशन)/, 'Mule pitch: receive money in your account, keep a cut, forward the rest');
add('task_job', 20, /hr (manager|team|executive|department)|hiring|vacancy|job offer|offer letter|selected for/, 'Unsolicited recruiter contact');

// ---- Investment / crypto / stock tips ----
add('investment', 65, /guarant(ee|eed|y)[^.\n]{0,15}(return|profit|income|gain|munafa|payout)|(return|profit)s?[^.\n]{0,10}guarant|assured (return|profit)|risk[- ]?free (return|profit|trading|invest)|100\s?% (return|profit|safe|guarantee|sure)|sure[- ]?shot|multibagger|jackpot (stock|call)|fixed (return|profit)|गारंटी(ड)?|पक्का मुनाफ़?ा|सुनिश्चित (रिटर्न|लाभ)/, 'Guaranteed / risk-free returns (illegal claim)');
add('investment', 60, /(daily|per day|every day|har din|roz|रोज|प्रतिदिन|weekly|monthly|per month|हर दिन)[^.\n]{0,20}\d{1,3}\s?%|\d{1,3}\s?%[^.\n]{0,20}(daily|per day|every day|per week|weekly|a day|हर दिन|रोज)|double (your|the) (money|investment)|paise double|पैसे डबल|(₹|rs\.?)\s?\d[\d,]*\s?(becomes|ban(ega|jayega)|=>?|to)\s?(₹|rs\.?)\s?\d{5,}/, 'Unrealistic daily / weekly return promise');
add('investment', 40, /stock (tip|call|market tips?)|share market (tips?|group|course)|trading (group|signals?|tips?|course|app|platform)|(vip|premium|free|paid)[^.\n]{0,15}(group|channel|calls?|tips)|intraday|option(s)? (calls?|tips|trading)|nifty (tips|calls?)|insider (info|tip)|ipo (allot|allocation|quota|tips)|pre-?ipo|block deal|institutional (account|trading)|स्टॉक टिप|शेयर बाजार|ट्रेडिंग|निवेश/, 'Stock-tip / trading-group / IPO-quota bait');
add('investment', 40, /crypto|bitcoin|\busdt\b|\bbtc\b|ethereum|binance|forex|\bnft\b|क्रिप्टो|बिटकॉइन/, 'Crypto / forex bait');
add('investment', 70, /(pay|clear|deposit|submit|send)[^.\n]{0,15}(tax|gst|tds|verification fee|processing fee|charges?|fees?|commission)[^.\n]{0,30}(withdraw|release|profit|funds|payout|credit)|(tax|gst|fee|charge)s?[^.\n]{0,25}(to withdraw|before withdraw|for withdraw)|withdraw(al)?[^.\n]{0,25}(blocked|fail|hold|stuck|pending|on hold)[^.\n]{0,40}(tax|gst|fee|deposit|pay)|withdrawal ke liye|nikalne ke liye (gst|tax)|gst bharo|tax bharo|निकालने के लिए/, "'Pay tax / GST / fee to withdraw your profit' trap");
add('investment', 35, /sebi (registered|approved|certified)|registered with sebi|profit screenshot|p&l|pnl|wealth ?(manager|advisor)|professor|mentor|analyst (group|team)|(admin|assistant) (will|ne) add/, 'Unverifiable SEBI / mentor / profit-screenshot claims');
add('investment', 30, /(invest|deposit|trade|trading)[^.\n]{0,40}(and |&|,)?[^.\n]{0,10}(earn|get|profit|return|double|triple|munafa|कमाएं|कमाओ|लाभ)|(earn|get|profit|return|double)[^.\n]{0,30}(invest|deposit|trading)/, 'Invest-and-earn pitch');

// ---- Sextortion ----
add('sextortion', 80, /nude|naked|porn|sex ?(video|tape|chat|call)|private video|intimate (video|photo|pic)|obscene|अश्लील|नग्न|न्यूड|morphed|compromis(ed|ing) (video|photo|pic)|your (video|clip|pics?|photos?) (is|are|has|have|was|were)? ?(recorded|captured|with us|with me)|video call (was |is |has been )?record|screen ?record(ed|ing)? (of )?(your|the) (video )?call/, 'Intimate / recorded / morphed video claim');
add('sextortion', 75, /pay (to|and) delete|delete the (video|clip|photo|pic)s?|viral (kar|kardunga|kar dunga|kar denge|kar dungi)|वायरल (कर|करूंगा|कर दूंगा|कर देंगे)|(upload|post|send|share|circulate|leak|forward|publish)[^.\n]{0,40}(youtube|facebook|instagram|whatsapp|friends|family|relatives|contacts|social media|online|internet|porn)|(leak|viral|circulate)(ed)?\s?(online|on|to|kar)|ruin your (life|reputation|career|image)|call your (family|parents|wife|husband|friends)|youtube link|ब्लैकमेल|blackmail/, 'Threat to circulate to family / friends / social media');
add('sextortion', 40, /(send|pay|transfer|bhej|भेज|जमा)[^.\n]{0,15}(₹|rs\.?|inr)?\s?\d{3,}[^.\n]{0,40}(delete|remove|else|otherwise|warna|वरना|nahi to|नहीं तो)|(₹|rs\.?|inr)\s?\d[\d,]*[^.\n]{0,40}(or (else )?|otherwise |warna |nahi to |वरना |नहीं तो )[^.\n]{0,40}(viral|leak|upload|send|circulate|वायरल)/, 'Ransom demand with deadline threat');

// ---- Courier / customs / India Post ----
add('courier', 20, /courier|parcel|consignment|package|shipment|fedex|\bdhl\b|blue ?dart|india ?post|speed ?post|postal|customs|कूरियर|पार्सल|डाक/, 'Parcel / courier theme');
add('courier', 55, /(कूरियर|पार्सल|डाक|पैकेज)[^.\n]{0,80}(डिलीवर नहीं|नहीं हो सका|पता अपडेट|रीडिलीवरी|शुल्क|रोक|अटक|जब्त|कस्टम)|पता अपडेट करें|(courier|parcel|package) (deliver|delivery) (nahi|na) (ho|hua)|pata update (karein|kare|karo)/, 'Hindi/Hinglish parcel held or address-update-fee wording');
add('courier', 55, /(parcel|courier|package|consignment|shipment|delivery|पार्सल|कूरियर)[^.\n]{0,60}(held|hold|detain|seiz|stuck|stopped|return(ed)?|on hold|blocked|cancel|rto|failed|unable to deliver|undeliver|pending|intercept|caught|लौटा|रोक|जब्त|अटक)|(held|detain|seiz|stuck|intercept|caught)[^.\n]{0,40}(parcel|courier|package|consignment|shipment|customs)|(customs|custom) (duty|clearance|fee|charges?|hold|issue|seizure|ne)|(incomplete|wrong|invalid|incorrect|update|confirm|verify)[^.\n]{0,12}address[^.\n]{0,40}(parcel|delivery|package|shipment|courier|redeliver|link|click|within)|redelivery (fee|charge)|re-?schedule (your )?delivery|address (update|verification) (required|needed|pending)/, 'Parcel is held / failed / needs address update or fee');
add('courier', 55, /(parcel|courier|package|consignment|shipment|पार्सल|कूरियर)[^.\n]{0,80}(drugs?|narcotic|mdma|passport|fake (passport|id)|illegal|contraband|weapon|counterfeit|forged|suspicious (item|content)|ड्रग्स|गैरकानूनी|नकली पासपोर्ट)|(drugs?|narcotic|mdma|fake passports?|illegal items?|contraband)[^.\n]{0,80}(parcel|courier|package|consignment|shipment|पार्सल|कूरियर)/, 'Claim of illegal items found in a parcel in your name');

// ---- Traffic challan ----
add('challan', 55, /e-?challan|challan|traffic (fine|violation|penalty|e-?notice)|vehicle (fine|penalty|violation)|rto (fine|penalty|notice)|parivahan|चालान|ट्रैफिक (फाइन|जुर्माना)/, 'Traffic e-challan theme');
add('challan', 25, /(pending|unpaid|overdue|outstanding|due|बकाया)[^.\n]{0,30}(challan|fine|चालान)|(challan|fine|चालान)[^.\n]{0,40}(pending|unpaid|overdue|court|licen[cs]e (suspend|cancel)|impound|within|warrant|बकाया)/, 'Pending challan with penalty / court threat');

// ---- Lottery / reward / KBC ----
add('lottery', 60, /lottery|lucky draw|\bkbc\b|kaun banega|lucky (winner|customer|user|number)|you (have )?(won|win)|(have )?been (selected|chosen)[^.\n]{0,20}(win|prize|gift|reward)|jackpot|winner|लॉटरी|लकी ड्रॉ|केबीसी|इनाम|जीत(ा|े|ी)|विजेता|(prize|reward|gift)[^.\n]{0,30}(claim|won|winner|selected)|25 ?lakh|₹ ?25,?00,?000/, 'Unsolicited prize / lottery claim');
add('lottery', 45, /free (recharge|gift|iphone|phone|mobile|laptop|data|gold|petrol)|मुफ्त (रिचार्ज|गिफ्ट)|congratulations|बधाई|reward points?|redeem (now|your|points|reward)|claim (now|your|reward|prize|gift|cashback)|cashback (credited|waiting|of|up to)|spin (and|&|n) win|scratch card|gift ?card|giftcard/, 'Reward / free-gift / redeem bait');
add('lottery', 40, /(processing|registration|claim|customs|tax|delivery|gst|clearance) (fee|charge|tax|amount)s?[^.\n]{0,50}(prize|gift|reward|lottery|win|claim|release)|(prize|gift|reward|lottery|win)[^.\n]{0,60}(processing|registration|claim|customs|tax|gst) (fee|charge|tax|amount)/, 'Fee demanded to release the prize');

// ---- Remote access ----
add('remote_access', 85, /any ?desk|team ?viewer|rust ?desk|quick ?support|al?ammyy|ultra ?viewer|aero ?admin|ammy+ ?admin|rescue ?assist|airdroid|mingle ?view|एनीडेस्क|टीमव्यूअर|screen ?shar(e|ing)|share (your )?screen|remote (support|access|control|desktop|session|assist)|9[- ]?digit (code|number)|(code|id) (shown|displayed) (on|in) (the )?app/, 'Remote-access / screen-sharing tool requested');
add('remote_access', 50, /(install|download|open|डाउनलोड|इंस्टॉल|खोलें)[^.\n]{0,40}(app|application|software|tool|apk|ऐप|एप्लीकेशन)[^.\n]{0,40}(support|verif|help|resolve|refund|kyc|solve|complaint|fix|सत्यापन)|(support|verif|resolve|refund|kyc|complaint)[^.\n]{0,40}(install|download|इंस्टॉल|डाउनलोड)[^.\n]{0,15}(app|apk|software|tool|ऐप)/, 'Told to install a support / verification app');
add('remote_access', 55, /\.apk\b|apk file|apk download|download (the )?apk|install (the )?apk|sideload|unknown sources/, 'APK sideload instruction');

// ---- Credential theft ----
add('credential', 65, /(share|send|tell|give|provide|forward|read ?out|enter|type|dictate|confirm|batao|bata do|bataiye|bhej(o|iye|na)?|dijiye|do|बताएं|बताओ|बताइए|भेजें|भेजो|दें|दीजिए|साझा करें)[^.\n]{0,30}\b(otp|o\.t\.p|one time password|cvv|cvc|card (number|no\.?)|expiry|atm pin|debit card pin|net ?banking (id|password)|password|passcode|aadhaar number|ओटीपी|सीवीवी|पासवर्ड)\b|(otp|ओटीपी|cvv|password|पासवर्ड)[^.\n]{0,20}(share|send|tell|forward|batao|bata|bhej|बताएं|बताओ|भेजें|साझा)/, 'Asks you to hand over OTP / PIN / CVV / password');
add('credential', 70, /(tell|give|share|read|say|batao|bataiye)[^.\n]{0,25}(otp|code)[^.\n]{0,40}(to (our|the|my) (agent|executive|officer|representative|person|team|staff|manager)|on (call|phone)|to (the )?caller|for (refund|verification|kyc|cancel|reversal|release))|otp[^.\n]{0,30}(cancel|reverse|refund|reversal|release|verification of|to verify|to confirm|to receive|prize|reward)|(verify|confirm|enter|submit)[^.\n]{0,15}(your )?otp (now|to|for|immediately|within)|otp (to|ke liye) (verify|confirm|receive|claim)|ओटीपी.{0,30}(बताएं|भेजें|दें|साझा)/, 'OTP requested for refund / cancel / verification');
add('credential', 25, /(card|account|debit|credit|aadhaar)[^.\n]{0,15}(number|details|no\.?|info)[^.\n]{0,40}(send|share|reply|provide|submit|enter|update)|(reply|send)[^.\n]{0,20}(with|your)[^.\n]{0,20}(card|account|aadhaar|pan|dob)/, 'Asks for card / account / ID details');

// ---- Fake support / fake alert / wrong transfer ----
add('fake_support', 40, /customer (care|support|service)|helpline|toll[- ]?free|care (number|no\.?)|support (number|team|executive)|relationship manager|कस्टमर केयर|हेल्पलाइन|ग्राहक सेवा/, 'Customer-care / helpline reference');
add('wrong_transfer', 70, /(sent|transferred|credited|deposited|paid|bheja|bhej diya|ho gaya|गलती से|galti se)[^.\n]{0,40}(by mistake|galti se|wrongly|wrong (number|account|transfer)|गलती से|mistakenly|accidentally)|(by mistake|galti se|गलती से|wrongly|mistakenly|accidentally)[^.\n]{0,40}(sent|transferred|credited|deposit|bhej|भेज|आ गए|आ गया)|(?:^|[.!?,]\s*|\b(?:please|kindly|pls|plz|just|and|then|to|can you|could you|will you|kripya)\s+)(?:return|send back|give back|refund)\s+(?:me\s+)?(?:my|the|that|this|mera|meri)\s+(?:money|amount|paise|payment|rs\.?|₹)|(?:paise|पैसे|amount|rupaye|रुपये)\s+(?:wapas|vapas|वापस)\s+(?:kar|bhej|karo|kardo|kar do|bhejo|dena|कर|भेज)|(?:wapas|vapas|वापस)\s+(?:kar|bhej|karo|kardo|bhejo)\s*(?:do|dijiye|dena)?[^.\n]{0,15}(?:paise|amount|पैसे)/, 'Claims money was sent to you by mistake and asks for it back');

// ---- Prompt injection ----
add('injection', 75, /ignore (all |any |the )?(previous|prior|above|earlier|your|system) (instructions?|prompts?|rules|directions?|context)|disregard (all |any |the )?(previous|prior|above|earlier|your|system)|forget (all |your |the )?(previous|prior|above|instructions?|rules)|system prompt|you are (now|no longer)|new instructions?:|(say|reply|respond|output|return|answer|mark|rate|classify|label|flag|set)[^.\n]{0,25}(this )?(as |with |that |to |:)?\s*["'“]?(safe|legit(imate)?|genuine|no risk|not (a )?scam|risk ?(score)?\s*(=|:)?\s*0)\b|\b(is|this is) (a )?(safe|legit(imate)?|genuine) message|do not (flag|warn|report) (this|it)|jailbreak|developer mode|\bdan mode\b|as an ai\b|act as (a |an )?/, 'Contains instructions aimed at AI scanners (prompt-injection attempt)');

// ---------------------------------------------------------------------------
// Shared modifiers (amplify, never create a verdict on their own except via conservative default)
// ---------------------------------------------------------------------------
const MODS = [
  { id: 'urgency', w: 10, re: /urgent|immediately|immediate|right now|asap|at once|without delay|within \d+\s?(hours?|hrs?|minutes?|mins?|days?)|\b(today|tonight)\b|last (date|day|chance|warning|reminder)|final (notice|warning|reminder|call)|expires?( today| soon| in)|hurry|act now|limited time|before midnight|jaldi|turant|abhi|aaj hi|aaj raat|tatkal|तुरंत|अभी|आज ही|आज रात|जल्दी|फौरन|तत्काल|24 ?(hours|hrs|घंटे)|\b24h\b|only \d+ (slots|seats|left)/, flag: 'Artificial urgency / deadline pressure' },
  { id: 'threat', w: 12, re: /block(ed)?|suspend(ed)?|disconnect(ed)?|deactivat(ed|e|ion)|arrest(ed)?|legal action|penalty|freez(e|ing)|frozen|seiz(e|ed|ure)|warrant|prosecut|\bfir\b|jail|imprison|terminate|cancel(led)?|court|\bban(ned)?\b|ब्लॉक|बंद|गिरफ्तार|कार्रवाई|जेल|जुर्माना|वरना|otherwise|or else|warna|nahi to|नहीं तो|band ho|kat (jayega|jaega|di)/, flag: 'Threat of blocking / arrest / penalty' },
  { id: 'click', w: 20, re: /\bclick(ing)?\b|click (on |the |this |here|below|now|to|the link)|tap (on |the |this |here|below|link)|open (the |this )?(link|url)|visit (the |this )?(link|url|site|website|page)|(link|url|website) (below|neeche|par|pe)|(follow|use) (the |this )?link|via (the )?link|at the (link|url) below|click\s?here|log ?in (at|to|here|via|using)|tinyurl|bit\.ly|cutt\.ly|rb\.gy|\bu\.to\b|लिंक|क्लिक|link (par|pe|se)|नीचे दिए|link kholen|link open/, flag: 'Pushes you to click a link' },
  { id: 'install', w: 20, re: /install|download|\.apk|डाउनलोड|इंस्टॉल|apk/, flag: 'Asks you to install / download an app' },
  { id: 'payment', w: 14, re: /(?<![a-z])(pay|transfer|send|deposit|remit|submit|clear|bhej(o|ein|na|iye)?|jama|bhar(o|ein)?|दे|भेज(ें|ो|िए)?|जमा|भरें)\b[^.\n]{0,35}(₹|rs\.?|inr|\d{3,}|fee|charge|amount|tax|gst|fine|penalty|deposit|रुपये|शुल्क|फीस)|(₹|rs\.?|inr)\s?\d[\d,]*[^.\n]{0,25}(?<![a-z])(pay|transfer|send|deposit|to be paid|payable|bhej|जमा|भेज)(?![a-z])|(processing|registration|security|refundable|verification|clearance|handling|release|unlock) (fee|charge|deposit|amount)/, flag: 'Demands a payment / fee / deposit' },
  { id: 'secrecy', w: 14, re: /(do not|don'?t|dont|never|mat|na|nahi)\s+(tell|inform|disclose|reveal|bata\w*|batana)\s+(anyone|anybody|any one|your family|family|parents|friends|bank|the bank|kisi ko|kisi|किसी)|\bko (mat|na|nahi) (bata\w*)|(mat|na) (bata\w*|batana) kisi|(do not|don'?t|dont|never)\s+(tell|inform|let)\s+(my |your |the |our )?(family|parents|mom|dad|mummy|papa|wife|husband)[^.\n]{0,12}(know|about)?|(please )?(keep|rakhna)[^.\n]{0,15}(secret|between us|raaz)|confidential (case|matter|investigation|call)|secret (case|matter|investigation)|(किसी|घर वालों|परिवार) (को|से) (न|मत|नहीं) (बताएं|बताना|बताएँ)|don'?t (disconnect|hang up)|keep (it|this) (a )?(secret|confidential|between us)/, flag: 'Demands secrecy / isolation from family or bank' },
  { id: 'callcta', w: 12, re: /\b(call|dial|contact|whatsapp|ring|phone|reach|message|msg|text)\b|कॉल|संपर्क|सम्पर्क|फोन करें|call (karein|kare|karo|kijiye|back)|sampark/, flag: 'Asks you to call / message a number' },
  { id: 'authority', w: 8, re: /\b(rbi|npci|sebi|uidai|trai|epfo|irctc|income ?tax|it department|ministry|government|govt|cbi|police|court|customs|ncb|ed)\b|reserve bank|आरबीआई|सरकार|मंत्रालय|पुलिस|भारत सरकार/, flag: 'Claims authority (bank / government / agency)' },
  { id: 'reward', w: 6, re: /won|prize|reward|gift|bonus|cashback|offer|free|congratulation/, flag: 'Reward / offer bait' }
];

const SHORTENER_RE = /\b(bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co|goo\.gl|ow\.ly|shorturl\.at|tiny\.cc|rebrand\.ly|v\.gd|t\.ly|u\.to|clck\.ru|s\.id|bitly\.[a-z]+|wa\.me|t\.me|telegram\.me)\b/;
const LINKISH_RE = /(https?:\/\/|www\.)\S+|\b[a-z0-9-]+\.(com|in|net|org|co|io|xyz|top|info|biz|link|cc|me|ly|gl|app|online|site|club|vip|live|shop|store|click|icu|tk|ml|ga|cf|gq|pw|work|tech|fun|page|cloud|apk|ru|cn|buzz|one|bond|sbs|cfd|rest|monster|digital|world|today|website|space)\b(\/\S*)?/;

// ---------------------------------------------------------------------------
// Legitimate-pattern recognisers
// ---------------------------------------------------------------------------
const LEGIT = [
  { id: 'bank_txn', re: /(debited|credited|debit(ed)? of|credit(ed)? of|withdrawn|deposited|paid (rs|₹|inr)|sent (rs|₹|inr)|received (rs|₹|inr)|txn|transaction (of|id|successful|ref)|upi (ref|txn|id)|ref(erence)? ?(no|number|#|id)|avl\.? ?(bal|balance)|available (bal|balance)|a\/c (no\.?\s)?[x*]*\d{3,4}|acct?\s?[x*]+\d{3,4}|card (ending|no\.? ending|xx|x{2,}))/, label: 'Standard bank / UPI transaction alert format' },
  { id: 'otp_notice', re: /(\botp\b|one[- ]time password|verification code|login code|passcode|security code)[^.\n]{0,80}(do not|don'?t|never|not)[^.\n]{0,20}(share|disclose|reveal|give)|(do not|don'?t|never)[^.\n]{0,20}(share|disclose|reveal|give)[^.\n]{0,50}(\botp\b|one[- ]time password|code|pin)|(\botp\b|code)[^.\n]{0,30}(is|:)\s?\d{4,8}[^.\n]{0,60}(valid|expires?)|(\d{4,8}) is (your|the) (otp|code|one time password)|किसी (के साथ|से) (साझा|शेयर) (न|नहीं)|ओटीपी.{0,30}(साझा|शेयर) (न|नहीं)/, label: 'OTP delivered with an explicit "do not share" warning' },
  { id: 'delivery', re: /(swiggy|zomato|blinkit|zepto|bigbasket|dunzo|amazon|flipkart|myntra|ola|uber|rapido|ajio|nykaa|meesho|bookmyshow|irctc|makemytrip|dominos|pizza hut|kfc|mcdonald)[^.\n]{0,120}(order|ride|delivery|delivered|arriving|trip|ticket|booking|shipped|dispatched|out for delivery|picked up|reached)|(your )?(order|ride|trip|booking|ticket)[^.\n]{0,60}(is|has been|will be)?[^.\n]{0,30}(delivered|arriving|out for delivery|confirmed|placed|dispatched|shipped|on the way|picked up|completed|reached)|rider|delivery (partner|executive|agent|associate)|your order|order (id|no|#)/, label: 'Routine order / delivery / ride notification' },
  { id: 'salary', re: /salary|payroll|sal(ary)? credit|stipend|pay ?slip|तनख्वाह|वेतन/, label: 'Salary / payroll credit notification' },
  { id: 'bill_due', re: /(emi|bill|premium|installment|instalment)[^.\n]{0,50}(due|generated|paid|received|processed|auto-?debit|successful)/, label: 'Routine bill / EMI notification' }
];

function stripNegatedAsks(t) {
  return t
    .replace(/\b(never|not|don'?t|dont|do not|should not|must not|will never|would never)\b[^.\n]{0,12}\b(ask|asks|asked|share|disclose|reveal|give|tell|forward|provide|send|call)\b[^.\n]{0,60}/g, ' ')
    .replace(/\b(mat|na|kabhi na|kisi ko na)\s+(share|batayen|bataye|batana|batao|bhejen|dein|den)\b[^.\n]{0,40}/g, ' ')
    .replace(/[^.\n]{0,50}(साझा|शेयर|बता\w*|भेज\w*|दें)\s*(न|ना|नहीं|मत)\s*(करें|करे|कीजिए|कीजिये|बताएं|बताएँ|भेजें|दें)?/g, ' ')
    .replace(/(किसी को|कभी भी)\s*(न|ना|नहीं|मत)?\s*(बताएं|बताएँ|बताना)/g, ' ');
}

const PIN_WORD_RE = /\b(upi ?pin|m-?pin|pin)\b|यूपीआई ?पिन|पिन/;
const FAM_REL_RE = /\b(relative|cousin|uncle|aunt(?:y|ie)?|nephew|niece|brother|sister|bhai(?:ya|ji)?|didi|papa|pappa|daddy|mummy|mom|mama|chacha|chachi|beta|beti|bete|son|daughter|friend|dost|yaar|rishtedaar|रिश्तेदार|पापा|भाई|बेटा|बेटी|मम्मी|दोस्त)\b|रिश्तेदार|पापा|बेटा|बेटी|मम्मी|दोस्त|भाई/;
const FAM_TROUBLE_RE = /\b(stuck|stranded|trouble|accident|hospital|emergency|arrested|custody|jail|lost (?:my )?(?:wallet|passport|phone|bag)|visa|surgery|operation|bail|detained|kidnap\w*|phans\w*|musibat|mushkil|dikkat|problem|hadsa|abroad|airport|customs|police|attack\w*|zaroorat|zarurat|jaruri|urgent(?:ly)? need|need urgent|need money|medical)\b|अस्पताल|फंस|मुसीबत|हादसा|एक्सीडेंट|ज़रूरत|जरूरत/;
const FAM_MONEY_RE = /(?:(?:send|transfer|pay|bhej\w*|dal\w*|de(?:do|na| do)?|भेज\w*|ट्रांसफर)\b[^.\n]{0,50}(?:(?:rs\.?|₹|inr)\s?\d|\d{3,}|paise|पैसे|money|amount|upi|account|\bid\b))|(?:(?:need|chahiye|zaroorat|चाहिए|जरूरत)[^.\n]{0,30}(?:(?:rs\.?|₹|inr)\s?\d|\d{3,}|paise|पैसे|money))|(?:(?:rs\.?|₹|inr)\s?\d[\d,]*[^.\n]{0,40}(?:send|transfer|bhej|भेज|upi|account))|(?:\d{3,}\s?(?:rs|rupees?|rupaye|rupay|paise|₹)?|paise|पैसे|money)[^.\n]{0,40}(?:send|transfer|bhej|भेज|\bupi\b)|\bupi (?:id|number)\b/;
const KYC_BRANCH_RE = /\bkyc\b[^.\n]{0,60}(?:periodic|due|renewal|re-?kyc|update)|(?:periodic|re-?)\s?kyc|visit[^.\n]{0,40}(?:home )?branch|yono|use (?:the )?[a-z ]{0,20}app/;

function levelFor(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  if (score >= 15) return 'LOW';
  return 'SAFE';
}

const UPI_SUSPICIOUS_WORDS = /(police|cbi|rbi|escrow|verification|verify|refund|custody|court|gov|govt|customs|fine|fines|official|support|helpdesk|help\.?desk|security|care|kyc|cashback|reward|lottery|prize|claim|income\.?tax|\bed\b|ncb|tax|cyber|bank|npci|sebi|npc|pmla|fedex|dhl|amazon|flipkart|paytm\.?care|booking|loan|trading|invest|task|offer|winner|kbc|insurance|delivery|courier|parcel|customer|service|desk|dept|department|officer|inspector|advocate|legal)/i;
const UPI_RE = /(?<![\w.\-])([a-z0-9][a-z0-9._\-]{1,40})@([a-z][a-z0-9]{1,20})(?![\w.\-@]|\.[a-z])/gi;

/**
 * Analyse already-validated raw text. opts.links = number of (verified) links found by the domain engine.
 * Returns a plain verdict object; caller shapes the HTTP response.
 */
function analyze(raw, opts = {}) {
  const { t, deleet, squashed } = normalizeText(raw);
  const T = t + ' || ' + (deleet !== t ? deleet : '');
  const Ts = stripNegatedAsks(T);
  const linkCount = opts.links || 0;
  // Links already judged by the domain engine: verified official domains or recognised global-platform domains.
  const trustedLinks = Math.min(linkCount, Math.max(0, opts.trustedLinks || 0));
  const recognisedLinks = Math.min(trustedLinks, Math.max(0, opts.recognisedLinks || 0));
  const allLinksTrusted = linkCount > 0 && trustedLinks >= linkCount;

  const cat = {};
  const catFlags = {};
  const hit = (c, w, flag) => {
    cat[c] = Math.min(100, (cat[c] || 0) + w);
    (catFlags[c] = catFlags[c] || []).push(flag);
  };

  // credential/QR/upi-collect "ask" signals are matched on the negation-stripped text
  const askCats = new Set(['credential', 'upi_collect', 'qr']);
  let credentialAsk = false;
  const deliveryExempt = /delivery (partner|executive|agent|associate|person|boy)|rider|captain|(share|give|tell)[^.\n]{0,25}(otp|code)[^.\n]{0,30}(only|at the time of|on) delivery/.test(T);
  for (const s of S) {
    const src = askCats.has(s.cat) ? Ts : T;
    if (s.re.test(src)) {
      if (s.cat === 'credential' && deliveryExempt && !/refund|cancel|verif|kyc|prize/.test(T)) continue;
      if (s.cat === 'credential' && s.w >= 65) credentialAsk = true;
      hit(s.cat, s.w, s.flag);
    }
  }

  // squashed-token signals: catches "K Y C", "A n y D e s k", "digital-arrest" even if spacing tricks survived
  const sq = [
    ['kyc', 30, /kyc/, 'KYC mentioned (obfuscated)'],
    ['remote_access', 85, /anydesk|teamviewer|rustdesk|quicksupport/, 'Remote-access tool named (obfuscated)'],
    ['digital_arrest', 75, /digitalarrest/, "'Digital arrest' (obfuscated)"],
    ['credential', 0, /^$/, '']
  ];
  for (const [c, w, re, f] of sq) if (w && re.test(squashed) && !(cat[c] >= w)) hit(c, w, f);

  // ---- UPI IDs ----
  const upiIds = [];
  let m;
  const scan = String(raw).normalize('NFKC').replace(ZERO_WIDTH, '');
  UPI_RE.lastIndex = 0;
  while ((m = UPI_RE.exec(scan)) !== null) {
    if (m[2].length < 2) continue;
    upiIds.push({ id: m[0], user: m[1], handle: m[2] });
    if (upiIds.length >= 5) break;
  }
  const payDemand = MODS.find(x => x.id === 'payment').re.test(T);
  let upiSuspicious = null;
  for (const u of upiIds) {
    if (UPI_SUSPICIOUS_WORDS.test(u.user)) { upiSuspicious = u; break; }
  }
  if (upiSuspicious) hit('upi_handle', 75, `UPI ID '${upiSuspicious.id}' uses authority / refund / support words`);
  else if (upiIds.length && payDemand) hit('upi_handle', 50, `Asks for payment to a personal UPI ID (${upiIds[0].id})`);
  else if (upiIds.length) {
    // A bare UPI ID typed on its own cannot be verified by anyone: say "not sure" (MEDIUM), not "looks OK".
    const bare = String(T).trim().toLowerCase() === upiIds[0].id.toLowerCase();
    hit('upi_handle', bare ? 42 : 22, bare
      ? `This is an unverified personal UPI ID (${upiIds[0].id}). SafeMeAI cannot confirm who owns it`
      : `Contains an unverified personal UPI ID (${upiIds[0].id})`);
  }

  // ---- Mobile numbers / links ----
  const mobiles = (T.match(new RegExp(MOBILE_RE.source, 'g')) || []).filter(x => !/^0?[6-9]\d{9}$/.test(x.replace(/\D/g, '').slice(-10)) || true);
  const hasMobile = mobiles.length > 0 && !(upiIds.length && mobiles.every(mb => upiIds.some(u => u.id.includes(mb.replace(/\D/g, '').slice(-10)))));
  const hasTollFree = TOLLFREE_RE.test(T);
  const hasShortener = SHORTENER_RE.test(T);
  const hasLinkText = linkCount > 0 ? !allLinksTrusted : LINKISH_RE.test(t);

  // ---- modifiers ----
  const mods = {};
  for (const md of MODS) if (md.re.test(md.id === 'click' || md.id === 'install' || md.id === 'secrecy' ? T : Ts)) mods[md.id] = md;
  // 'callcta' counts only when a number is actually given or the text is Hindi/English "call this/the number"
  if (mods.callcta && !(hasMobile || hasTollFree || /call (this|the|us|on|back|immediately|now)|contact (us|this|the)/.test(T))) delete mods.callcta;
  // reward/authority words alone are too common to count
  const isCtaNumber = hasMobile && (mods.callcta || /whatsapp|contact|संपर्क|कॉल/.test(T));
  if (allLinksTrusted && mods.click && !SHORTENER_RE.test(T)) delete mods.click; // "tap this link" points at a verified/recognised domain
  if (hasLinkText && !mods.click) mods.click = { id: 'click', w: 12, flag: 'Contains a link' };

  const catEntries = Object.entries(cat).sort((a, b) => b[1] - a[1]);
  const topCat = catEntries.length ? catEntries[0][0] : null;
  const topScore = catEntries.length ? catEntries[0][1] : 0;
  const otherSum = Math.min(30, catEntries.slice(1).reduce((s, [, v]) => s + v, 0) * 0.3);

  let modSum = 0;
  const modFlags = [];
  for (const id of Object.keys(mods)) {
    if (id === 'reward' && topScore < 20) continue;
    if (id === 'authority' && topScore < 20) continue;
    modSum += mods[id].w; modFlags.push(mods[id].flag);
  }
  if (hasMobile && isCtaNumber) { modSum += 12; modFlags.push('Gives a personal mobile number to call / WhatsApp'); }
  else if (hasMobile) { modSum += 6; modFlags.push('Contains a mobile number'); }
  if (hasShortener) { modSum += 15; modFlags.push('Uses a URL shortener / chat-invite link (hides destination)'); }

  // ---- fake support / fake alert (txn alert + callback/link) ----
  const txnAlert = LEGIT.find(l => l.id === 'bank_txn').re.test(T);
  if (txnAlert && (isCtaNumber || (hasMobile && mods.callcta) || hasShortener || (mods.click && !allLinksTrusted && /unauthori[sz]ed|not (done|made|initiated) by you|if not you|dispute|report|block|reverse|cancel/.test(T)))) {
    hit('fake_support', 60, 'Transaction-alert style message with a personal callback number / link (fake bank alert)');
  }
  if (cat.fake_support && (isCtaNumber || hasMobile) && cat.fake_support >= 40) hit('fake_support', 25, 'Customer-care number given as a personal mobile number');
  if (cat.fake_support && !(hasMobile || mods.click || mods.install) && !(txnAlert)) { /* plain mention of "customer care" is not a signal on its own */ cat.fake_support = Math.min(cat.fake_support, 15); }

  // ---- QR scan / UPI PIN "to receive money" trap (PIN or QR can only ever SEND money) ----
  let receiveTrap = Boolean(cat.upi_collect >= 70);
  if (cat.qr && PIN_WORD_RE.test(Ts) && !cat.upi_collect) { hit('upi_collect', 70, 'Asks for a QR scan together with a UPI PIN (PIN / QR only ever send money out)'); receiveTrap = true; }
  else if (cat.qr && cat.upi_collect >= 30) receiveTrap = true;

  // ---- family emergency: relative / friend "in trouble" + money ask (+ secrecy) ----
  let familyAsk = false;
  if (FAM_REL_RE.test(T) && FAM_MONEY_RE.test(T) && !cat.digital_arrest) {
    const trouble = FAM_TROUBLE_RE.test(T);
    const secret = Boolean(mods.secrecy);
    if (trouble && secret) { hit('family_emergency', 80, 'Relative/friend "in trouble" asks for urgent money AND secrecy from the family'); familyAsk = true; }
    else if (trouble || secret) { hit('family_emergency', 62, secret ? 'Money request from a "relative/friend" with a demand for secrecy' : 'Money request from a "relative/friend" in an emergency'); familyAsk = secret || (trouble && (mods.urgency || upiIds.length > 0)); }
  }

  // ---- genuine KYC-due notice: visit branch / use bank app, no link, no phone, no threat ----
  const kycFlagsBenign = (catFlags.kyc || []).every(f => /^(KYC mentioned|Generic greeting|Pushes urgent KYC)/.test(f));
  const benignKycNotice = KYC_BRANCH_RE.test(T) && cat.kyc && kycFlagsBenign && !hasLinkText && !hasMobile && !mods.urgency && !mods.threat && !mods.payment && !mods.install && !mods.secrecy && !credentialAsk;

  // ---- re-rank after late additions ----
  const ranked = Object.entries(cat).sort((a, b) => b[1] - a[1]);
  const top = ranked.length ? ranked[0] : [null, 0];

  // ---- assemble score ----
  let score;
  let flags = [];
  if (top[1] > 0) {
    const mult = top[1] >= 40 ? 1 : (top[1] >= 22 ? 0.75 : 0.5);
    score = top[1] * 0.9 + otherSum + modSum * mult;
    // amplification: authority/theme + (urgency|threat) + (CTA: click|call|payment|install|secrecy) - the BFSI scam triad
    const hasPressure = mods.urgency || mods.threat || mods.secrecy;
    const hasAction = mods.click || mods.install || mods.payment || isCtaNumber || mods.callcta;
    if (top[1] >= 30 && hasPressure && hasAction) score += 15;
    else if (top[1] >= 30 && (hasPressure || hasAction)) score += 6;
    // single weak theme with no pressure/action stays modest (e.g. a normal electricity bill notice)
    const base = CATS[top[0]].base;
    // strong signal => category floor
    if (top[1] >= 70) score = Math.max(score, base - 8);
    else if (top[1] >= 55 && (hasPressure || hasAction)) score = Math.max(score, 72);
    else if (top[1] >= 40 && hasPressure && hasAction) score = Math.max(score, 66);
    if (top[1] >= 40 && (mods.click || mods.install || mods.payment)) score = Math.max(score, 62);
    if (top[1] >= 85 || (top[1] >= 70 && hasAction)) score = Math.max(score, base - 3);
    if (top[1] >= 70 && (top[0] === 'digital_arrest' || top[0] === 'sextortion' || top[0] === 'remote_access')) score = Math.max(score, base - 3);
    // weak lone theme: cap below the "scam" threshold so benign mentions (bill, parcel) are not shouted about
    if (top[1] < 30 && !hasPressure && !hasAction) score = Math.min(score, 34);
    // Loss-of-funds floors: a request to hand over a credential / PIN-to-receive trap / urgent relative-money ask is never below CRITICAL / HIGH
    if (credentialAsk) score = Math.max(score, 88);
    if (receiveTrap) score = Math.max(score, 86);
    if (familyAsk) score = Math.max(score, cat.family_emergency >= 80 ? 86 : 72);
    else if (cat.family_emergency) score = Math.max(score, 64);
    for (const c of ranked.slice(0, 3)) for (const f of catFlags[c[0]] || []) if (!flags.includes(f)) flags.push(f);
  } else {
    score = 0;
  }
  for (const f of modFlags) if (!flags.includes(f)) flags.push(f);

  // ---- legit gate ----
  const legitHits = LEGIT.filter(l => l.re.test(T));
  const hasAnyCta = !!(mods.click || mods.install || hasShortener || (linkCount > 0 && !allLinksTrusted) || hasMobile || mods.payment ||
    (mods.callcta && !hasTollFree) || mods.secrecy || cat.injection || cat.fake_support || cat.upi_handle >= 50 || (mods.urgency && mods.threat));
  const weakTop = top[1] < 25 || (legitHits.length && top[1] < 40 && !hasAnyCta) || benignKycNotice;
  if (benignKycNotice && !legitHits.some(l => l.id === 'kyc_branch')) legitHits.push({ id: 'kyc_branch', label: 'Routine periodic-KYC notice (visit branch / use bank app; no link, number or threat)' });
  let legit = null;
  if (legitHits.length && weakTop && !hasAnyCta && !cat.injection && !credentialAsk && !receiveTrap && !familyAsk) {
    legit = legitHits;
  }

  // ---- conservative default (no category matched) ----
  let defaultUnknown = false;
  if (!legit && top[1] === 0) {
    defaultUnknown = true;
    const risky = [];
    let s = 0;
    if (hasLinkText) { s += 42; risky.push('Contains an unverified link'); }
    if (hasShortener) { s += 10; }
    if (hasMobile) { s += hasLinkText ? 6 : 42; risky.push('Contains a personal phone number'); }
    if (mods.urgency) { s += 8; }
    if (mods.threat) { s += 8; }
    if (mods.payment) { s += 18; risky.push('Asks for a payment'); }
    if (mods.install) { s += 25; risky.push('Asks you to install / download something'); }
    if (mods.click && !hasLinkText) { s += 28; risky.push('Asks you to click a link'); }
    if (mods.secrecy) { s += 15; }
    if (mods.callcta && !hasMobile && !hasTollFree) { s += 12; }
    if (upiIds.length) { s += 5; }
    score = s;
    if (s === 0) {
      score = (squashed.length > 0) ? 8 : 0;
    }
    if (mods.urgency && !s) score = 20;
    if (score >= 40) flags = [...risky, ...flags.filter(f => !risky.includes(f))];
  }

  // ---- injection floor: manipulation attempt is itself hostile ----
  if (cat.injection) score = Math.max(score, Math.min(99, (top[0] === 'injection' ? 72 : score)));

  score = Math.round(Math.max(0, Math.min(99, score)));

  // Hard evidence the optional AI second opinion may never override (only purely stylistic text may be de-escalated).
  const sigs = {
    link: hasLinkText || hasShortener, credential: Boolean(credentialAsk || cat.credential), payment: Boolean(mods.payment), mobile: hasMobile,
    upi: upiIds.length > 0, install: Boolean(mods.install), secrecy: Boolean(mods.secrecy), receiveTrap, familyAsk, indicator: false
  };

  // ---- shape ----
  const analyzedText = String(raw).length > 200 ? String(raw).substring(0, 200) + '...' : String(raw);
  const base = { analyzedText, timestamp: new Date().toISOString() };

  if (legit) {
    const toll = hasTollFree && !hasMobile;
    // Links are only ever "verified" by the domain engine; a recognised (non-bank) platform link keeps the result at LOW, never green.
    const sc = toll ? 18 : (recognisedLinks > 0 ? 16 : (trustedLinks > 0 ? 8 : 5));
    return {
      ...base, riskScore: sc, riskLevel: levelFor(sc),
      scamType: toll ? 'Likely Genuine Alert (verify contact number)' : 'Legitimate Transactional Notification',
      headline: toll ? 'ℹ️ Looks like a genuine alert - verify any number via your app/card' : '✅ SAFE: Standard Transactional Notification',
      verdictDescription: trustedLinks > 0
        ? 'Matches a routine notification format; the only link(s) point to domains the domain engine verified or recognised, and there is no callback number, payment demand, app install or pressure language.'
        : 'Matches a routine notification format and contains no link, mobile callback number, payment demand, app install or pressure language.',
      flags: [...legit.map(l => l.label), trustedLinks > 0 ? 'Link(s) point to verified / recognised domains only' : 'No links, personal phone numbers, payment demands or threats'],
      actionAdvice: ['Message appears genuine.', 'Never share OTP, UPI PIN, CVV or passwords with anyone - not even bank staff.', 'If you did not make this transaction, call the number on your card or use the bank app.'],
      protectionLaw: 'RBI Fair Practices Code & Customer Protection Circular',
      _meta: { category: 'legit', signals: { link: false, credential: false, payment: false, mobile: false, upi: upiIds.length > 0, install: false, secrecy: false } }
    };
  }

  if (defaultUnknown) {
    const lvl = levelFor(score);
    const noisy = score >= 40;
    return {
      ...base, riskScore: score, riskLevel: lvl,
      scamType: noisy ? 'Unverified Message with Link / Contact / Pressure' : 'No Known Scam Pattern Detected',
      headline: noisy ? '⚠️ SUSPICIOUS: Unverified message asks you to act' : (score >= 15 ? 'ℹ️ Unverified message - low risk signals' : 'ℹ️ No known scam pattern found'),
      verdictDescription: noisy
        ? 'This message does not match a known scam script, but it contains a link, phone number, payment request or pressure. Unknown senders asking for action are treated as unsafe until verified.'
        : 'No known scam signatures were found. This is not a guarantee of safety: never share OTPs, PINs or money based on a message you cannot verify.',
      flags: flags.length ? flags : ['No scam signatures matched', 'Origin not verified against official directories'],
      actionAdvice: [
        '🛑 Do not click unknown links, install apps or transfer money.',
        '🛑 Do not call numbers given in unverified messages.',
        '✅ Verify through your official banking app or the number on your card.',
        '📞 Report fraud to 1930 / cybercrime.gov.in.'
      ],
      protectionLaw: 'Indian Cyber Security & Consumer Protection Directives',
      _meta: { category: 'unknown', signals: sigs }
    };
  }

  const c = CATS[top[0]];
  const lvl = levelFor(score);
  return {
    ...base, riskScore: score, riskLevel: lvl,
    scamType: c.name,
    headline: score >= 60 ? c.headline : `⚠️ CAUTION: Possible ${c.name}`,
    verdictDescription: score >= 60 ? c.desc : `${c.desc} Only some warning signs were found - treat as unverified.`,
    flags: flags.length ? flags.slice(0, 8) : [c.name],
    actionAdvice: c.advice,
    protectionLaw: c.law,
    _meta: { category: top[0], categories: Object.fromEntries(ranked), signals: sigs }
  };
}

const KNOWN_TLDS = new Set(('com in net org co io xyz top info biz link cc me ly gl app online site club vip live shop store click icu tk ml ga cf gq pw work tech fun page cloud apk ru cn buzz one bond sbs cfd rest monster digital world today website space gov nic edu us uk to ee ink ws su ai dev bank fin ac res mil jud life pro mobi name asia tv sh gd cn br ng pk bd lk np').split(' '));
/** Avoid treating "Customer.Your" / "Rs.Pay" (missing space after full stop) as a domain. */
function isPlausibleLink(token) {
  if (/^[a-z]+:\/\//i.test(token) || /^www\./i.test(token) || /^\d{1,3}(\.\d{1,3}){3}/.test(token)) return true;
  const host = token.split(/[\/?#:]/)[0];
  const tld = host.split('.').pop().toLowerCase();
  if (/[\/?#]/.test(token) && KNOWN_TLDS.has(tld)) return true;
  if (/^xn--/.test(tld) || /[^\x00-\x7f]/.test(host)) return true; // IDN / punycode
  return KNOWN_TLDS.has(tld) && tld === tld && !/[A-Z]/.test(token.slice(token.lastIndexOf('.') + 1, token.lastIndexOf('.') + 2)) ;
}

/**
 * Extract up to 5 distinct link candidates from free text (shared by /api/scam/check and the offline benchmark).
 * `parseTarget` is domainEngine.parseTarget. Returns [{full, domain}] and the normalised text.
 */
function extractLinks(raw, parseTarget) {
  const urlRegex = /(?:https?:\/\/|ftp:\/\/)?(?:[^\s\/@<>"']+@)?(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]*[a-z0-9¡-￿])?\.)+[a-z¡-￿]{2,})(?::\d+)?(?:[\/?#][^\s]*)?/gi;
  const urls = [];
  const seen = new Set();
  const urlText = normalizeForUrls(raw);
  let match;
  while ((match = urlRegex.exec(urlText)) !== null) {
    let token = match[0].replace(/[.,;:!?)\]'"]+$/, '');
    if (!/^[a-z]+:\/\//i.test(token) && !token.includes('@') && !isPlausibleLink(token)) continue;
    const hasScheme = /^[a-z]+:\/\//i.test(token);
    if (!hasScheme && token.includes('@')) token = token.split('@').pop();
    if (/^\d+(\.\d+)?$/.test(token) || /^v?\d+(\.\d+)+$/i.test(token)) continue;
    const p = parseTarget(token);
    if (!p.ok || seen.has(p.host)) continue;
    if (!p.isIp && !p.host.includes('.')) continue;
    seen.add(p.host);
    urls.push({ full: token, domain: p.host });
    if (urls.length >= 5) break;
  }
  return { urls, urlText };
}

module.exports = { extractLinks, isPlausibleLink, analyze, normalizeText, normalizeForUrls, levelFor, CATS };

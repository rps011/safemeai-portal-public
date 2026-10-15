'use strict';
// PII redaction for anything leaving our process (Gemini, third parties). Conservative: over-masking is
// preferred to leaking. Order matters (email -> UPI -> card -> phone -> Aadhaar -> PAN -> OTP).
const RULES = [
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g, '[EMAIL]'],
  [/\b[\w.\-]{1,64}@[a-z][a-z0-9]{1,30}\b/gi, '[UPI_ID]'],
  [/\b(?:\d[ -]?){13,19}\b/g, '[CARD]'],
  [/(?<![\d])(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)/g, '[PHONE]'],
  [/(?<![\d])[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)/g, '[AADHAAR]'],
  [/\b[A-Z]{5}\d{4}[A-Z]\b/gi, '[PAN]'],
  [/\b(otp|pin|cvv|cvc|passcode|password|code)\b([^\d\n]{0,25})\d{4,8}\b/gi, '$1$2[REDACTED]'],
  [/\b\d{4,8}(?=[^\d\n]{0,12}\b(?:is|as)?\s*(?:your|the)?\s*(?:otp|pin|cvv|code)\b)/gi, '[REDACTED]']
];

function redact(text) {
  let s = String(text == null ? '' : text);
  for (const [re, rep] of RULES) s = s.replace(re, rep);
  return s;
}

module.exports = { redact };

'use strict';
/**
 * How the links inside a MESSAGE influence its verdict (shared by /api/scam/check and the offline benchmark mirror).
 *
 * Old rule: "any link not verified / recognised is forced to >= HIGH (75)". It condemned genuine notices that link to a real
 * but smaller site (a university, a lab, a matrimony portal). New rule, evidence based:
 *   - trusted      verified official, recognised platform, or org-validated + established   -> never boosted
 *   - positive     the domain engine found POSITIVE evidence (Tranco-popular, org-validated certificate, established verdict)
 *                  and nothing against it                                                    -> never boosted
 *   - dangerous    hard block (threat feed, regulator list, look-alike, raw IP, shortener, NXDOMAIN ...), engine score >= 60,
 *                  free-hosting subdomain, or a domain younger than 90 days                  -> HIGH/CRITICAL as before
 *   - unknown      resolves, nothing against it, nothing for it                              -> "not sure" (MEDIUM) UNLESS the text
 *                  around it carries a concrete risk signal (credential / OTP ask, payment ask, urgency + threat, install, secrecy,
 *                  impersonation theme ...), in which case HIGH as before.
 * A link whose assessment failed fails CLOSED (treated as dangerous). Hard blocks are never lowered.
 */

const POSITIVE_VERDICTS = new Set(['ESTABLISHED_THIRD_PARTY_DOMAIN', 'RECOGNISED_BRAND_DOMAIN']);

function classify(a) {
  if (a.verified || a.recognisedBrand || a.orgValidatedEstablished) return 'trusted';
  const young = a.domainAge && a.domainAge.available && Number.isFinite(a.domainAge.ageDays) && a.domainAge.ageDays < 90;
  if (a.hardBlock || a.riskScore >= 60 || a.sharedHosting || young || (a.impersonation && a.impersonation.length && a.impersonation.some(f => f.type !== 'BRAND_NAME_COLLISION'))) return 'dangerous';
  if (a.popularRank || a.orgValidated || POSITIVE_VERDICTS.has(a.verdict)) return a.riskScore < 45 ? 'positive' : 'unknown';
  return 'unknown';
}

/**
 * @param {Array} scored  successful domain assessments
 * @param {object|null} failed  first failed assessment (fails closed)
 * @returns {{trusted:Array, positive:Array, dangerous:Array, unknown:Array, failed:object|null, textOpts:{trustedLinks:number,recognisedLinks:number}}}
 */
function plan(scored, failed) {
  const by = { trusted: [], positive: [], dangerous: [], unknown: [] };
  for (const a of scored) by[classify(a)].push(a);
  const sorter = (x, y) => y.riskScore - x.riskScore;
  by.dangerous.sort(sorter); by.unknown.sort(sorter);
  const accepted = [...by.trusted, ...by.positive];
  return {
    ...by, failed: failed || null,
    // links the text engine may treat as already-judged-fine (positive links count as "recognised": not bank-verified)
    textOpts: { trustedLinks: accepted.length, recognisedLinks: accepted.filter(a => !a.verified).length }
  };
}

/**
 * Decide what the links do to the message.
 * @returns {{mode:'none'|'boost'|'soft', link:object|null, floor:number}}
 *   none  -> links add nothing; the text engine alone decides
 *   boost -> worst link is dangerous (or unknown + concrete text risk): verdict >= 75
 *   soft  -> unknown link, no concrete risk in the text: "not sure" (MEDIUM, 45..59)
 */
function decide(p, textVerdict) {
  if (p.failed && !p.dangerous.length) return { mode: 'boost', link: null, floor: 75 };
  if (p.dangerous.length) return { mode: 'boost', link: p.dangerous[0], floor: 75 };
  if (!p.unknown.length) return { mode: 'none', link: null, floor: 0 };
  const link = p.unknown[0];
  if (p.failed) return { mode: 'boost', link, floor: 75 };
  const sig = (textVerdict && textVerdict._meta && textVerdict._meta.signals) || {};
  if (sig.concrete) return { mode: 'boost', link, floor: 75 };
  return { mode: 'soft', link, floor: Math.max(45, Math.min(59, link.riskScore)) };
}

module.exports = { classify, plan, decide };

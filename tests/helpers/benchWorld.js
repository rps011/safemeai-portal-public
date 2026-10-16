'use strict';
/**
 * Deterministic, fully offline "world" for the accuracy benchmark: simulated DNS / TLS / RDAP / Web Risk / DoH and a
 * Tranco-like popularity table, plus an in-process mirror of the /api/scam/check merge logic (link verdicts + text engine).
 * No sockets are opened. Production allow-list / brand / TLD / shortener data are read from the repo so tests track production.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const engine = require('../../lib/domainEngine');
const textEngine = require('../../lib/textEngine');
const linkPolicy = require('../../lib/linkPolicy');

function loadServerData() {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'server.js'), 'utf8');
  const grab = (name) => {
    const m = src.match(new RegExp(`const ${name} = ([\\s\\S]*?\\n(?:\\]\\)|\\]));`));
    if (!m) throw new Error('could not extract ' + name);
    return vm.runInNewContext(m[1]);
  };
  return {
    whitelist: new Set(require('../../data/allowlist.json').entries.map(e => e.domain)),
    brands: grab('BRAND_KEYWORDS'),
    suspiciousTlds: new Set(grab('SUSPICIOUS_TLDS')),
    shorteners: new Set(grab('URL_SHORTENERS'))
  };
}

const OLD_DAYS = 6000;
// Established, genuinely old sites that are NOT in the BFSI allow-list.
const ESTABLISHED = new Set(['github.com', 'bbc.com', 'wikipedia.org', 'indiatimes.com', 'whatsapp.com', 'claude.ai', 'zerodha.com', 'groww.in',
  // post-v2 fixtures (fictional): popular smaller sites that are NOT in the BFSI allow-list, and a site that publishes only www.<name>
  'campusexams.ac.in', 'carepathlab.com', 'rishtamilap.com', 'unionexchange.io', 'sarvodaya-medical.org.in', 'apexonly-college.edu.in']);
// Tranco-style ranks (indiatimes.com popular; its RDAP is "unavailable" and its DNS TTL is low, as seen in production).
const POPULAR = { 'github.com': 40, 'bbc.com': 150, 'indiatimes.com': 900, 'wikipedia.org': 12, 'whatsapp.com': 30, 'campusexams.ac.in': 9000, 'carepathlab.com': 61000, 'rishtamilap.com': 35000, 'unionexchange.io': 2500 };
// RDAP_DOWN: registry lookup unavailable, so the domain's age is unknown (and nothing else vouches for it) - the "unknown unverified link" case.
const RDAP_DOWN = new Set(['indiatimes.com', 'townhospital-portal.in', 'localcoopcredit.in', 'sarvodaya-medical.org.in', 'greenfieldpoly.in']);
const LOW_TTL = new Set(['indiatimes.com']);
// Names that exist only as zone apex without an A record (NOERROR, NS+SOA) - e.g. incometax.gov.in
const APEX_NO_A = new Set(['incometax.gov.in', 'sarvodaya-medical.org.in', 'apexonly-college.edu.in']);
// Apex has no A record but www.<name> is a CNAME / A (many Indian colleges and hospitals).
const WWW_ONLY = new Set(['sarvodaya-medical.org.in']);
const REAL_SOVEREIGN_EXTRA = new Set(['mygov.in', 'cybercrime.gov.in', 'uidai.gov.in']);

function createWorld() {
  const DATA = loadServerData();
  const WL = DATA.whitelist;
  const regOf = (h) => engine.registrable(h);
  const exists = (host) => {
    if (host.includes('nonexistent-')) return false;
    return true;
  };
  const isOld = (host) => {
    const r = regOf(host);
    return ESTABLISHED.has(r) || WL.has(r) || [...WL].some(d => regOf(d) === r);
  };
  const store = {
    lookup: () => [],
    lookupDomainSuffixes: () => [],
    popularRank: (d) => (POPULAR[d] ? { rank: POPULAR[d], source: 'tranco', ingestedAt: 0 } : null),
    sourceMeta: () => null
  };
  const deps = {
    whitelist: WL, brands: DATA.brands, suspiciousTlds: DATA.suspiciousTlds, shorteners: DATA.shorteners,
    useGemini: false, threatStore: store,
    openPhish: { domains: new Set(), urls: new Set() },
    async dnsCheck(host) {
      if (!exists(host)) return { resolved: false, status: 'NXDOMAIN', ips: [], ttl: null, isFastFlux: false, isNxDomain: true };
      if (APEX_NO_A.has(host)) return { resolved: false, status: 'NOERROR', ips: [], ttl: null, isFastFlux: false, isNxDomain: false };
      const ttl = LOW_TTL.has(regOf(host)) ? 20 : 300;
      return { resolved: true, status: 'NOERROR', ips: ['93.184.216.34'], ttl, isFastFlux: ttl < 60, isNxDomain: false };
    },
    async sslCheck(host) {
      const good = isOld(host);
      return { supported: true, hasValidSsl: true, authorized: true, isExpired: false, isEV_OV: good, subjectOrg: good ? 'Org' : '', issuer: 'Test CA', ageDays: 200, isNewlyIssued: false };
    }
  };
  const realFetch = global.fetch;
  const body = (obj, status = 200) => ({ ok: status < 400, status, text: async () => JSON.stringify(obj) });
  function install() {
    global.fetch = async (url) => {
      const u = String(url);
      if (u.startsWith('https://rdap.org/domain/')) {
        const reg = decodeURIComponent(u.slice('https://rdap.org/domain/'.length));
        if (RDAP_DOWN.has(reg)) return body({}, 503);
        if (!exists(reg)) return body({}, 404);
        const days = isOld(reg) ? OLD_DAYS : 8;
        return body({ events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - days * 86400000).toISOString() }] });
      }
      if (u.startsWith('https://dns.google/resolve')) {
        const q = new URL(u); const name = q.searchParams.get('name'); const type = q.searchParams.get('type');
        const wwwApex = name.startsWith('www.') ? name.slice(4) : null;
        if (wwwApex && WWW_ONLY.has(wwwApex) && (type === 'A' || type === 'CNAME')) {
          return body({ Status: 0, Answer: [{ name: name + '.', type: type === 'A' ? 1 : 5, TTL: 300, data: type === 'A' ? '93.184.216.34' : 'd1234.cloudfront.net.' }] });
        }
        if (APEX_NO_A.has(name) && !WWW_ONLY.has(name) && (type === 'NS' || type === 'SOA')) {
          const t = type === 'NS' ? 2 : 6;
          return body({ Status: 0, Answer: [{ name: name + '.', type: t, TTL: 300, data: 'x.' }] });
        }
        return body({ Status: exists(name) ? 0 : 3 });
      }
      if (u.startsWith('https://webrisk.googleapis.com/')) return body({});
      throw new Error('benchmark world: unexpected network call ' + u);
    };
  }
  function restore() { global.fetch = realFetch; }
  return { deps, install, restore, DATA };
}

const levelBoost = (score) => (score >= 80 ? 'CRITICAL' : (score >= 60 ? 'HIGH' : 'MODERATE'));

/** Mirror of /api/domain/check. */
async function runDomain(world, input) {
  engine._clearCaches();
  const a = await engine.assessDomain(input, { ...world.deps });
  if (!a.ok) return { level: 'ERROR', score: 100, verdict: a.error };
  return { level: a.riskLevel, score: a.riskScore, verdict: a.verdict };
}

/** Mirror of /api/scam/check (message branch): link verdicts merged with the text engine. */
async function runMessage(world, raw) {
  engine._clearCaches();
  const { urls } = textEngine.extractLinks(raw, engine.parseTarget);
  const assessments = await Promise.all(urls.map(u => engine.assessDomain(u.full, { ...world.deps }).catch(err => ({ ok: false, error: err.message, host: u.domain }))));
  const failed = assessments.find(a => !a.ok);
  const scored = assessments.filter(a => a.ok);
  const lp = linkPolicy.plan(scored, failed);
  const opts = { links: urls.length, ...lp.textOpts };
  const tv = textEngine.analyze(raw, opts);
  const decision = linkPolicy.decide(lp, tv);
  if (decision.mode === 'boost') {
    const linkScore = Math.max(decision.link ? decision.link.riskScore : 75, decision.floor);
    const score = Math.max(linkScore, tv.riskScore);
    return { level: levelBoost(score), score, verdict: 'link:' + (decision.link ? decision.link.verdict : 'failed'), flags: tv.flags };
  }
  if (decision.mode === 'soft') {
    const score = Math.min(59, Math.max(decision.floor, tv.riskScore));
    return { level: textEngine.levelFor(score), score, verdict: 'link-soft:' + decision.link.verdict, flags: tv.flags };
  }
  return { level: tv.riskLevel, score: tv.riskScore, verdict: tv.scamType, flags: tv.flags };
}

module.exports = { createWorld, runDomain, runMessage, levelBoost };

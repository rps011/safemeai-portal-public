'use strict';
/**
 * SEBI "Recognised Intermediaries" registers -> POSITIVE allow-list (category 'regulated-entity').
 *
 *   Landing : https://www.sebi.gov.in/sebiweb/other/OtherAction.do?doRecognisedFpi=yes&intmId=<ID>   (page 1, sets JSESSIONID)
 *   Paging  : POST https://www.sebi.gov.in/sebiweb/ajax/other/getintmfpiinfo.jsp   (25 per page, needs the session cookie
 *             + Referer; without the cookie SEBI's WAF answers "Unauthorized Request Blocked")
 *   robots.txt allows all but /js /css. Data is a public statutory register.
 *
 * SEBI publishes NO website field, only name / reg no / validity / address / email / phone. We therefore emit:
 *   - an 'entity' record per registrant (name + registration number: the authoritative signal), and
 *   - a LOWER-confidence 'domain' record derived from a corporate (non free-mail) e-mail domain.
 * Personal contact data (phone, e-mail local-part, contact person) is deliberately NOT stored.
 */
const U = require('./_util');

const BASE = 'https://www.sebi.gov.in';
const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

function parseDate(s) {
  const m = /^([A-Za-z]{3})[a-z]*\s+(\d{1,2}),\s*(\d{4})$/.exec(String(s || '').trim());
  if (!m || !(m[1].toLowerCase() in MONTHS)) return null;
  return Date.UTC(+m[3], MONTHS[m[1].toLowerCase()], +m[2]);
}

const CARD_RE = /<div class=["']card-view["'][^>]*>\s*<div class=["']title["']><span>([^<]*)<\/span><\/div>\s*<div class=["']value[^"']*["']><span>([\s\S]*?)<\/span><\/div>\s*<\/div>/g;

/** Parse one result page (full page or the ajax fragment). Pure. */
function parsePage(html, id = 'sebi') {
  if (typeof html !== 'string') throw new U.IndiaParseError(id, 'page is not a string');
  const pm = /(\d+)\s+to\s+(\d+)\s+of\s+(\d+)\s+records/i.exec(U.decodeEntities(html));
  if (!pm) {
    if (/Unauthori[sz]ed Request Blocked/i.test(html)) throw new U.IndiaParseError(id, 'SEBI WAF blocked the request (missing session cookie / Referer?)');
    throw new U.IndiaParseError(id, 'pagination banner ("N to M of T records") not found - layout changed?');
  }
  const from = +pm[1], to = +pm[2], total = +pm[3];
  const recs = [];
  let cur = null;
  let m;
  CARD_RE.lastIndex = 0;
  while ((m = CARD_RE.exec(html))) {
    const key = U.stripTags(m[1]).toLowerCase();
    const val = U.stripTags(m[2]);
    if (key === 'name') { cur = { name: val }; recs.push(cur); continue; }
    if (!cur) continue;
    if (key === 'trade name') cur.tradeName = val;
    else if (key.startsWith('registration no')) cur.regNo = val;
    else if (key === 'e-mail') cur.email = val;
    else if (key === 'validity') cur.validity = val;
    else if (key === 'exchange name') cur.exchange = val;
  }
  if (total > 0 && recs.length === 0) throw new U.IndiaParseError(id, `banner says ${total} records but 0 parsed`);
  // a normal (non-truncated) page must contain exactly to-from+1 records
  return { from, to, total, records: recs, expected: to - from + 1 };
}

function makeSource(cfg) {
  const { id, name, intmId, regRe, typeName, schedule, staleAfterHours, timeoutMs } = cfg;
  const pageUrl = `${BASE}/sebiweb/other/OtherAction.do?doRecognisedFpi=yes&intmId=${intmId}`;
  const ajaxUrl = `${BASE}/sebiweb/ajax/other/getintmfpiinfo.jsp`;

  /** Turn raw registrants into SafeMeAI records. Pure. */
  function toRecords(registrants, { now = Date.now() } = {}) {
    const iso = U.isoDay(now);
    const byReg = new Map();
    for (const r of registrants) {
      if (!r.name) throw new U.IndiaParseError(id, 'registrant without a name');
      if (!r.regNo || !regRe.test(r.regNo)) throw new U.IndiaParseError(id, `registrant ${JSON.stringify(r.name)} has invalid registration number ${JSON.stringify(r.regNo)}`);
      const e = byReg.get(r.regNo);
      if (e) { if (r.exchange && !e.exchanges.includes(r.exchange)) e.exchanges.push(r.exchange); continue; }
      byReg.set(r.regNo, { ...r, exchanges: r.exchange ? [r.exchange] : [] });
    }
    const out = [];
    const seenDom = new Set();
    for (const r of byReg.values()) {
      const endStr = (r.validity || '').split(/\s+-\s+/)[1];
      const end = endStr && !/perpetual/i.test(endStr) ? parseDate(endStr) : null;
      if (end && end < now) continue; // expired registration is not a positive signal
      const meta = {
        regulator: 'SEBI', registrationNo: r.regNo, registrationType: typeName, validity: r.validity || null,
        label: `SEBI-registered ${typeName} ${r.regNo}`, verdict: 'regulated',
        ...(r.tradeName && r.tradeName.toLowerCase() !== r.name.toLowerCase() ? { tradeName: r.tradeName } : {}),
        ...(r.exchanges.length ? { exchanges: r.exchanges } : {}),
      };
      const base = { category: 'regulated-entity', source: id, sourceUrl: pageUrl, firstSeen: iso, lastSeen: iso };
      out.push({ ...base, type: 'entity', value: r.name, confidence: 0.99, meta });
      const dom = U.domainFromEmail(r.email);
      if (dom && !seenDom.has(dom + r.regNo)) {
        seenDom.add(dom + r.regNo);
        out.push({ ...base, type: 'domain', value: dom, confidence: 0.6, meta: { ...meta, entity: r.name, derivedFrom: 'registered-email-domain' } });
      }
    }
    return out;
  }

  async function collect(ctx) {
    const first = await U.httpText(ctx, id, pageUrl, { conditional: false });
    const p1 = parsePage(first.text, id);
    const perPage = p1.expected;
    if (perPage < 1) throw new U.IndiaParseError(id, 'page size is zero');
    const pages = Math.ceil(p1.total / perPage);
    const cookies = U.getSetCookies(first.res.headers).map((c) => c.split(';')[0]).filter(Boolean).join('; ');
    const maxPages = Number(ctx.maxPages || 0) || pages;
    const all = [...p1.records];
    let truncated = false;
    for (let p = 1; p < pages; p++) {
      if (p >= maxPages) { truncated = true; break; }
      const body = new URLSearchParams({
        nextValue: '1', next: 'n', intmId: String(intmId), contPer: '', name: '', regNo: '', email: '', location: '',
        exchange: '', affiliate: '', alp: '', doDirect: String(p), intmIds: '',
      }).toString();
      const r = await U.httpText(ctx, id, ajaxUrl, {
        method: 'POST', body, conditional: false,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Referer: pageUrl, 'X-Requested-With': 'XMLHttpRequest', ...(cookies ? { Cookie: cookies } : {}) },
      });
      const pg = parsePage(r.text, id);
      if (pg.from !== p * perPage + 1) throw new U.IndiaParseError(id, `page ${p + 1}: expected to start at record ${p * perPage + 1}, got ${pg.from}`);
      if (pg.total !== p1.total) throw new U.IndiaParseError(id, `total changed mid-crawl (${p1.total} -> ${pg.total}); retry later`);
      if (pg.records.length !== pg.expected) throw new U.IndiaParseError(id, `page ${p + 1}: parsed ${pg.records.length} of ${pg.expected} records`);
      all.push(...pg.records);
    }
    if (!truncated && all.length !== p1.total) throw new U.IndiaParseError(id, `crawled ${all.length} registrants but SEBI reports ${p1.total}`);
    return { registrants: all, total: p1.total, truncated };
  }

  async function fetch(ctx) {
    const { registrants, truncated } = await collect(ctx);
    const records = toRecords(registrants, { now: U.nowMs(ctx) });
    return U.guardedResult(id, ctx, records, { partial: truncated });
  }

  return {
    id, name, group: 'india', schedule, ...(staleAfterHours ? { staleAfterHours } : {}), ...(timeoutMs ? { timeoutMs } : {}),
    license: 'SEBI public register (sebi.gov.in). robots.txt permits crawling; no stated ToS prohibition on reuse of the register, but SEBI content is "© SEBI". Keep request rate low (<=1 req/3s), attribute SEBI, never present as SEBI endorsement.',
    fetch, parse: (html) => toRecords(parsePage(html, id).records), parsePage, toRecords, URL: pageUrl,
  };
}

module.exports = { makeSource, parsePage, parseDate };

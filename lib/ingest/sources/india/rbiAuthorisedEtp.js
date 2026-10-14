'use strict';
/**
 * RBI list of authorised Electronic Trading Platforms (ETPs). POSITIVE allow-list source.
 *   Page: https://www.rbi.org.in/Scripts/bs_viewcontent.aspx?Id=4080   (server-rendered HTML)
 *   Only Section A (currently authorised) is used; Section B (cancelled) is ignored.
 */
const U = require('./_util');

const ID = 'rbi-authorised-etp';
const URL_ = 'https://www.rbi.org.in/Scripts/bs_viewcontent.aspx?Id=4080';

function parse(html, { now = Date.now() } = {}) {
  if (typeof html !== 'string' || html.length < 500) throw new U.IndiaParseError(ID, 'empty or too-short document');
  const rows = U.tableRows(html);
  const text = rows.map((cells) => cells.map(U.stripTags));
  const headerIdx = text.findIndex((r) => r.length >= 6 && /authorisation no/i.test(r[1]) && /operator/i.test(r[2]) && /web/i.test(r[5]));
  if (headerIdx < 0) throw new U.IndiaParseError(ID, 'ETP header row not found - page layout changed?');
  const iso = U.isoDay(now);
  const byOperator = new Map();
  for (let i = headerIdx + 1; i < text.length; i++) {
    const r = text[i];
    if (r.some((c) => /^remarks$/i.test(c))) break; // Section B (cancelled) header reached
    if (r.length < 6 || !/^\d{1,3}$/.test(r[0])) continue;
    const authNo = r[1];
    if (!/^ETP\d+\/[A-Za-z0-9-]+\/\d{4}$/.test(authNo)) throw new U.IndiaParseError(ID, `unexpected authorisation number ${JSON.stringify(authNo)}`);
    const operator = r[2];
    if (!operator) throw new U.IndiaParseError(ID, `row ${r[0]} missing operator name`);
    const hrefM = /href\s*=\s*["']([^"']+)["']/i.exec(rows[i][5] || '');
    const host = U.normaliseDomain(hrefM ? hrefM[1] : r[5].replace(/\s+/g, ''));
    const opKey = operator.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
    let e = byOperator.get(opKey);
    if (!e) { e = { operator, nos: [], etps: [], hosts: new Set() }; byOperator.set(opKey, e); }
    e.nos.push(authNo); e.etps.push(r[3]);
    if (host) e.hosts.add(host);
  }
  if (byOperator.size < 3) throw new U.IndiaParseError(ID, `only ${byOperator.size} ETP operators parsed - refusing partial data`);
  const out = [];
  for (const e of byOperator.values()) {
    const meta = {
      regulator: 'RBI', registrationNo: e.nos[0], registrationNos: e.nos, registrationType: 'Authorised Electronic Trading Platform',
      etps: e.etps, label: `RBI-authorised ETP ${e.nos[0]}`, verdict: 'regulated',
    };
    const base = { category: 'regulated-entity', source: ID, sourceUrl: URL_, confidence: 0.98, firstSeen: iso, lastSeen: iso };
    out.push({ ...base, type: 'entity', value: e.operator, meta: { ...meta, websites: [...e.hosts] } });
    for (const h of e.hosts) out.push({ ...base, type: 'domain', value: h, meta: { ...meta, entity: e.operator } });
  }
  return out;
}

async function fetch(ctx) {
  const { text, notModified } = await U.httpText(ctx, ID, URL_);
  if (notModified) return null;
  return U.guardedResult(ID, ctx, parse(text, { now: U.nowMs(ctx) }), { maxDrop: 0.5 });
}

module.exports = {
  id: ID, name: 'RBI authorised Electronic Trading Platforms (allow-list)', group: 'india',
  schedule: 'every 7d', staleAfterHours: 24 * 14,
  license: 'RBI public notice (rbi.org.in). Same terms as rbi-alert-list; "listing is not an endorsement".',
  fetch, parse, URL: URL_,
};

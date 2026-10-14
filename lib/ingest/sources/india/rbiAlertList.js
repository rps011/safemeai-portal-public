'use strict';
/**
 * RBI "Alert List" of entities/platforms/websites NOT authorised to deal in forex
 * (FEMA) or to run a forex electronic trading platform. BLOCK-type source.
 *
 *   Page : https://www.rbi.org.in/Scripts/bs_viewcontent.aspx?Id=4235   (server-rendered HTML table)
 *   Cadence: irregular (ad hoc additions; roughly a few times a year). Poll weekly.
 *
 * NOTE: the list names large foreign brokers (eToro, IG, ...) that are merely not authorised in
 * India. category 'unauthorised-forex' + meta.verdict 'unauthorised' (NOT 'scam') so the UI can say
 * "Listed in RBI Alert List: not authorised to offer forex trading in India".
 */
const U = require('./_util');

const ID = 'rbi-alert-list';
const URL_ = 'https://www.rbi.org.in/Scripts/bs_viewcontent.aspx?Id=4235';

function parse(html, { now = Date.now() } = {}) {
  if (typeof html !== 'string' || html.length < 500) throw new U.IndiaParseError(ID, 'empty or too-short document');
  const rows = U.tableRows(html).map((cells) => cells.map(U.stripTags));
  const headerIdx = rows.findIndex((r) => r.length >= 3 && /^sr\.?\s*no/i.test(r[0]) && /name/i.test(r[1]) && /website|url/i.test(r[2]));
  if (headerIdx < 0) throw new U.IndiaParseError(ID, 'header row (Sr. No | Name | Website) not found - page layout changed?');
  const updated = (U.stripTags(html).match(/Alert List \(Updated as on ([^)]{4,40})\)/i) || [])[1] || null;
  const iso = U.isoDay(now);

  const out = [];
  const seenDomain = new Set();
  const seenEntity = new Set();
  let dataRows = 0;
  for (const r of rows.slice(headerIdx + 1)) {
    if (r.length < 3 || !/^\d{1,4}$/.test(r[0])) continue;
    dataRows++;
    const name = r[1].replace(/\s+/g, ' ').trim();
    const web = r[2].trim();
    if (!name) throw new U.IndiaParseError(ID, `row ${r[0]} has empty name`);
    const meta = {
      regulator: 'RBI', list: 'Alert List', listUpdated: updated, srNo: Number(r[0]), verdict: 'unauthorised',
      label: 'Listed in RBI Alert List',
      note: 'Not authorised under FEMA / RBI ETP Directions to offer forex trading in India. Not necessarily a scam.',
      website: web || null,
    };
    const base = { category: 'unauthorised-forex', source: ID, sourceUrl: URL_, confidence: 0.9, firstSeen: iso, lastSeen: iso };
    const ek = name.toLowerCase();
    if (!seenEntity.has(ek) && ek.replace(/[^a-z0-9]/g, '').length >= 3) { // pipeline rejects entity names < 3 chars (e.g. "XM"); the domain record still carries it
      seenEntity.add(ek);
      out.push({ ...base, type: 'entity', value: name, meta: { ...meta, channel: /mobile app/i.test(web) ? 'mobile-app' : 'website' } });
    }
    const host = U.normaliseDomain(web);
    if (host) {
      if (!seenDomain.has(host)) {
        seenDomain.add(host);
        out.push({ ...base, type: 'domain', value: host, meta: { ...meta, entity: name } });
      }
      const withPath = U.normaliseUrlWithPath(web);
      if (withPath) out.push({ ...base, type: 'url', value: withPath, meta: { ...meta, entity: name } });
    } else if (web && !/mobile app/i.test(web)) {
      throw new U.IndiaParseError(ID, `row ${r[0]} (${name}) has an unparseable website value: ${JSON.stringify(web)}`);
    }
  }
  if (dataRows < 20) throw new U.IndiaParseError(ID, `only ${dataRows} data rows parsed (expected 90+) - refusing partial data`);
  if (!out.some((x) => x.type === 'domain')) throw new U.IndiaParseError(ID, 'no domains extracted');
  return out;
}

async function fetch(ctx) {
  const { text, notModified } = await U.httpText(ctx, ID, URL_);
  if (notModified) return null; // runner keeps the previous snapshot
  const records = parse(text, { now: U.nowMs(ctx) });
  return U.guardedResult(ID, ctx, records);
}

module.exports = {
  id: ID, name: 'RBI Alert List (unauthorised forex trading platforms)', group: 'india',
  schedule: 'every 7d', staleAfterHours: 24 * 14,
  license: 'RBI public notice (rbi.org.in). No explicit scraping prohibition; Disclaimer: content "as is", RBI may block access; attribute RBI; do not imply RBI endorsement.',
  fetch, parse, URL: URL_,
};

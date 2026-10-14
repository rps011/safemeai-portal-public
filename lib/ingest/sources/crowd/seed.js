'use strict';
// SafeMeAI Android seed source (ingestion contract: lib/ingest/contract.js). Static, offline, no network.
// NOTE: registry.validateSource only accepts group 'global'|'india', so this uses 'india' although it lives in sources/crowd/.
// Record shape: {type,value,category,source,sourceUrl,confidence,firstSeen,lastSeen,meta}
const fs = require('fs');
const path = require('path');

const SEED_FILE = path.join(__dirname, '..', '..', '..', '..', 'data', 'fraud-domains.seed.json');
const SOURCE = 'safemeai-android-seed';

function normDomain(v) {
  const d = String(v || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[\/?#]/)[0].replace(/\.$/, '');
  return /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(d) ? d : null;
}

/** Parse the seed document into contract records. Invalid rows are dropped and counted. */
function parseSeed(doc, now = new Date()) {
  const ts = (now instanceof Date ? now : new Date(now)).toISOString();
  const records = []; let rejected = 0;
  const seen = new Set();
  for (const e of (doc && doc.entries) || []) {
    const value = e && e.type === 'domain' ? normDomain(e.value) : null;
    if (!value || seen.has(value)) { rejected++; continue; }
    seen.add(value);
    records.push({
      type: 'domain', value, category: e.category || 'unknown', source: SOURCE,
      sourceUrl: e.sourceUrl || null, confidence: typeof e.confidence === 'number' ? e.confidence : 0.8,
      firstSeen: ts, lastSeen: ts, meta: Object.assign({ seed: true, version: doc.version }, e.meta || {})
    });
  }
  return { records, rejected };
}

function load(file = SEED_FILE, now) {
  return parseSeed(JSON.parse(fs.readFileSync(file, 'utf8')), now);
}

module.exports = {
  id: 'safemeai-android-seed',
  name: 'SafeMeAI Android seed domains',
  group: 'india',
  schedule: 'every 24h',
  license: 'First-party SafeMeAI data (hand-curated, ported from the Android app)',
  staleAfterHours: 24 * 14,
  async fetch(ctx) { return load(SEED_FILE, ctx && ctx.now ? ctx.now : undefined).records; },
  SOURCE, SEED_FILE, parseSeed, load, normDomain };

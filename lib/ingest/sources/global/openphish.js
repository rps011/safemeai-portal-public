'use strict';
// OpenPhish community feed. NOTE: the community feed is for NON-COMMERCIAL use; a commercial licence from
// OpenPhish is required before relying on it in a paid product. Disable with INGEST_SOURCES_DISABLE=openphish.
const URL_ = 'https://openphish.com/feed.txt';

module.exports = {
  id: 'openphish',
  name: 'OpenPhish community feed',
  group: 'global',
  schedule: 'every 6h',
  license: 'OpenPhish community feed: non-commercial use only; commercial licence required',
  staleAfterHours: 12,
  async fetch(ctx) {
    const r = await ctx.http(URL_, { robots: false, maxBytes: 8 * 1024 * 1024 });
    if (r.notModified) return null;
    const out = [];
    const seenHosts = new Set();
    for (const line of r.text.split('\n').slice(0, 200000)) {
      const v = line.trim();
      if (!v) continue;
      let host;
      try { host = new URL(v).hostname.replace(/^www\./, ''); } catch (_) { continue; }
      out.push({ type: 'url', value: v, category: 'phishing', source: 'openphish', sourceUrl: URL_, confidence: 0.95, firstSeen: ctx.now, lastSeen: ctx.now });
      if (!seenHosts.has(host)) { seenHosts.add(host); out.push({ type: 'domain', value: host, category: 'phishing', source: 'openphish', sourceUrl: URL_, confidence: 0.9, firstSeen: ctx.now, lastSeen: ctx.now }); }
    }
    return out;
  }
};

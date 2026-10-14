'use strict';
// Phishing.Database ACTIVE domains (mitchellkrogza/Phishing.Database, MIT licence).
const URL_ = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt';

module.exports = {
  id: 'phishing-database',
  name: 'Phishing.Database (active phishing domains)',
  group: 'global',
  schedule: 'every 6h',
  license: 'MIT (mitchellkrogza/Phishing.Database)',
  async fetch(ctx) {
    // robots:false -> this is a published bulk-download file (raw.githubusercontent.com), fetched at most every few hours.
    const r = await ctx.http(URL_, { robots: false, maxBytes: 64 * 1024 * 1024 });
    if (r.notModified) return null;
    const out = [];
    for (const line of r.text.split('\n')) {
      const v = line.trim();
      if (!v || v.charCodeAt(0) === 35) continue; // blank / comment
      out.push({ type: 'domain', value: v, category: 'phishing', source: 'phishing-database', sourceUrl: URL_, confidence: 0.9, firstSeen: ctx.now, lastSeen: ctx.now });
    }
    return out;
  }
};

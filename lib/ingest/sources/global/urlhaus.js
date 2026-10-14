'use strict';
// abuse.ch URLhaus: URLs currently serving malware. Historically published as CC0; the current abuse.ch API page only
// states 'fair use' + Terms of Use and a free Auth-Key for downloads, and for-profit users may need a commercial
// subscription. VERIFY abuse.ch terms before commercial launch.
const URL_ = 'https://urlhaus.abuse.ch/downloads/text_online/';

module.exports = {
  id: 'urlhaus',
  name: 'abuse.ch URLhaus (online malware URLs)',
  group: 'global',
  schedule: 'every 6h',
  license: 'abuse.ch fair-use terms (previously CC0); free Auth-Key required; commercial use: verify with abuse.ch',
  async fetch(ctx) {
    // URLHAUS_AUTH_KEY: abuse.ch requires a free Auth-Key for downloads; sent as the Auth-Key header when configured.
    const headers = process.env.URLHAUS_AUTH_KEY ? { 'Auth-Key': process.env.URLHAUS_AUTH_KEY } : {};
    const r = await ctx.http(URL_, { robots: false, headers, maxBytes: 32 * 1024 * 1024 });
    if (r.notModified) return null;
    const out = [];
    const hosts = new Set();
    for (const line of r.text.split('\n')) {
      const v = line.trim();
      if (!v || v[0] === '#') continue;
      out.push({ type: 'url', value: v, category: 'malware', source: 'urlhaus', sourceUrl: 'https://urlhaus.abuse.ch/', confidence: 0.95, firstSeen: ctx.now, lastSeen: ctx.now });
      try { hosts.add(new URL(v).hostname); } catch (_) {}
    }
    // Host-level listing is weaker evidence (a compromised legitimate site may host one bad file): low confidence,
    // so the engine adds risk but does not hard-block on the host alone.
    for (const h of hosts) out.push({ type: 'domain', value: h, category: 'malware', source: 'urlhaus', sourceUrl: 'https://urlhaus.abuse.ch/', confidence: 0.5, firstSeen: ctx.now, lastSeen: ctx.now });
    return out;
  }
};

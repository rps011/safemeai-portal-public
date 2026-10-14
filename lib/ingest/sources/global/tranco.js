'use strict';
// Tranco research ranking (https://tranco-list.eu). Used ONLY as context ("established popular site"), never as a
// safety verdict. Only the top 100k are stored.
const zlib = require('zlib');
const URL_ = 'https://tranco-list.eu/top-1m.csv.zip';
const KEEP = 100000;

/** Minimal ZIP reader: returns the decompressed bytes of the first file entry (central directory based). */
function unzipFirst(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('zip: end of central directory not found');
  const cdOff = buf.readUInt32LE(eocd + 16);
  if (buf.readUInt32LE(cdOff) !== 0x02014b50) throw new Error('zip: bad central directory');
  const method = buf.readUInt16LE(cdOff + 10);
  const csize = buf.readUInt32LE(cdOff + 20);
  const lho = buf.readUInt32LE(cdOff + 42);
  if (buf.readUInt32LE(lho) !== 0x04034b50) throw new Error('zip: bad local header');
  const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
  const data = buf.subarray(start, start + csize);
  if (method === 0) return data;
  if (method === 8) return zlib.inflateRawSync(data, { maxOutputLength: 64 * 1024 * 1024 });
  throw new Error('zip: unsupported compression method ' + method);
}

module.exports = {
  id: 'tranco',
  name: 'Tranco top sites (popularity context)',
  group: 'global',
  schedule: 'every 24h',
  license: 'No licence stated by tranco-list.eu; it aggregates sources incl. CC BY-NC 4.0 (Cloudflare Radar). Verify before commercial use',
  staleAfterHours: 24 * 8,
  unzipFirst,
  async fetch(ctx) {
    const r = await ctx.http(URL_, { robots: false, binary: true, maxBytes: 64 * 1024 * 1024 });
    if (r.notModified) return null;
    const csv = unzipFirst(r.buffer).toString('utf8');
    const out = [];
    for (const line of csv.split('\n')) {
      const i = line.indexOf(',');
      if (i < 1) continue;
      const rank = Number(line.slice(0, i));
      if (!Number.isInteger(rank) || rank < 1) continue;
      if (rank > KEEP) break;
      out.push({ type: 'domain', value: line.slice(i + 1).trim(), category: 'popular-site', source: 'tranco', sourceUrl: 'https://tranco-list.eu/', confidence: 1, firstSeen: ctx.now, lastSeen: ctx.now, meta: { rank } });
    }
    return out;
  }
};

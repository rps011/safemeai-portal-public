# Threat-intelligence source contract

Every source is one CommonJS module at `lib/ingest/sources/<group>/<id>.js` (`group` = `global` | `india`).
The registry (`lib/ingest/registry.js`) auto-discovers it; a module that fails to load or validate is skipped and
reported, never fatal. Files starting with `_` are ignored (use them for shared helpers).

```js
module.exports = {
  id: 'sebi-investor-alerts',          // [a-z0-9_-], unique, stable (it is the storage key and the `source` field)
  name: 'SEBI unauthorised entities',   // human name; shown verbatim in verdicts: "Listed by <name> (ingested <ts>)"
  group: 'india',                       // 'global' | 'india'
  schedule: 'every 12h',                // informational ('every <n>m|h|d'); Cloud Scheduler is the real driver
  license: 'Public regulator data; ...',// REQUIRED, stated honestly (shown in /internal/ingest/status)
  // optional:
  mode: 'snapshot',                     // 'snapshot' (default: result REPLACES the source's previous set) | 'delta' (merged)
  staleAfterHours: 36,                  // after this long without a success the feed is reported `stale`, not `live`
  timeoutMs: 120000, maxRecords: 5e6,
  async fetch(ctx) { return [ /* records */ ]; }
};
```

## ctx
| field | meaning |
|---|---|
| `ctx.http(url, opts)` | Polite fetch. Descriptive `User-Agent: SafeMeAI-ThreatIntel/1.0 (+<INGEST_CONTACT>)`, honours **robots.txt** (disable only for published bulk-download files with `{robots:false}`), per-host rate limit (>=1 s between requests), 30 s timeout, 32 MiB size cap (`{maxBytes}`), conditional GET with stored ETag/Last-Modified. Returns `{status, text}` (or `{buffer}` with `{binary:true}`) or `{notModified:true}` on 304. **Throws** on network error, non-2xx, oversize, robots disallow. Options: `headers, timeoutMs, maxBytes, robots, conditional, binary`. |
| `ctx.log(level, msg)` | `level` = `'info'`/`'warn'`. |
| `ctx.state.get(key)` / `.set(key, value)` | Async, JSON-serialisable, persisted per source (shared across Cloud Run instances). Use it for cursors/hashes. |
| `ctx.now` | Run start, epoch ms. Use it for `firstSeen/lastSeen` when the page has no date. |
| `ctx.signal` | AbortSignal fired on timeout. |
| `ctx.force` | `true` when the runner wants an unconditional fetch. |

## Return value
* `Array` of records (below). **Empty array = failure** ("no valid records"); the previous snapshot is kept.
* `null`  = "unchanged" (you got `notModified`). The runner keeps the previous snapshot and counts a success.
  (If the store holds nothing for the source the runner transparently retries unconditionally.)
* Throw on any error. The runner retries with exponential backoff (permanent errors - 4xx, robots - are not retried).
* Snapshot guard: a snapshot that shrinks by >70% (when the previous had >= 50 records) is rejected as a broken scrape.

## Record
```js
{
  type: 'domain'|'url'|'phone'|'upi'|'entity',
  value,                    // normalised by the pipeline (you may pass raw): see below
  category,                 // 'phishing'|'malware'|'unauthorised-forex'|'unregistered-investment'|'fraud-report'|'popular-site'|...
  source,                   // your id (overwritten with the module id)
  sourceUrl,                // https? URL of the evidence page (optional, <=512 chars)
  confidence,               // 0..1 (>=0.6 may hard-block in the engine; lower is a weak signal)
  firstSeen, lastSeen,      // ms | ISO string | Date (default: now)
  expiresAt,                // optional; expired records are dropped
  meta                      // optional object, <=1 KB JSON. Recognised: meta.regulator ("SEBI") is named in the verdict
}
```
Normalisation (`lib/ingest/contract.js`): domain = lowercase punycode, no `www.` stripping, no wildcard prefix, must have a dot;
url = http(s) only, lowercase, fragment removed; phone = `+91XXXXXXXXXX` for Indian numbers else `+<digits>`;
upi = lowercase `handle@psp`; entity = lowercase, punctuation-stripped name (3-200 chars).
Invalid records are rejected and counted (`rejected`, `rejectedReasons` in the run stats); duplicates keep the highest confidence.

### Categories the engine acts on
`unauthorised-forex`, `unregistered-investment` => CRITICAL, verdict `REGULATOR_WARNING_LISTED`, "Listed by <meta.regulator || name>".
Any other threat category with confidence >= 0.6 => hard block `THREAT_FEED_LISTED`. `popular-site` is context only (never a block).
Put the regulator in `meta.regulator` so the verdict names it. Phone/UPI/entity records are exposed through
`engine.lookupIndicator(type, rawValue, {threatStore})` for the text engine.

## Do / don't
* Scrapers: identify yourself, keep to the regulator's public pages, never bypass logins/captchas, cache with ETag.
* Prefer machine-readable endpoints (CSV/JSON/RSS) over HTML scraping.
* Do not put personal data in `meta`.

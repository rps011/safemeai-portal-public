'use strict';
/**
 * Threat indicator store.
 *
 * DESIGN
 *  - Source of truth = one *snapshot per source* (a source's latest full feed). Snapshots are gzip-JSON blobs.
 *  - Hot path = in-memory index (Map per indicator type, per source). lookup() is O(1)/O(labels) and NEVER touches
 *    the backend. The index is built at init(), updated immediately after an ingest, and re-synced from the backend
 *    every THREAT_REFRESH_SEC (default 300s) by comparing one tiny metadata doc per source.
 *  - Memory: bulk feeds (millions of plain domains) are stored as value -> small-int profile index (category,
 *    confidence, sourceUrl are shared per profile); only records carrying meta/expiresAt are stored as objects.
 *    Sources with <= 20k records are always kept at full fidelity. ~100 B/domain => 1M domains ~ 100-150 MB.
 *  - Backends only persist opaque blobs + tiny metadata + per-source state:
 *      file/memory  : dev + tests.
 *      firestore    : THREAT_STORE=firestore. Blob is split into <=800 KB chunk docs (Firestore limit 1 MiB/doc),
 *                     written under a new generation id, then the meta doc flips atomically to the new generation and
 *                     the old chunks are deleted. Readers never see a half-written snapshot.
 *    No Cloud Storage dependency; a GCS backend would implement the same 5-method backend interface.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { NON_THREAT_CATEGORIES } = require('./ingest/contract');

const BULK_THRESHOLD = 20000;
const CHUNK_BYTES = 800 * 1024;
const TYPES = ['domain', 'url', 'phone', 'upi', 'entity'];

// ------------------------------------------------------------------------------------------------ backends
function memoryBackend() {
  const sources = new Map(); const state = new Map();
  return {
    kind: 'memory',
    async loadMeta() { const o = {}; for (const [k, v] of sources) o[k] = v.meta; return o; },
    async loadSource(id) { const v = sources.get(id); return v ? v.buf : null; },
    async saveSource(id, buf, meta) { sources.set(id, { buf, meta }); },
    async deleteSource(id) { sources.delete(id); },
    async getState(k) { return state.has(k) ? state.get(k) : null; },
    async setState(k, v) { state.set(k, v); }
  };
}

const safeName = (s) => String(s).replace(/[^a-zA-Z0-9._:-]/g, '_').slice(0, 200);

function fileBackend(dir) {
  dir = dir || process.env.THREAT_STORE_DIR || path.join(os.tmpdir(), 'safeme-threat-store');
  fs.mkdirSync(dir, { recursive: true });
  const stateFile = path.join(dir, '_state.json');
  let state = {};
  try { state = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch (_) {}
  const metaFile = (id) => path.join(dir, safeName(id) + '.meta.json');
  const blobFile = (id) => path.join(dir, safeName(id) + '.snap.gz');
  const atomicWrite = (f, data) => { const t = f + '.tmp' + process.pid; fs.writeFileSync(t, data); fs.renameSync(t, f); };
  return {
    kind: 'file', dir,
    async loadMeta() {
      const o = {};
      for (const f of fs.readdirSync(dir)) {
        if (!f.endsWith('.meta.json')) continue;
        try { const m = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); o[m.id] = m; } catch (_) {}
      }
      return o;
    },
    async loadSource(id) { try { return fs.readFileSync(blobFile(id)); } catch (_) { return null; } },
    async saveSource(id, buf, meta) { atomicWrite(blobFile(id), buf); atomicWrite(metaFile(id), JSON.stringify(meta)); },
    async deleteSource(id) { for (const f of [blobFile(id), metaFile(id)]) { try { fs.unlinkSync(f); } catch (_) {} } },
    async getState(k) { return Object.prototype.hasOwnProperty.call(state, k) ? state[k] : null; },
    async setState(k, v) { state[k] = v; atomicWrite(stateFile, JSON.stringify(state)); }
  };
}

function firestoreBackend(opts = {}) {
  let db = opts.db;
  if (!db) {
    const { Firestore } = require('@google-cloud/firestore'); // lazy: only needed when THREAT_STORE=firestore
    db = new Firestore({
      projectId: process.env.GOOGLE_CLOUD_PROJECT || undefined,
      databaseId: process.env.FIRESTORE_DATABASE || undefined,
      ignoreUndefinedProperties: true
    });
  }
  const p = opts.prefix || process.env.THREAT_FS_PREFIX || 'threat';
  const srcCol = () => db.collection(`${p}_sources`);
  const chunkCol = () => db.collection(`${p}_chunks`);
  const stateCol = () => db.collection(`${p}_state`);
  const chunkId = (id, gen, i) => `${safeName(id)}__${gen}__${String(i).padStart(4, '0')}`;
  return {
    kind: 'firestore',
    async loadMeta() { const o = {}; (await srcCol().get()).forEach(d => { o[d.id] = d.data().meta; }); return o; },
    async loadSource(id) {
      const m = await srcCol().doc(safeName(id)).get();
      if (!m.exists) return null;
      const { gen, chunks } = m.data();
      const parts = [];
      for (let i = 0; i < chunks; i++) {
        const c = await chunkCol().doc(chunkId(id, gen, i)).get();
        if (!c.exists) throw new Error(`threat snapshot ${id} missing chunk ${i}`);
        parts.push(Buffer.from(c.data().data));
      }
      return Buffer.concat(parts);
    },
    async saveSource(id, buf, meta) {
      const prev = await srcCol().doc(safeName(id)).get();
      const gen = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      const n = Math.max(1, Math.ceil(buf.length / CHUNK_BYTES));
      for (let i = 0; i < n; i++) await chunkCol().doc(chunkId(id, gen, i)).set({ data: buf.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES) });
      await srcCol().doc(safeName(id)).set({ meta: { ...meta, gen }, gen, chunks: n, bytes: buf.length, updatedAt: Date.now() });
      if (prev.exists) {
        const { gen: og, chunks: oc } = prev.data();
        if (og !== gen) for (let i = 0; i < oc; i++) { try { await chunkCol().doc(chunkId(id, og, i)).delete(); } catch (_) {} }
      }
    },
    async deleteSource(id) {
      const prev = await srcCol().doc(safeName(id)).get();
      if (prev.exists) { const { gen, chunks } = prev.data(); for (let i = 0; i < chunks; i++) await chunkCol().doc(chunkId(id, gen, i)).delete(); await srcCol().doc(safeName(id)).delete(); }
    },
    async getState(k) { const d = await stateCol().doc(safeName(k)).get(); return d.exists ? JSON.parse(d.data().json) : null; },
    async setState(k, v) { await stateCol().doc(safeName(k)).set({ json: JSON.stringify(v), updatedAt: Date.now() }); }
  };
}

function backendFromEnv(env = process.env) {
  const kind = (env.THREAT_STORE || 'file').toLowerCase();
  if (kind === 'firestore') return firestoreBackend();
  if (kind === 'memory') return memoryBackend();
  return fileBackend();
}

// ------------------------------------------------------------------------------------------------ index
function emptyIndex(meta) {
  const maps = {}; for (const t of TYPES) maps[t] = new Map();
  return { meta, profiles: [], profileKey: new Map(), maps };
}

function profileOf(idx, r) {
  const k = `${r.type}|${r.category}|${r.confidence}|${r.sourceUrl || ''}`;
  let i = idx.profileKey.get(k);
  if (i === undefined) { i = idx.profiles.length; idx.profiles.push({ type: r.type, category: r.category, confidence: r.confidence, sourceUrl: r.sourceUrl }); idx.profileKey.set(k, i); }
  return i;
}

function buildIndex(meta, records, bulkMode) {
  const idx = emptyIndex(meta);
  for (const r of records) {
    if (bulkMode && !r.meta && !r.expiresAt) idx.maps[r.type].set(r.value, profileOf(idx, r));
    else idx.maps[r.type].set(r.value, r);
  }
  idx.meta.count = records.length;
  return idx;
}

function* iterRecords(idx) {
  for (const t of TYPES) for (const [value, e] of idx.maps[t]) yield expand(idx, t, value, e);
}

function expand(idx, type, value, e) {
  const m = idx.meta;
  if (typeof e === 'number') {
    const p = idx.profiles[e];
    return { type, value, category: p.category, source: m.id, sourceName: m.name, sourceUrl: p.sourceUrl, confidence: p.confidence, firstSeen: m.ingestedAt, lastSeen: m.ingestedAt, ingestedAt: m.ingestedAt };
  }
  return { ...e, source: m.id, sourceName: m.name, ingestedAt: m.ingestedAt };
}

function serialize(idx) {
  const tables = {};
  for (const t of TYPES) {
    const plain = {}; const rich = [];
    for (const [v, e] of idx.maps[t]) { if (typeof e === 'number') (plain[e] || (plain[e] = [])).push(v); else rich.push(e); }
    if (rich.length || Object.keys(plain).length) tables[t] = { plain, rich };
  }
  return zlib.gzipSync(Buffer.from(JSON.stringify({ v: 1, meta: idx.meta, profiles: idx.profiles, tables })), { level: 6 });
}

function deserialize(buf) {
  const o = JSON.parse(zlib.gunzipSync(buf).toString('utf8'));
  if (o.v !== 1) throw new Error('unsupported snapshot version');
  const idx = emptyIndex(o.meta);
  idx.profiles = o.profiles;
  o.profiles.forEach((p, i) => idx.profileKey.set(`${p.type}|${p.category}|${p.confidence}|${p.sourceUrl || ''}`, i));
  for (const t of Object.keys(o.tables)) {
    const { plain, rich } = o.tables[t];
    for (const pi of Object.keys(plain)) for (const v of plain[pi]) idx.maps[t].set(v, Number(pi));
    for (const r of rich) idx.maps[t].set(r.value, r);
  }
  return idx;
}

// ------------------------------------------------------------------------------------------------ store
function createStore(opts = {}) {
  const backend = opts.backend || backendFromEnv();
  const log = opts.log || (() => {});
  const nowFn = opts.now || Date.now;
  const index = new Map();           // sourceId -> idx   (replaced atomically by reference)
  let ready = false, lastRefresh = 0, timer = null, loadError = null;

  const store = {
    backend, get ready() { return ready; }, get lastRefresh() { return lastRefresh; }, get loadError() { return loadError; },

    async init() {
      try { await store.refresh({ force: true }); ready = true; loadError = null; }
      catch (e) { loadError = e.message; log('warn', `threat store init failed: ${e.message}`); }
      return store;
    },

    /** Re-sync any source whose persisted generation differs from what we hold. Cheap: metadata only. */
    async refresh({ force = false } = {}) {
      const metas = await backend.loadMeta();
      for (const [id, m] of Object.entries(metas)) {
        const have = index.get(id);
        if (!force && have && have.meta.ingestedAt === m.ingestedAt && have.meta.gen === m.gen) continue;
        try {
          const buf = await backend.loadSource(id);
          if (buf) index.set(id, deserialize(buf));
        } catch (e) { log('warn', `threat store: reload of ${id} failed: ${e.message}`); }
      }
      for (const id of [...index.keys()]) if (!metas[id]) index.delete(id);
      lastRefresh = nowFn(); ready = true;
    },

    startRefreshTimer(sec = Number(process.env.THREAT_REFRESH_SEC) || 300) {
      if (timer) return;
      timer = setInterval(() => { store.refresh().catch(e => log('warn', `threat refresh failed: ${e.message}`)); }, sec * 1000);
      if (timer.unref) timer.unref();
    },
    stopRefreshTimer() { if (timer) clearInterval(timer); timer = null; },

    /**
     * Upsert one source's records (already validated by contract.sanitizeRecords).
     * mode 'snapshot' (default): the record set REPLACES the source's previous set (feeds that publish full lists).
     * mode 'delta': merged into the existing set.
     * @returns {{added:number, removed:number, total:number}}
     */
    async upsertMany(records, { sourceId, sourceMeta = {}, mode = 'snapshot', now = nowFn() } = {}) {
      if (!sourceId) throw new Error('upsertMany requires sourceId');
      const prev = index.get(sourceId);
      let all = records;
      if (mode === 'delta' && prev) {
        const m = new Map();
        for (const r of iterRecords(prev)) m.set(r.type + '\0' + r.value, r);
        for (const r of records) m.set(r.type + '\0' + r.value, r);
        all = [...m.values()];
      }
      all = all.filter(r => !r.expiresAt || r.expiresAt > now);
      const meta = { id: sourceId, name: sourceMeta.name || sourceId, group: sourceMeta.group || 'global', license: sourceMeta.license || null, ingestedAt: now };
      const idx = buildIndex(meta, all, all.length > BULK_THRESHOLD);
      let added = 0, removed = 0;
      for (const t of TYPES) {
        const pm = prev ? prev.maps[t] : null; const nm = idx.maps[t];
        for (const k of nm.keys()) if (!pm || !pm.has(k)) added++;
        if (pm) for (const k of pm.keys()) if (!nm.has(k)) removed++;
      }
      meta.count = all.length;
      await backend.saveSource(sourceId, serialize(idx), meta);   // persist first; memory only flips if durable
      index.set(sourceId, idx);
      return { added, removed, total: all.length };
    },

    /** All hits for exact (type,value). Value must already be normalised (contract.normaliseValue). */
    lookup(type, value) {
      const out = [];
      for (const idx of index.values()) {
        const m = idx.maps[type]; if (!m) continue;
        const e = m.get(value);
        if (e !== undefined) { if (typeof e !== 'number' && e.expiresAt && e.expiresAt <= nowFn()) continue; out.push(expand(idx, type, value, e)); }
      }
      return out;
    },

    /** Hits for host and each parent suffix with >= minLabels labels (a.b.evil.com -> a.b.evil.com, b.evil.com, evil.com). */
    lookupDomainSuffixes(host, { minLabels = 2 } = {}) {
      const labels = String(host || '').toLowerCase().replace(/\.$/, '').split('.');
      const out = [];
      for (let i = 0; labels.length - i >= minLabels; i++) {
        const cand = labels.slice(i).join('.');
        for (const h of store.lookup('domain', cand)) out.push(h);
      }
      return out;
    },

    /** Threat hits only (excludes context categories such as popular-site). */
    lookupThreats(type, value) { return store.lookup(type, value).filter(h => !NON_THREAT_CATEGORIES.has(h.category)); },

    /** Tranco-style popularity rank for an exact registrable domain, or null. */
    popularRank(domain) {
      for (const h of store.lookup('domain', domain)) if (h.category === 'popular-site' && h.meta && Number.isFinite(h.meta.rank)) return { rank: h.meta.rank, source: h.source, ingestedAt: h.ingestedAt };
      return null;
    },

    sourceCount(sourceId) { const i = index.get(sourceId); return i ? i.meta.count : 0; },
    sourceMeta(sourceId) { const i = index.get(sourceId); return i ? { ...i.meta } : null; },

    stats() {
      const sources = {}; let total = 0;
      for (const [id, idx] of index) {
        const byType = {}; for (const t of TYPES) if (idx.maps[t].size) byType[t] = idx.maps[t].size;
        sources[id] = { name: idx.meta.name, group: idx.meta.group, count: idx.meta.count, byType, ingestedAt: idx.meta.ingestedAt };
        total += idx.meta.count;
      }
      return { backend: backend.kind, ready, lastRefresh, totalIndicators: total, sources };
    },

    /** Drop expired records (those with expiresAt) from every source and persist changed sources. */
    async pruneExpired(now = nowFn()) {
      let pruned = 0;
      for (const [id, idx] of [...index]) {
        let dirty = 0;
        for (const t of TYPES) for (const [v, e] of idx.maps[t]) if (typeof e !== 'number' && e.expiresAt && e.expiresAt <= now) { idx.maps[t].delete(v); dirty++; }
        if (dirty) {
          idx.meta.count -= dirty; pruned += dirty;
          await backend.saveSource(id, serialize(idx), idx.meta);
        }
      }
      return pruned;
    },

    async removeSource(id) { await backend.deleteSource(id); index.delete(id); },

    // State is shared between instances (Firestore), so reads always go to the backend (never on the request hot path).
    async getState(key) { return backend.getState(key); },
    async setState(key, value) { await backend.setState(key, value); }
  };
  return store;
}

module.exports = { createStore, memoryBackend, fileBackend, firestoreBackend, backendFromEnv, BULK_THRESHOLD, _internals: { serialize, deserialize, buildIndex } };

'use strict';
/** Discovers source modules at lib/ingest/sources/<group>/<id>.js. A broken module is skipped, never fatal. */
const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, 'sources');

function validateSource(s) {
  if (!s || typeof s !== 'object') return 'not an object';
  if (typeof s.id !== 'string' || !/^[a-z0-9][a-z0-9_-]{1,48}$/.test(s.id)) return 'bad id';
  if (typeof s.name !== 'string' || !s.name) return 'missing name';
  if (s.group !== 'global' && s.group !== 'india') return 'group must be global|india';
  if (typeof s.fetch !== 'function') return 'missing fetch()';
  if (typeof s.license !== 'string' || !s.license) return 'missing license';
  return null;
}

function loadSources({ dir = DIR, log = () => {}, disabled = (process.env.INGEST_SOURCES_DISABLE || '').split(',').map(x => x.trim()).filter(Boolean) } = {}) {
  const out = []; const seen = new Set(); const problems = [];
  let groups = [];
  try { groups = fs.readdirSync(dir, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name).sort(); } catch (_) { return { sources: out, problems }; }
  for (const g of groups) {
    let files = [];
    try { files = fs.readdirSync(path.join(dir, g)).filter(f => f.endsWith('.js') && !f.startsWith('_')).sort(); } catch (_) { continue; }
    for (const f of files) {
      const file = path.join(dir, g, f);
      try {
        const mod = require(file);
        const err = validateSource(mod);
        if (err) { problems.push({ file, error: err }); log('warn', `ingest: skipping ${g}/${f}: ${err}`); continue; }
        if (seen.has(mod.id)) { problems.push({ file, error: 'duplicate id ' + mod.id }); continue; }
        if (disabled.includes(mod.id)) continue;
        seen.add(mod.id); out.push(mod);
      } catch (e) { problems.push({ file, error: e.message }); log('warn', `ingest: failed to load ${g}/${f}: ${e.message}`); }
    }
  }
  return { sources: out, problems };
}

module.exports = { loadSources, validateSource };

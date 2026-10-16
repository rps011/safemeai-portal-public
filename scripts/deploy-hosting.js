#!/usr/bin/env node
'use strict';
/**
 * Deploy safeme-portal/public + firebase.json (hosting config) to Firebase Hosting via the REST API, using the
 * gcloud login (no `firebase login` needed).
 *
 *   node scripts/deploy-hosting.js --channel preview-migrate     # free temporary preview URL (expires in 24h)
 *   node scripts/deploy-hosting.js --live                        # release to the live site (safemeai.in)
 *   node scripts/deploy-hosting.js --rollback <versionId>        # re-release an older version to live
 *
 * Previous live versions are kept by Firebase, so rollback is `--rollback <versionId>` (the version printed before
 * every live release; the pre-migration version is 59f79f11d173a3a7).
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const cfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'firebase.json'), 'utf8')).hosting;
const SITE = cfg.site;
const PROJECT = process.env.GOOGLE_CLOUD_PROJECT || 'fraudshield-daa79c8e';
const API = 'https://firebasehosting.googleapis.com/v1beta1';
const args = process.argv.slice(2);
const flag = n => args.includes(n);
const val = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };

const token = () => execFileSync('gcloud', ['auth', 'print-access-token'], { encoding: 'utf8' }).trim();
let TOKEN = token();
async function call(method, url, body, extra = {}) {
  const r = await fetch(url, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, 'x-goog-user-project': PROJECT, ...(body && !extra.raw ? { 'Content-Type': 'application/json' } : {}), ...(extra.headers || {}) },
    body: extra.raw ? body : (body ? JSON.stringify(body) : undefined)
  });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch (_) { /* not json */ }
  if (!r.ok) throw new Error(`${method} ${url} -> ${r.status} ${text.slice(0, 400)}`);
  return json;
}

function walk(dir, base = dir, out = []) {
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    const rel = '/' + path.relative(base, full).split(path.sep).join('/');
    if (name.startsWith('.') && !rel.startsWith('/.well-known')) continue; // ignore dotfiles except .well-known
    if (cfg.ignore && cfg.ignore.some(g => g === name)) continue;
    if (fs.statSync(full).isDirectory()) walk(full, base, out); else out.push({ rel, full });
  }
  return out;
}

function toHostingConfig() {
  const c = { cleanUrls: cfg.cleanUrls, trailingSlashBehavior: cfg.trailingSlash ? 'ADD' : 'REMOVE' };
  c.rewrites = (cfg.rewrites || []).map(r => ({ glob: r.source, run: r.run }));
  c.headers = (cfg.headers || []).map(h => ({ glob: h.source, headers: Object.fromEntries(h.headers.map(x => [x.key, x.value])) }));
  return c;
}

async function release(versionName, channel) {
  const url = channel
    ? `${API}/sites/${SITE}/channels/${channel}/releases?versionName=${encodeURIComponent(versionName)}`
    : `${API}/sites/${SITE}/releases?versionName=${encodeURIComponent(versionName)}`;
  return call('POST', url, {});
}

async function main() {
  if (flag('--rollback')) {
    const id = val('--rollback');
    if (!id) throw new Error('--rollback needs a version id');
    const rel = await release(`sites/${SITE}/versions/${id}`, null);
    console.log('rolled back live to version', id, rel.name);
    return;
  }
  const channel = val('--channel');
  if (!channel && !flag('--live')) throw new Error('pass --channel <id> or --live');

  if (flag('--live')) {
    const cur = await call('GET', `${API}/sites/${SITE}/releases?pageSize=1`);
    const prev = cur.releases && cur.releases[0] && cur.releases[0].version.name.split('/').pop();
    console.log('current live version (rollback target):', prev);
  }

  const files = walk(path.join(ROOT, cfg.public));
  const hashes = {}; const byHash = {};
  for (const f of files) {
    const gz = zlib.gzipSync(fs.readFileSync(f.full), { level: 9 });
    const h = crypto.createHash('sha256').update(gz).digest('hex');
    hashes[f.rel] = h; byHash[h] = gz;
  }
  console.log(`files: ${files.length}`);

  const version = await call('POST', `${API}/sites/${SITE}/versions`, { config: toHostingConfig() });
  const vname = version.name;
  const pop = await call('POST', `${API}/${vname}:populateFiles`, { files: hashes });
  const need = pop.uploadRequiredHashes || [];
  console.log(`uploading ${need.length} of ${files.length} files`);
  for (const h of need) {
    await call('POST', `${pop.uploadUrl}/${h}`, byHash[h], { raw: true, headers: { 'Content-Type': 'application/octet-stream' } });
  }
  await call('PATCH', `${API}/${vname}?update_mask=status`, { status: 'FINALIZED' });

  if (channel) {
    try { await call('POST', `${API}/sites/${SITE}/channels?channelId=${channel}`, { ttl: '86400s' }); } catch (e) { if (!/ALREADY_EXISTS|409/.test(e.message)) throw e; }
    await release(vname, channel);
    const ch = await call('GET', `${API}/sites/${SITE}/channels/${channel}`);
    console.log('preview URL:', ch.url, '(expires', ch.expireTime + ')');
  } else {
    const rel = await release(vname, null);
    console.log('LIVE release:', rel.name, 'version', vname.split('/').pop());
  }
}
main().catch(e => { console.error('FAILED:', e.message); process.exit(1); });

'use strict';
// Minimal Google Cloud REST helpers (no npm deps). Auth = Cloud Run metadata-server ADC.
// All callers must treat every function here as "may be unavailable" and fall back honestly.

async function fetchJson(url, { timeoutMs = 4000, headers = {}, method = 'GET', body } = {}) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ac.signal, redirect: 'error', headers, method, body });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch (_) { /* non-json */ }
    return { ok: r.ok, status: r.status, json, text };
  } finally {
    clearTimeout(t);
  }
}

const status = require('./systemStatus');
const META = 'http://metadata.google.internal/computeMetadata/v1/';
let tokenCache = { token: null, exp: 0 };
async function getAdcToken() {
  if (tokenCache.token && Date.now() < tokenCache.exp) return tokenCache.token;
  const r = await fetchJson(META + 'instance/service-accounts/default/token', { timeoutMs: 800, headers: { 'Metadata-Flavor': 'Google' } });
  if (!r.ok || !r.json || !r.json.access_token) throw new Error('no ADC token (not running on Google Cloud?)');
  tokenCache = { token: r.json.access_token, exp: Date.now() + (r.json.expires_in - 60) * 1000 };
  return tokenCache.token;
}

async function projectId() {
  if (process.env.GOOGLE_CLOUD_PROJECT) return process.env.GOOGLE_CLOUD_PROJECT;
  if (projectIdCache) return projectIdCache; // metadata lookups on every call added latency and flakiness
  const r = await fetchJson(META + 'project/project-id', { timeoutMs: 800, headers: { 'Metadata-Flavor': 'Google' } });
  if (!r.ok) throw new Error('no project id');
  projectIdCache = r.text.trim();
  return projectIdCache;
}
let projectIdCache = null;

/** Is this IP literal public-routable? (SSRF guard for anything that connects to user-supplied hosts.) */
function isPublicIp(ip) {
  ip = String(ip || '').toLowerCase();
  if (ip.includes(':')) {
    if (ip === '::1' || ip === '::' || /^f[cd]/.test(ip) || /^fe[89ab]/.test(ip)) return false;
    const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return m ? isPublicIp(m[1]) : true;
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || (b === 0 && p[2] === 0))) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  return true;
}

// ---- Gemini (Vertex AI via ADC, or Gemini API key) -------------------------
const GEMINI_MODEL = () => process.env.GEMINI_MODEL || 'gemini-2.5-flash';

async function geminiGenerate({ system, userText, maxOutputTokens = 800, timeoutMs = 8000 }) {
  if (process.env.DISABLE_GEMINI === '1') return { available: false, reason: 'disabled by DISABLE_GEMINI=1' };
  const body = {
    systemInstruction: { parts: [{ text: system }] },
    contents: [{ role: 'user', parts: [{ text: userText }] }],
    generationConfig: { temperature: 0, responseMimeType: 'application/json', maxOutputTokens: Math.max(maxOutputTokens, 2048), thinkingConfig: { thinkingBudget: 0 } }
  };
  try {
    let url; const headers = { 'Content-Type': 'application/json' }; let via;
    if (process.env.GEMINI_API_KEY) {
      url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL()}:generateContent`;
      headers['x-goog-api-key'] = process.env.GEMINI_API_KEY;
      via = 'Gemini API';
    } else {
      const [tok, proj] = await Promise.all([getAdcToken(), projectId()]);
      const loc = process.env.VERTEX_LOCATION || 'asia-south1'; // India region by default (data residency)
      url = `https://${loc}-aiplatform.googleapis.com/v1/projects/${proj}/locations/${loc}/publishers/google/models/${GEMINI_MODEL()}:generateContent`;
      headers.Authorization = `Bearer ${tok}`;
      via = 'Vertex AI';
    }
    // One bounded retry on 429 / 5xx / network error inside the single overall deadline (timeoutMs).
    const payload = JSON.stringify(body);
    const t0 = Date.now();
    let r = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const left = timeoutMs - (Date.now() - t0);
      if (left < 600) break;
      try {
        r = await fetchJson(url, { method: 'POST', headers, body: payload, timeoutMs: left });
        if (r.ok || (r.status !== 429 && r.status < 500)) break;
      } catch (e) {
        if ((e && e.name === 'AbortError') || attempt === 1) throw e;
        r = null;
      }
      await new Promise(res => setTimeout(res, 250));
    }
    if (!r) throw new Error('Gemini unreachable');
    if (!r.ok) { status.note('gemini', false, `HTTP ${r.status}`); return { available: false, reason: `Gemini HTTP ${r.status}`, via }; }
    const parts = r.json && r.json.candidates && r.json.candidates[0] && r.json.candidates[0].content && r.json.candidates[0].content.parts;
    const text = (parts || []).map(p => p.text || '').join('');
    status.note('gemini', true);
    return { available: true, via, model: GEMINI_MODEL(), text };
  } catch (e) {
    status.note('gemini', false, e.name === 'AbortError' ? 'timeout' : e.message);
    return { available: false, reason: e.name === 'AbortError' ? 'Gemini timeout' : e.message };
  }
}

// ---- Document AI (optional) -------------------------------------------------
// DOCUMENT_AI_PROCESSOR = projects/<num>/locations/<us|eu>/processors/<id>
async function documentAiOcr(buffer, mimeType) {
  const proc = process.env.DOCUMENT_AI_PROCESSOR;
  if (!proc) return { available: false, reason: 'DOCUMENT_AI_PROCESSOR not configured' };
  const m = proc.match(/^projects\/[^/]+\/locations\/([a-z0-9-]+)\/processors\/[A-Za-z0-9]+$/);
  if (!m) return { available: false, reason: 'DOCUMENT_AI_PROCESSOR malformed' };
  try {
    const tok = await getAdcToken();
    const r = await fetchJson(`https://${m[1]}-documentai.googleapis.com/v1/${proc}:process`, {
      method: 'POST', timeoutMs: 20000,
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawDocument: { content: buffer.toString('base64'), mimeType } })
    });
    if (!r.ok) return { available: false, reason: `Document AI HTTP ${r.status}` };
    const text = r.json && r.json.document && r.json.document.text;
    return text ? { available: true, text: String(text).slice(0, 20000) } : { available: false, reason: 'Document AI returned no text' };
  } catch (e) {
    return { available: false, reason: e.name === 'AbortError' ? 'Document AI timeout' : e.message };
  }
}

// ---- BigQuery (optional) ----------------------------------------------------
// BIGQUERY_DATASET=<dataset>; expects table `threat_events(vector STRING, event_ts TIMESTAMP)`.
async function bigQueryTopVectors() {
  const ds = process.env.BIGQUERY_DATASET;
  if (!ds || !/^[A-Za-z0-9_]+$/.test(ds)) return { available: false, reason: 'BIGQUERY_DATASET not configured' };
  try {
    const [tok, proj] = await Promise.all([getAdcToken(), projectId()]);
    const query = `SELECT vector, COUNT(*) AS cnt FROM \`${proj}.${ds}.threat_events\` WHERE event_ts > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR) GROUP BY vector ORDER BY cnt DESC LIMIT 5`;
    const r = await fetchJson(`https://bigquery.googleapis.com/bigquery/v2/projects/${proj}/queries`, {
      method: 'POST', timeoutMs: 10000,
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, useLegacySql: false, timeoutMs: 8000 })
    });
    if (!r.ok || !r.json || !r.json.rows) return { available: false, reason: `BigQuery HTTP ${r.status}` };
    const rows = r.json.rows.map(x => ({ vector: String(x.f[0].v), count: Number(x.f[1].v) }));
    const total = rows.reduce((s, x) => s + x.count, 0) || 1;
    return { available: true, query, rows: rows.map(x => ({ ...x, share: Math.round(100 * x.count / total) })) };
  } catch (e) {
    return { available: false, reason: e.message };
  }
}

module.exports = { fetchJson, getAdcToken, projectId, isPublicIp, geminiGenerate, documentAiOcr, bigQueryTopVectors };

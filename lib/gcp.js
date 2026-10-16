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
// DOCUMENT_AI_PROCESSOR = projects/<num>/locations/<region>/processors/<id> (we use asia-south1)
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

// ---- BigQuery (jobs.query, parameterised) ------------------------------------
// Runs ONE fixed SQL statement with named query parameters as the runtime service account.
// Callers pass SQL text they control; user input never reaches `sql` (values go through `params`).
const BQ_LOCATION = () => process.env.BIGQUERY_LOCATION || 'asia-south1';

function bqValue(type, v) {
  if (v == null) return null;
  if (type === 'INTEGER' || type === 'INT64') return Number(v);
  if (type === 'FLOAT' || type === 'FLOAT64' || type === 'NUMERIC') return Number(v);
  if (type === 'BOOLEAN' || type === 'BOOL') return v === true || v === 'true';
  if (type === 'TIMESTAMP') return new Date(Number(v) * 1000).toISOString();
  return String(v);
}

/**
 * @param {{sql:string, params?:Array<{name:string,type:string,value:any}>, maxBytesBilled?:number, timeoutMs?:number, fetchImpl?:Function}} o
 * @returns {Promise<{available:true, rows:object[], bytesProcessed:number, cacheHit:boolean}|{available:false, reason:string}>}
 */
async function bigQueryQuery({ sql, params = [], maxBytesBilled = 100 * 1024 * 1024, timeoutMs = 5000, fetchImpl } = {}) {
  try {
    const [tok, proj] = await Promise.all([getAdcToken(), projectId()]);
    const body = {
      query: sql, useLegacySql: false, location: BQ_LOCATION(), timeoutMs, maxResults: 1000,
      maximumBytesBilled: String(maxBytesBilled), useQueryCache: true,
      parameterMode: 'NAMED',
      queryParameters: params.map(p => ({ name: p.name, parameterType: { type: p.type }, parameterValue: { value: String(p.value) } }))
    };
    const r = await (fetchImpl || fetchJson)(`https://bigquery.googleapis.com/bigquery/v2/projects/${encodeURIComponent(proj)}/queries`, {
      method: 'POST', timeoutMs: timeoutMs + 1500,
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!r.ok) {
      const msg = r.json && r.json.error && r.json.error.message;
      return { available: false, reason: `BigQuery HTTP ${r.status}${msg ? ': ' + String(msg).slice(0, 160) : ''}` };
    }
    const j = r.json;
    if (!j || j.jobComplete !== true) return { available: false, reason: 'BigQuery query did not finish within the time limit' };
    const fields = (j.schema && j.schema.fields) || [];
    const rows = (j.rows || []).map(row => {
      const o = {};
      fields.forEach((f, i) => { o[f.name] = bqValue(f.type, row.f && row.f[i] ? row.f[i].v : null); });
      return o;
    });
    return { available: true, rows, bytesProcessed: Number(j.totalBytesProcessed || 0), cacheHit: j.cacheHit === true };
  } catch (e) {
    return { available: false, reason: e.name === 'AbortError' ? 'BigQuery timeout' : String(e.message || e).slice(0, 200) };
  }
}

module.exports = { fetchJson, getAdcToken, projectId, isPublicIp, geminiGenerate, documentAiOcr, bigQueryQuery };

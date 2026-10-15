'use strict';
// Audit trail: one structured JSON line per check request on stdout (Cloud Logging ingests it as jsonPayload).
// Never logs raw input or raw IPs: input is SHA-256 hashed, client is an HMAC of the /24 (IPv4) or /48 (IPv6).
// Optional BigQuery streaming sink (AUDIT_BIGQUERY_TABLE=dataset.table), batched and fail-safe, OFF by default.
const crypto = require('crypto');
const pkg = require('../package.json');
const gcp = require('./gcp');
const status = require('./systemStatus');

const AUDITED = /^\/api\/(scam\/check|domain\/check|gemini\/advisor|document-ai\/analyze|emergency\/|v1\/batch)/;
const NO_AUGMENT = /^\/api\/v1\/(blocklist|admin)\//;
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');

function engineVersion(env = process.env) {
  const sha = String(env.GIT_SHA || '').trim().slice(0, 12);
  return sha ? `${pkg.version}+${sha}` : pkg.version;
}

function detectInputType(input) {
  const s = String(input == null ? '' : input).trim();
  if (!s) return 'empty';
  if (/^[\w.\-]{2,64}@[a-z][a-z0-9]{1,30}$/i.test(s)) return 'upi';
  if (/^(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}$/.test(s)) return 'phone';
  if (!/\s/.test(s) && (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || /^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:[\/?#]|$)/i.test(s))) return 'url';
  return 'message';
}

function networkKey(ip, secret) {
  let net = String(ip || 'unknown').replace(/^::ffff:/, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(net)) net = net.split('.').slice(0, 3).join('.') + '.0/24';
  else if (net.includes(':')) net = net.split(':').slice(0, 3).join(':') + '::/48';
  return crypto.createHmac('sha256', secret).update(net).digest('hex').slice(0, 24);
}

function pick(o, keys) { for (const k of keys) if (o && o[k] != null) return o[k]; return undefined; }

/** Pull verdict / riskScore out of any of our response shapes without depending on one. */
function extractOutcome(body) {
  const d = (body && typeof body === 'object' && body.data && typeof body.data === 'object') ? body.data : body || {};
  const an = d.analysis || {};
  const verdict = pick(d, ['verdict', 'riskLevel', 'level']) ?? pick(an, ['verdict']) ?? pick(body || {}, ['verdict', 'level']);
  const riskScore = pick(d, ['riskScore', 'score']) ?? pick(an, ['riskScore']) ?? pick(body || {}, ['riskScore']);
  return { verdict: verdict == null ? null : String(verdict).slice(0, 80), riskScore: Number.isFinite(Number(riskScore)) ? Number(riskScore) : null };
}

function geminiUsed(body) {
  const d = (body && body.data) || body || {};
  return Boolean(d.dataSource === 'gemini-live' || (d.gemini && d.gemini.available) ||
    (d.agenticAi && /gemini/i.test(JSON.stringify(d.agenticAi.engine || d.agenticAi.model || ''))));
}

function createAudit({ env = process.env, out = line => process.stdout.write(line + '\n'), getSnapshotTs = () => null, fetchImpl } = {}) {
  let secret = env.AUDIT_HMAC_SECRET;
  let ephemeral = false;
  if (!secret) { secret = crypto.randomBytes(32).toString('hex'); ephemeral = true; }
  const ver = engineVersion(env);
  const table = env.AUDIT_BIGQUERY_TABLE && /^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$/.test(env.AUDIT_BIGQUERY_TABLE) ? env.AUDIT_BIGQUERY_TABLE : null;
  const MAX_BUF = 1000, BATCH = 50;
  let buf = [], lastError = null, timer = null, inflight = null;

  async function flush() {
    if (!table || !buf.length) return inflight || undefined;
    const rows = buf.splice(0, buf.length);
    inflight = (async () => {
      try {
        const [tok, proj] = await Promise.all([gcp.getAdcToken(), gcp.projectId()]);
        const [ds, tb] = table.split('.');
        const r = await gcp.fetchJson(`https://bigquery.googleapis.com/bigquery/v2/projects/${proj}/datasets/${ds}/tables/${tb}/insertAll`, {
          method: 'POST', timeoutMs: 6000, headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ skipInvalidRows: true, ignoreUnknownValues: true, rows: rows.map(r => ({ insertId: r.requestId + ':' + r.endpoint, json: bqRow(r) })) })
        });
        if (!r.ok || (r.json && r.json.insertErrors)) throw new Error('insertAll HTTP ' + r.status);
        lastError = null;
      } catch (e) { lastError = String(e.message).slice(0, 160); /* fail-safe: drop, never block requests */ }
    })();
    await inflight; inflight = null;
  }
  if (table) { timer = setInterval(() => { flush(); }, 5000); if (timer.unref) timer.unref(); }

  function record(rec) {
    const line = { severity: 'INFO', message: 'audit', logType: 'safemeai.audit', ...rec };
    try { out(JSON.stringify(line)); } catch (_) { /* never throw from logging */ }
    if (table) { if (buf.length >= MAX_BUF) buf.shift(); buf.push(rec); if (buf.length >= BATCH) flush(); }
  }

  /** Express middleware: request id, response augmentation, audit line on finish. */
  function middleware() {
    return (req, res, next) => {
      const inbound = String(req.headers['x-request-id'] || '');
      const requestId = /^[A-Za-z0-9._-]{8,80}$/.test(inbound) ? inbound : crypto.randomUUID();
      req.requestId = requestId;
      res.setHeader('x-request-id', requestId);
      const t0 = process.hrtime.bigint();
      let sent = null;
      const origJson = res.json.bind(res);
      res.json = body => {
        if (req.path.startsWith('/api/') && !NO_AUGMENT.test(req.path) && body && typeof body === 'object' && !Array.isArray(body)) {
          body = { ...body, requestId, engineVersion: ver };
        }
        sent = body;
        return origJson(body);
      };
      res.on('finish', () => {
        try {
          const p = req.path;
          // domain-check responses reveal whether Web Risk answered
          const wr = sent && sent.data && sent.data.threatFeeds && sent.data.threatFeeds.webRisk;
          if (wr) status.note('webRisk', Boolean(wr.available), wr.reason || 'unavailable');
          if (req.method !== 'POST' || !AUDITED.test(p)) return;
          const b = req.body && typeof req.body === 'object' ? req.body : {};
          let text, inputType;
          if (req.file) { text = `file:${req.file.mimetype}:${req.file.size}:${req.file.originalname}`; inputType = 'document-file'; }
          else if (/document-ai/.test(p)) { text = String(b.specimenKey || b.customText || ''); inputType = b.specimenKey ? 'specimen' : 'document-text'; }
          else if (/emergency/.test(p)) { text = JSON.stringify(b); inputType = 'questionnaire'; }
          else if (/batch/.test(p)) { text = JSON.stringify(b.items || ''); inputType = 'batch'; }
          else { text = String(pick(b, ['text', 'url', 'domain', 'prompt', 'input']) ?? ''); inputType = /domain/.test(p) ? (detectInputType(text) === 'url' ? 'url' : 'domain') : detectInputType(text); }
          const o = extractOutcome(sent);
          const ip = req.internalIp || req.ip;
          record({
            timestamp: new Date().toISOString(), requestId, endpoint: p, route: req.originalUrl.split('?')[0],
            httpStatus: res.statusCode, apiKeyId: (req.apiAuth && req.apiAuth.keyId) || 'anon',
            clientNetHash: networkKey(ip, secret), inputType, inputHash: sha256(text), inputLength: text.length,
            verdict: o.verdict, riskScore: o.riskScore, engineVersion: ver,
            dataSources: { threatStoreSnapshotTs: getSnapshotTs() ? new Date(getSnapshotTs()).toISOString() : null, geminiUsed: geminiUsed(sent) },
            latencyMs: Math.round(Number(process.hrtime.bigint() - t0) / 1e6)
          });
        } catch (_) { /* audit must never break a response */ }
      });
      next();
    };
  }

  return {
    record, flush, middleware, engineVersion: ver, networkKey: ip => networkKey(ip, secret),
    ephemeralSecret: ephemeral, bigQueryEnabled: Boolean(table),
    sinkStatus: () => ({ bigQueryEnabled: Boolean(table), buffered: buf.length, lastError }),
    stop() { if (timer) clearInterval(timer); }
  };
}

function bqRow(r) {
  return {
    timestamp: r.timestamp, request_id: r.requestId, endpoint: r.endpoint, api_key_id: r.apiKeyId, client_net_hash: r.clientNetHash,
    input_type: r.inputType, input_hash: r.inputHash, input_length: r.inputLength, verdict: r.verdict, risk_score: r.riskScore,
    engine_version: r.engineVersion, gemini_used: r.dataSources.geminiUsed, snapshot_ts: r.dataSources.threatStoreSnapshotTs,
    latency_ms: r.latencyMs, http_status: r.httpStatus
  };
}

module.exports = { createAudit, detectInputType, engineVersion, extractOutcome, networkKey, sha256, AUDITED };

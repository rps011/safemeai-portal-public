'use strict';
// OpenAPI 3.0 spec + a dependency-free human docs page (no CDN, no scripts).

const errRef = { $ref: '#/components/schemas/Error' };
const errResp = d => ({ description: d, content: { 'application/json': { schema: errRef } } });
const std = {
  '400': errResp('Invalid input (code BAD_REQUEST / BAD_JSON)'),
  '401': errResp('Invalid API key (code INVALID_API_KEY)'),
  '413': errResp('Body larger than 64 KB (code PAYLOAD_TOO_LARGE)'),
  '429': { description: 'Rate limited (code RATE_LIMITED). See Retry-After.', headers: { 'Retry-After': { schema: { type: 'integer' } } }, content: { 'application/json': { schema: errRef } } },
  '500': errResp('Internal error (code INTERNAL, includes requestId)')
};
const ok = (d, schema) => ({ description: d, content: { 'application/json': { schema } } });
const verdictData = { type: 'object', description: 'Verdict payload. Stable fields: verdict, riskScore (0-100), riskLevel; more fields may be added.', additionalProperties: true };
const resultSchema = { type: 'object', properties: { status: { type: 'string', example: 'success' }, data: verdictData, requestId: { type: 'string' }, engineVersion: { type: 'string' } } };
const body = (props, required) => ({ required: true, content: { 'application/json': { schema: { type: 'object', required, properties: props } } } });

function buildSpec({ version = '1.0.0' } = {}) {
  return {
    openapi: '3.0.3',
    info: {
      title: 'SafeMeAI Fraud Defence API', version,
      description: 'Scam message, URL, UPI and phone verdicts for Indian banking/UPI users. Anonymous use is allowed (free tier). Optional API keys raise limits: send header X-API-Key: <keyId>.<secret>. Every response carries requestId and engineVersion and an x-request-id header. Verdicts are decision support, not a guarantee of safety; unknown inputs are never reported as safe.'
    },
    servers: [{ url: '/' }],
    tags: [{ name: 'check' }, { name: 'ops' }],
    components: {
      securitySchemes: { ApiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key', description: '<keyId>.<secret>. Optional; omit for anonymous free tier.' } },
      schemas: {
        Error: { type: 'object', required: ['error'], properties: { error: { type: 'string' }, code: { type: 'string', enum: ['BAD_REQUEST', 'BAD_JSON', 'INVALID_API_KEY', 'PAYLOAD_TOO_LARGE', 'RATE_LIMITED', 'INTERNAL'] }, retryAfterSec: { type: 'integer' }, requestId: { type: 'string' } } },
        CheckResult: resultSchema
      }
    },
    security: [{}, { ApiKey: [] }],
    paths: {
      '/api/v1/check': { post: { tags: ['check'], summary: 'Auto-detecting check (message, URL, UPI id, phone)', description: 'Detects the input type and runs the same engine as /api/scam/check. Rate-limit group: check.', requestBody: body({ input: { type: 'string', maxLength: 5000, description: 'Text, URL, UPI id or phone number. Alias fields: text, url.' } }, ['input']), responses: { '200': ok('Verdict', { $ref: '#/components/schemas/CheckResult' }), ...std } } },
      '/api/v1/message/check': { post: { tags: ['check'], summary: 'Check an SMS/WhatsApp message', requestBody: body({ text: { type: 'string', maxLength: 5000 } }, ['text']), responses: { '200': ok('Verdict', { $ref: '#/components/schemas/CheckResult' }), ...std } } },
      '/api/v1/domain/check': { post: { tags: ['check'], summary: 'Check a domain or URL', requestBody: body({ url: { type: 'string', maxLength: 2048 }, domain: { type: 'string', maxLength: 2048 } }, []), responses: { '200': ok('Domain assessment', { $ref: '#/components/schemas/CheckResult' }), ...std } } },
      '/api/v1/batch': { post: { tags: ['check'], summary: 'Check up to 20 items', description: 'Items are strings or {input, type?: "domain"}. Concurrency 4. Consumes 1 + ceil(n/10) units of the check quota. Per-item errors do not fail the batch.', requestBody: body({ items: { type: 'array', minItems: 1, maxItems: 20, items: { oneOf: [{ type: 'string' }, { type: 'object', properties: { input: { type: 'string' }, type: { type: 'string', enum: ['domain', 'auto'] } } }] } } }, ['items']), responses: { '200': ok('Per-item results in input order', { type: 'object', properties: { status: { type: 'string' }, count: { type: 'integer' }, quotaUnits: { type: 'integer' }, results: { type: 'array', items: { type: 'object', properties: { index: { type: 'integer' }, httpStatus: { type: 'integer' }, result: { type: 'object' }, error: { type: 'string' } } } } } }), ...std } } },
      '/api/gemini/advisor': { post: { tags: ['check'], summary: 'AI fraud advisor (Gemini on Vertex AI, rules fallback)', description: 'Input is PII-redacted before it reaches Gemini. Rate-limit group: gemini (10/min).', requestBody: body({ prompt: { type: 'string', maxLength: 2000 } }, ['prompt']), responses: { '200': ok('Advice', { $ref: '#/components/schemas/CheckResult' }), ...std } } },
      '/api/document-ai/analyze': { post: { tags: ['check'], summary: 'Analyse a document (multipart: document file PDF/PNG/JPG/TXT up to 5 MB, or customText)', description: 'Rate-limit group: doc (6/min).', responses: { '200': ok('Analysis', { $ref: '#/components/schemas/CheckResult' }), ...std } } },
      '/api/v1/openapi.json': { get: { tags: ['ops'], summary: 'This specification', responses: { '200': { description: 'OpenAPI 3.0 JSON' } } } },
      '/api/system/status': { get: { tags: ['ops'], summary: 'Which backing services are really live (cached 30 s, no secrets)', responses: { '200': { description: 'Status' } } } },
      '/api/health': { get: { tags: ['ops'], summary: 'Liveness probe (also /health)', responses: { '200': { description: 'ok' } } } }
    },
    'x-rate-limits': {
      note: 'Token buckets per route group, keyed by API key id, else client IP. Per Cloud Run instance. Pilot tier = 5x.',
      groups: { check: { burst: 20, perMinute: 30 }, gemini: { burst: 10, perMinute: 10 }, doc: { burst: 6, perMinute: 6 }, general: { burst: 60, perMinute: 120 } },
      headers: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'X-RateLimit-Group', 'Retry-After (429 only)']
    }
  };
}

const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function docsHtml(spec) {
  const rows = [];
  for (const [p, ops] of Object.entries(spec.paths)) for (const [m, op] of Object.entries(ops)) {
    const schema = op.requestBody && op.requestBody.content['application/json'].schema;
    rows.push(`<section><h3><span class="m">${esc(m.toUpperCase())}</span> ${esc(p)}</h3><p>${esc(op.summary)}</p>${op.description ? `<p class="d">${esc(op.description)}</p>` : ''}` +
      (schema ? `<h4>Request body</h4><pre>${esc(JSON.stringify(schema.properties, null, 2))}</pre>` : '') +
      `<h4>Responses</h4><ul>${Object.entries(op.responses).map(([c, r]) => `<li><b>${esc(c)}</b> ${esc(r.description)}</li>`).join('')}</ul></section>`);
  }
  const rl = spec['x-rate-limits'];
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SafeMeAI API docs</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:0 auto;padding:16px;color:#14202b;background:#fff}pre{background:#f3f5f7;padding:10px;overflow:auto;border-radius:6px}section{border-top:1px solid #dde3e8;margin-top:18px}.m{background:#0b6b3a;color:#fff;border-radius:4px;padding:1px 7px;font-size:13px}.d{color:#44525e}@media(prefers-color-scheme:dark){body{background:#10161c;color:#e4eaef}pre{background:#1a232b}section{border-color:#2a3640}.d{color:#9fb0bd}}</style></head><body>
<h1>SafeMeAI Fraud Defence API <small>v${esc(spec.info.version)}</small></h1><p>${esc(spec.info.description)}</p>
<h2>Authentication</h2><p>Optional. Send <code>X-API-Key: &lt;keyId&gt;.&lt;secret&gt;</code>. Invalid key: 401 <code>INVALID_API_KEY</code>. No key: anonymous free tier.</p>
<h2>Rate limits</h2><p>${esc(rl.note)}</p><pre>${esc(JSON.stringify(rl.groups, null, 2))}</pre><p>Headers: ${rl.headers.map(h => `<code>${esc(h)}</code>`).join(', ')}. A 429 returns <code>{"error","code":"RATE_LIMITED","retryAfterSec"}</code>.</p>
<h2>Error codes</h2><pre>${esc(JSON.stringify(spec.components.schemas.Error.properties.code.enum, null, 2))}</pre>
<h2>Endpoints</h2>${rows.join('')}
<p><a href="/api/v1/openapi.json">openapi.json</a></p></body></html>`;
}

module.exports = { buildSpec, docsHtml };

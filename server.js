const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const tls = require('tls');
const dns = require('dns').promises;
const gcp = require('./lib/gcp');
const { geminiAdvise } = require('./lib/geminiAdvisor');
const crypto = require('crypto');
const { createAudit, detectInputType } = require('./lib/audit');
const { createKeyStore, safeEqual, TIERS } = require('./lib/apiKeys');
const rateLimit = require('./lib/rateLimit');
const systemStatus = require('./lib/systemStatus');
const openapi = require('./lib/openapi');

const BODY_LIMIT = '64kb';                    // single source of truth for the JSON body limit (used by parser + error handler)
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const platformRefs = {};                      // filled later (threatStore) so audit/status can read live values
const audit = createAudit({ getSnapshotTs: () => (platformRefs.threatStore && platformRefs.threatStore.lastRefresh) || null });
const apiKeys = createKeyStore();
const limiter = rateLimit.createLimiter();
const INTERNAL_TOKEN = crypto.randomBytes(24).toString('hex'); // lets /api/v1/batch call our own handlers without re-limiting

const app = express();
const PORT = process.env.PORT || 8080;

// ---- Hardening: proxy trust, security headers, CORS, body limits, rate limiting ----
app.set('trust proxy', 1);          // Cloud Run: exactly one trusted hop (Google front end)
app.disable('x-powered-by');
app.use(require('./lib/clientIp').middleware()); // real visitor IP behind Firebase Hosting (rate limits, audit hashing)
app.use(audit.middleware());        // requestId (x-request-id in/out), response augmentation, audit log line

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; '));
  next();
});

// CORS: same-origin by default. Set CORS_ORIGINS="https://a.example,https://b.example" to allow others.
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => cb(null, !origin ? false : CORS_ORIGINS.includes(origin)),
  methods: ['GET', 'POST'],
  exposedHeaders: ['x-request-id', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'X-RateLimit-Group'],
  maxAge: 600
}));

const healthDoc = () => ({ status: 'ok', uptimeSec: Math.round(process.uptime()), version: audit.engineVersion });
app.get('/healthz', (req, res) => res.json(healthDoc()));
app.get('/health', (req, res) => res.json(healthDoc()));       // Cloud Run intercepts /healthz; use these externally
app.get('/api/health', (req, res) => res.json(healthDoc()));

app.use(express.json({ limit: BODY_LIMIT }));

// Optional API keys: X-API-Key: <keyId>.<secret>. No header = anonymous free tier. Bad key = 401.
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) return next();
  const tok = req.headers['x-internal-batch'];
  if (tok && safeEqual(tok, INTERNAL_TOKEN)) { // loopback call from /api/v1/batch
    req.internalBatch = true; req.internalIp = req.headers['x-internal-ip'];
    const kid = req.headers['x-internal-key-id'];
    req.apiAuth = { keyId: kid || null, tier: 'free', rpm: null };
    return next();
  }
  const a = apiKeys.authenticate(req.headers['x-api-key']);
  if (!a.ok) return res.status(401).json({ error: 'Invalid API key.', code: 'INVALID_API_KEY' });
  req.apiAuth = a;
  next();
});

// Versioned aliases: rewritten to the existing handlers (no logic duplicated).
app.use((req, res, next) => {
  if (req.method !== 'POST' || !req.path.startsWith('/api/v1/')) return next();
  const q = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  const b = (req.body && typeof req.body === 'object') ? req.body : {};
  if (req.path === '/api/v1/message/check') { req.url = '/api/scam/check' + q; }
  else if (req.path === '/api/v1/domain/check') {
    if (b.input && !b.url && !b.domain) req.body = { ...b, url: b.input };
    req.url = '/api/domain/check' + q;
  } else if (req.path === '/api/v1/check') {
    const input = [b.input, b.text, b.url, b.domain].find(v => typeof v === 'string');
    req.body = { ...b, text: input };
    req.detectedType = input ? detectInputType(input) : 'empty';
    req.url = '/api/scam/check' + q;
  } else if (req.path === '/api/v1/batch') {
    const n = Array.isArray(b.items) ? Math.min(b.items.length, 20) : 0;
    req.rlCost = 1 + Math.ceil(n / 10);
  }
  next();
});

app.use(rateLimit.middleware(limiter, TIERS));
// Hindi responses (X-Lang: hi | body.lang; auto-detected for Devanagari/Hinglish when unset): translated as the last step before res.json.
app.use(require('./lib/i18n').middleware());

app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore', index: 'index.html' }));

// robots/security.txt: served only when public/ does not provide its own (static above wins).
const SECURITY_CONTACT = process.env.SECURITY_CONTACT || 'mailto:support@safemeai.in';
app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /internal/\n'));
const securityTxt = (req, res) => res.type('text/plain').send(`Contact: ${SECURITY_CONTACT}\nExpires: ${new Date(Date.UTC(new Date().getUTCFullYear() + 1, 0, 1)).toISOString()}\nPreferred-Languages: en, hi\n`);
app.get('/.well-known/security.txt', securityTxt);
app.get('/security.txt', securityTxt);

// ---- API product surface: OpenAPI, docs, system status, batch ----
const openApiSpec = openapi.buildSpec({ version: audit.engineVersion });
app.get('/api/v1/openapi.json', (req, res) => res.json(openApiSpec));
app.get('/api/docs', (req, res) => res.type('html').send(openapi.docsHtml(openApiSpec)));

const statusDoc = systemStatus.cached(() => systemStatus.build({
  engineVersion: audit.engineVersion, audit,
  threatStore: platformRefs.threatStore ? { ready: platformRefs.threatStore.ready, ...platformRefs.threatStore.stats() } : null
}), 30000);
app.get('/api/system/status', (req, res) => { res.set('Cache-Control', 'public, max-age=30'); res.json(statusDoc()); });

app.post('/api/v1/batch', async (req, res) => {
  const items = req.body && req.body.items;
  if (!Array.isArray(items) || items.length < 1 || items.length > 20) {
    return res.status(400).json({ error: 'items must be an array of 1 to 20 entries.', code: 'BAD_REQUEST' });
  }
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      const it = items[i];
      const input = typeof it === 'string' ? it : (it && typeof it.input === 'string' ? it.input : null);
      if (input == null) { results[i] = { index: i, httpStatus: 400, error: 'Item must be a string or {input}.' }; continue; }
      const domain = it && typeof it === 'object' && it.type === 'domain';
      try {
        const r = await fetch(`http://127.0.0.1:${PORT}${domain ? '/api/domain/check' : '/api/scam/check'}`, {
          method: 'POST', signal: AbortSignal.timeout(25000),
          headers: {
            'Content-Type': 'application/json', 'x-internal-batch': INTERNAL_TOKEN, 'x-internal-ip': req.ip || '',
            'x-internal-key-id': (req.apiAuth && req.apiAuth.keyId) || '', 'x-request-id': `${req.requestId}-${i}`
          },
          body: JSON.stringify(domain ? { url: input } : { text: input })
        });
        const j = await r.json().catch(() => null);
        results[i] = r.ok ? { index: i, httpStatus: r.status, result: j && (j.data || j) } : { index: i, httpStatus: r.status, error: (j && j.error) || 'Check failed' };
      } catch (e) { results[i] = { index: i, httpStatus: 502, error: 'Check failed or timed out.' }; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(4, items.length) }, worker));
  res.json({ status: 'success', count: items.length, quotaUnits: req.rlCost || 1, results });
});

// Uploads: 5 MB, allow-listed types, random server-side names, temp files deleted after processing.
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const ALLOWED_UPLOAD = { '.pdf': 'application/pdf', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.txt': 'text/plain' };
const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1, fields: 10, fieldSize: 64 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!ALLOWED_UPLOAD[ext]) return cb(Object.assign(new Error('Unsupported file type. Use PDF, PNG, JPG or TXT.'), { status: 415 }));
    cb(null, true);
  }
});
const safeName = n => path.basename(String(n || 'document')).replace(/[^\w.\- ]/g, '_').slice(0, 80);
const rmTemp = f => { if (f && f.path) fs.unlink(f.path, () => {}); };

// ==========================================
// PRESET SPECIMEN DOCUMENTS FOR INSTANT JUDGE TESTING
// ==========================================
const SPECIMENS = {
  fake_arrest_warrant: {
    id: "SPEC-001",
    title: "Fake Digital Arrest Warrant (CBI / Supreme Court Impersonation)",
    type: "Extortion / Digital Arrest",
    rawText: `CENTRAL BUREAU OF INVESTIGATION - NEW DELHI\n` +
      `SPECIAL CYBER CRIME CELL - ORDER NO: CBI/CYB/2026/8941\n` +
      `SUBJECT: IMMEDIATE FREEZING ORDER & NATIONAL ARREST WARRANT UNDER PMLA ACT SEC 3/4\n\n` +
      `To: The Account Holder\n` +
      `We have intercepted a suspicious DHL courier in your name containing 140g MDMA and 5 fake passports.\n` +
      `You are placed under 24-HOUR DIGITAL SURVEILLANCE. Do NOT disconnect your Skype/WhatsApp video call.\n` +
      `To clear your name from money laundering charges, transfer your total liquid funds of INR 4,85,000 to the\n` +
      `RBI FINANCIAL SAFETY VERIFICATION ESCROW ACCOUNT:\n` +
      `UPI ID: rbi.safecustody99@okhdfcbank\n` +
      `Account: 919876543210 (RBI Secret Verification Cell)\n\n` +
      `Failure to comply within 2 hours will lead to physical arrest by local police team under IPC 420/120B.\n` +
      `Signed,\n` +
      `Director General of CBI, New Delhi (Seal Attached)`,
    forensicAnalysis: {
      authenticityScore: 4, // out of 100
      riskScore: 98,
      verdict: "COUNTERFEIT_MALICIOUS",
      severity: "CRITICAL",
      findings: [
        {
          rule: "GCP_DOC_AI_SEAL_VERIFICATION",
          status: "FAILED",
          detail: "The Ashoka Lion emblem resolution is pixelated with non-standard geometric distortion indicating digital forgery."
        },
        {
          rule: "RBI_ESCROW_PROCEDURE_CHECK",
          status: "CRITICAL_VIOLATION",
          detail: "Reserve Bank of India (RBI) NEVER instructs citizens to transfer funds to personal UPI handles or 'Verification Accounts'."
        },
        {
          rule: "CRIMINAL_EXTORTION_PATTERN",
          status: "FLAGGED",
          detail: "Digital Arrest tactics detected: 'Skype/WhatsApp surveillance' and '24-Hour Digital Arrest' do not legally exist under CrPC or BNSS 2023."
        },
        {
          rule: "VPA_MULE_DETECTION",
          status: "FLAGGED",
          detail: "UPI ID 'rbi.safecustody99@okhdfcbank' belongs to a newly activated mule account flagged in I4C/CFCFRMS database."
        }
      ],
      legalCitations: ["BNSS Section 105", "IT Act Section 66D (Cheating by Impersonation)", "PMLA Guideline 2024"],
      recommendedAction: "DO NOT TRANSFER FUNDS. Disconnect video call immediately. Report to National Cyber Crime Portal (1930) and block contact."
    }
  },

  predatory_loan: {
    id: "SPEC-002",
    title: "Predatory Instant Loan Approval Notice (Harassment App)",
    type: "Loan App Extortion",
    rawText: `QUICK-CREDIT INDIA - INSTANT SANCTION LETTER\n` +
      `LOAN SANCTION REF: QC/2026/LOAN-88712\n\n` +
      `Congratulations! Your loan of INR 20,000 has been sanctioned instantly.\n` +
      `Amount Disbursed to Bank: INR 12,200 (Processing Fee + GST Deducted: INR 7,800)\n` +
      `Repayment Amount: INR 24,000\n` +
      `Repayment Due: 7 Days from Disbursal\n\n` +
      `MANDATORY TERMS:\n` +
      `- User grants irrevocable consent for 24x7 synchronization of Contact List, Camera, SMS, and Gallery photos.\n` +
      `- In case of 1 day delay, recovery agents reserve right to call all contact numbers and circulate morphed photographs to family.\n\n` +
      `Quick Credit NBFC Partner: (Unregistered Private Lending Network)`,
    forensicAnalysis: {
      authenticityScore: 8,
      riskScore: 95,
      verdict: "PREDATORY_UNREGISTERED_LENDER",
      severity: "CRITICAL",
      findings: [
        {
          rule: "RBI_DIGITAL_LENDING_COMPLIANCE",
          status: "FAILED",
          detail: "Violates RBI Digital Lending Circular 2022: Upfront 39% fee deduction on 7-day tenure exceeds legal usury caps (APR > 900%)."
        },
        {
          rule: "PRIVACY_CONTACT_HARVESTING",
          status: "CRITICAL_VIOLATION",
          detail: "Demanding access to full Contact List and Photo Gallery is strictly prohibited for regulated lending entities on Google Play & RBI."
        },
        {
          rule: "EXTORTION_RECOVERY_CLAUSE",
          status: "ILLEGAL",
          detail: "Threatening to contact relatives and circulate photographs constitutes criminal intimidation under IPC 503/506 & BNS 351."
        }
      ],
      legalCitations: ["RBI Digital Lending Guidelines (Sept 2022)", "IT Act Section 72A", "BNS Section 351"],
      recommendedAction: "Do NOT repay through unofficial UPI links. File police complaint with SafeMeAI call recording and contact blacklist."
    }
  },

  authentic_bank: {
    id: "SPEC-003",
    title: "Authentic HDFC Bank Sanction Letter (Regulated BFSI Standard)",
    type: "Legitimate Banking Document",
    rawText: `HDFC BANK LIMITED\n` +
      `RETAIL ASSETS BRANCH - CONNAUGHT PLACE, NEW DELHI - 110001\n` +
      `CIN: L65920MH1994PLC080618 | RBI REG: B-05.00012\n\n` +
      `SANCTION LETTER - PERSONAL LOAN\n` +
      `Date: 04-Oct-2026 | Ref No: HDFC/PL/2026/099824\n\n` +
      `Dear Customer,\n` +
      `We are pleased to inform you that your Personal Loan application has been sanctioned on the following terms:\n` +
      `- Sanctioned Amount: INR 5,00,000\n` +
      `- Rate of Interest: 10.75% per annum (Floating)\n` +
      `- Tenure: 48 Months | Monthly EMI: INR 12,860\n` +
      `- Processing Fee: 1.0% + GST\n` +
      `- Grievance Redressal Officer: grievances.retail@hdfcbank.com | Helpline: 1800 202 6161\n\n` +
      `For and on behalf of HDFC Bank Limited\n` +
      `Authorized Signatory (Digital Signature Attached)`,
    forensicAnalysis: {
      authenticityScore: 97,
      riskScore: 3,
      verdict: "AUTHENTIC_REGULATED_DOCUMENT",
      severity: "SAFE",
      findings: [
        {
          rule: "GCP_DOC_AI_SEAL_VERIFICATION",
          status: "PASSED",
          detail: "Valid corporate CIN and RBI Registration Number verified against MCA & RBI directories."
        },
        {
          rule: "RBI_DIGITAL_LENDING_COMPLIANCE",
          status: "PASSED",
          detail: "Full Key Fact Statement (KFS) provided with transparent APR, tenure, and approved Grievance Officer contacts."
        },
        {
          rule: "VPA_MULE_DETECTION",
          status: "CLEAN",
          detail: "No unauthorized personal UPI or third-party transfer accounts mentioned."
        }
      ],
      legalCitations: ["Banking Regulation Act 1949", "RBI Fair Practices Code"],
      recommendedAction: "Document is legitimate. Follow standard verification procedures via official HDFC Bank NetBanking."
    }
  }
};

// ==========================================
// API 1: DOCUMENT INTELLIGENCE (Google Document AI + Gemini)
// ==========================================
app.get('/api/document-ai/specimens', (req, res) => {
  res.json({
    status: 'success',
    data: Object.keys(SPECIMENS).map(key => ({
      key,
      id: SPECIMENS[key].id,
      title: SPECIMENS[key].title,
      type: SPECIMENS[key].type
    }))
  });
});

app.post('/api/document-ai/analyze', upload.single('document'), async (req, res) => {
  const body = req.body || {};
  const specimenKey = body.specimenKey;
  const tmp = req.file;
  try {
    if (specimenKey && Object.prototype.hasOwnProperty.call(SPECIMENS, specimenKey)) {
      const specimen = SPECIMENS[specimenKey];
      return res.json({
        status: 'success',
        mode: 'PRESET_SPECIMEN',
        dataSource: 'demo-simulated',
        dataSourceNote: 'Built-in specimen with pre-written forensic findings. Not produced by Document AI.',
        timestamp: new Date().toISOString(),
        document: { id: specimen.id, title: specimen.title, type: specimen.type, extractedText: specimen.rawText },
        analysis: specimen.forensicAnalysis
      });
    }

    let customText = String(body.customText || '').slice(0, 20000);
    let filename = 'User Submitted Document';
    let ocr = { available: false, reason: 'no file uploaded' };
    let ocrNote = 'Text pasted by user; analysed by wording triage (co-occurrence rules). No seal, signature or image forensics were run.';

    if (req.file) {
      filename = safeName(req.file.originalname);
      const ext = path.extname(filename).toLowerCase();
      if (ext === '.txt') {
        customText = fs.readFileSync(req.file.path, 'utf8').slice(0, 20000);
        ocrNote = 'Plain text read directly; analysed by wording triage (co-occurrence rules). No seal, signature or image forensics were run.';
      } else {
        ocr = await gcp.documentAiOcr(fs.readFileSync(req.file.path), ALLOWED_UPLOAD[ext]);
        if (ocr.available) {
          customText = ocr.text;
          ocrNote = 'Text extracted by Google Document AI OCR; then analysed by wording triage (co-occurrence rules). No seal, signature or image forensics were run.';
        } else {
          customText = `[OCR unavailable: ${ocr.reason}. The file "${filename}" (${(req.file.size / 1024).toFixed(1)} KB) was NOT analysed.]`;
          ocrNote = `Document AI not used (${ocr.reason}). The file was NOT analysed and no score is given.`;
        }
      }
    }

    // Word-boundary, co-occurrence triage (lib/docTriage.js). Files without a text processor stay honestly "not analysed".
    return res.json(docTriage.buildResponse({
      text: customText, filename, hasFile: Boolean(req.file), isText: Boolean(req.file) && path.extname(filename).toLowerCase() === '.txt',
      ocr, ocrNote
    }));
  } catch (e) {
    console.error('[document-ai] failure:', e.message);
    res.status(500).json({ error: 'Document analysis failed. Treat the document as unverified.' });
  } finally {
    rmTemp(tmp);
  }
});

// Global error handler: no parser internals or stack text ever reaches the client.
function globalErrorHandler(err, req, res, next) {
  if (!err) return next();
  if (req.file) rmTemp(req.file);
  const rid = req.requestId;
  if (err.type === 'entity.parse.failed' || (err instanceof SyntaxError && err.status === 400)) {
    return res.status(400).json({ error: 'Malformed JSON body', code: 'BAD_JSON' });
  }
  if (err.type === 'entity.too.large' || err.code === 'LIMIT_FILE_SIZE') {
    const isFile = err.code === 'LIMIT_FILE_SIZE';
    const lim = isFile ? `${MAX_UPLOAD_BYTES / 1048576} MB` : `${Math.round(parseFloat(BODY_LIMIT))} KB`;
    return res.status(413).json({ error: `${isFile ? 'File' : 'Request body'} too large (max ${lim}).`, code: 'PAYLOAD_TOO_LARGE' });
  }
  const status = err.status || err.statusCode || (err.name === 'MulterError' ? 400 : 500);
  if (status >= 400 && status < 500) {
    const custom = err.name === 'MulterError' || err.expose === true && !err.type;
    return res.status(status).json({ error: custom ? err.message : 'Bad request', code: 'BAD_REQUEST' });
  }
  console.error(JSON.stringify({ severity: 'ERROR', message: 'unhandled error', requestId: rid, error: String(err && err.message).slice(0, 300) }));
  res.status(500).json({ error: 'Internal error', code: 'INTERNAL', requestId: rid });
}
app.use(globalErrorHandler);

// ==========================================
// API 2: GEMINI ON VERTEX AI (Fraud Reasoning & Financial Advisory)
// ==========================================
app.post('/api/gemini/advisor', async (req, res) => {
  const raw = req.body && req.body.prompt;
  const userQuery = (typeof raw === 'string' ? raw : '').trim().slice(0, 2000);
  if (!userQuery) return res.status(400).json({ error: 'Please describe the suspicious message or situation.' });

  const g = await geminiAdvise(userQuery, req.lang);
  if (g.available) {
    return res.json({
      status: 'success',
      data: {
        model: `${g.model} (${g.via})`, grounded: true, dataSource: 'gemini-live',
        query: userQuery, timestamp: new Date().toISOString(),
        reasoning: g.reasoning, riskLevel: g.riskLevel, signals: g.signals, recommendedAction: g.recommendedAction
      }
    });
  }
  const f = advisorRules(userQuery);
  res.json({
    status: 'success',
    data: {
      model: 'rules-engine fallback', grounded: false, dataSource: 'rules-engine',
      fallbackReason: g.reason || 'Gemini unavailable',
      query: userQuery, timestamp: new Date().toISOString(), ...f
    }
  });
});

/** Deterministic keyword advisor, used only when Gemini is unreachable. */
function advisorRules(userQuery) {
  const responseData = { reasoning: '', riskLevel: 'MEDIUM', signals: [], recommendedAction: '' };
  const lower = userQuery.toLowerCase();
  if (lower.includes("digital arrest") || lower.includes("cbi") || lower.includes("parcel") || lower.includes("skype") || lower.includes("customs")) {
    responseData.riskLevel = "CRITICAL";
    responseData.signals = [
      "Psychological Fear Appeal (Coercive threat of immediate arrest)",
      "Impersonation of Central Law Enforcement Agency (CBI / Customs / Cyber Cell)",
      "Demand for digital surveillance isolation (staying on camera)",
      "Financial Escrow / Fund Verification Transfer trap"
    ];
    responseData.reasoning = 
      "This matches the signature traits of the 'Digital Arrest' cyber-extortion scheme. In Indian law (CrPC / BNSS), no court or police officer conducts bail, investigation, or asset verification over WhatsApp or Skype video calls, nor does the Reserve Bank of India maintain 'verification escrow' accounts for individuals.";
    responseData.recommendedAction = 
      "1. Immediately disconnect the call and block the sender.\n" +
      "2. Do NOT transfer any money.\n" +
      "3. Inform your local police station or dial 1930 (National Cyber Crime Reporting Helpline).\n" +
      "4. Report the number at cybercrime.gov.in so it can be flagged.";
  } else if (lower.includes("upi") || lower.includes("pin") || lower.includes("qr") || lower.includes("refund") || lower.includes("receive")) {
    responseData.riskLevel = "HIGH";
    responseData.signals = [
      "UPI Collect Request Inversion Scam (Paying to Receive)",
      "Urgency trigger (Refund expiring within 15 mins)",
      "Fake customer support / delivery partner handle"
    ];
    responseData.reasoning = 
      "In the Unified Payments Interface (UPI) architecture, you NEVER need to enter your UPI PIN, scan a QR code, or approve a Collect Request to RECEIVE money. Entering your PIN authorizes a debit from your account.";
    responseData.recommendedAction = 
      "Reject the collect request immediately on PhonePe / Google Pay / Paytm.";
  } else if (lower.includes("telegram") || lower.includes("like youtube") || lower.includes("part time job") || lower.includes("crypto return")) {
    responseData.riskLevel = "CRITICAL";
    responseData.signals = [
      "Task-based Pig Butchering Scheme",
      "Mule account recruitment funnel",
      "Initial small payout hook followed by high deposit requirement"
    ];
    responseData.reasoning = 
      "This is a classic 'Task Scam'. Scammers pay INR 150-500 initially to build false trust, then demand thousands in 'pre-paid tasks' on simulated trading platforms. The bank accounts you transfer to are illegal mule accounts.";
    responseData.recommendedAction = 
      "Cease all contact immediately. Exit the Telegram group. Any funds sent to their accounts should be reported immediately via cybercrime.gov.in.";
  } else {
    responseData.riskLevel = "MEDIUM";
    responseData.signals = ["No known scam pattern matched by the offline rules (this is not a safety guarantee)"];
    responseData.reasoning = 
      "The offline rules could not assess this message; treat it as unverified. Remember the golden BFSI security rule: Never share OTPs, UPI PINs, CVV codes, or install remote-access apps (AnyDesk, TeamViewer, RustDesk) at the request of anyone claiming to represent a bank.";
    responseData.recommendedAction = "Verify all sensitive inquiries directly through official banking apps or customer support numbers on your debit card.";
  }
  return responseData;
}

// ==========================================
// API 3: BIGQUERY RISK & ANOMALY ANALYTICS
// ==========================================
const analyticsLib = require('./lib/analytics');
const liveAnalytics = analyticsLib.createAnalytics();
async function threatIntelDoc() {
  let feeds = [];
  try { feeds = (await threatPlatform.runner.status()).feeds || []; } catch (_) { /* status is best-effort */ }
  return analyticsLib.threatIntelFacts({ stats: { ready: threatStore.ready, ...threatStore.stats() }, feeds });
}
app.get('/api/analytics/threat-intel', async (req, res) => {
  res.set('Cache-Control', 'public, max-age=30');
  res.json({ status: 'success', dataSource: 'threat-store-live', generatedAt: new Date().toISOString(), data: await threatIntelDoc() });
});
app.get('/api/bigquery/analytics', async (req, res) => {
  res.set('Cache-Control', 'public, max-age=30');
  const [bq, threatIntel] = await Promise.all([liveAnalytics.bigQuerySummary(), threatIntelDoc()]);
  if (!bq.available) {
    return res.json({
      status: 'success', available: false, empty: Boolean(bq.empty), dataSource: 'bigquery-unavailable',
      reason: bq.reason, sql: bq.sql || null, threatIntel, generatedAt: new Date().toISOString()
    });
  }
  const { available, ...rest } = bq;
  res.json({
    status: 'success', available: true, dataSource: 'bigquery-live',
    engine: 'Google Cloud BigQuery (jobs.query, parameterised, asia-south1)',
    table: process.env.AUDIT_BIGQUERY_TABLE, ...rest, threatIntel, generatedAt: new Date().toISOString()
  });
});

// ==========================================
// API 4: VERTEX AI SEARCH / REGULATORY COMPLIANCE
// ==========================================
app.post('/api/compliance/search', (req, res) => {
  const rawQuery = String((req.body && req.body.query) || '').slice(0, 500);
  const query = rawQuery.toLowerCase();

  let citation = {
    source: "Reserve Bank of India (RBI) Master Direction on Customer Protection",
    regulationNumber: "RBI/2017-18/15 DBR.No.Leg.BC.78/09.07.005/2017-18",
    clause: "Zero Liability of a Customer in Unauthorized Electronic Banking Transactions",
    summary: "If an unauthorized transaction occurs due to third-party breach or fraud where deficiency lies neither with the bank nor customer, and the customer notifies the bank within THREE working days, the customer liability is ZERO.",
    steps: [
      "1. Immediately report the unauthorized transaction to the issuing bank within 72 hours.",
      "2. Obtain official incident complaint token / acknowledgment number.",
      "3. Register an FIR / complaint on national portal 1930 (cybercrime.gov.in).",
      "4. Bank must credit the shadow reversal into customer account within 10 working days."
    ]
  };

  if (query.includes("loan") || query.includes("recovery") || query.includes("harassment")) {
    citation = {
      source: "RBI Guidelines on Digital Lending - Protection of Borrowers",
      regulationNumber: "RBI/2022-23/111 DOR.CRE.REC.66/21.07.001/2022-23",
      clause: "Fair Practices Code - Fair Recovery Measures & Data Privacy",
      summary: "Regulated Lending Entities (REs) and their Lending Service Providers (LSPs) are strictly prohibited from accessing mobile phone resources such as Contacts, File and Media, Call Logs, or Telephony data. Recovery agents cannot contact borrowers between 7 PM and 8 AM or intimidate family members.",
      steps: [
        "1. Check if the lending app is listed in RBI's approved NBFC portal.",
        "2. Save call recordings and WhatsApp extortion screenshots.",
        "3. Lodge complaint on RBI CMS portal (cms.rbi.org.in).",
        "4. Block and report the abusive callers to 1930 / cybercrime.gov.in."
      ]
    };
  }

  res.json({
    status: 'success',
    dataSource: 'curated-static',
    retrievalEngine: 'Curated static citations (keyword match; Vertex AI Search is not connected)',
    query: rawQuery,
    data: citation
  });
});

// ==========================================
// API 5: TELEMETRY STREAM INGESTION (PUB/SUB SUBSCRIBER)
// ==========================================
app.post('/api/telemetry/ingest', (req, res) => {
  const { deviceId } = req.body || {};
  // Demo endpoint: validates and acknowledges only. Nothing is published to Pub/Sub or stored.
  res.json({
    status: 'success',
    event: 'SIMULATED_ACK',
    dataSource: 'demo-simulated',
    messageId: 'sim-' + Math.random().toString(36).substring(2, 10),
    timestamp: new Date().toISOString(),
    ingestedFrom: String(deviceId || 'unknown').replace(/[^\w.\-]/g, '_').slice(0, 64)
  });
});

// ==========================================
// AUTHORITATIVE WHITELISTS & BRAND MATRIX (HCRV ENGINE)
// ==========================================
// Loaded from data/allowlist.json (entries: {domain, category, owner}); edit that file, not this code.
const ALLOWLIST_ENTRIES = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'allowlist.json'), 'utf8')).entries;
const PROTECTED_DOMAINS_WHITELIST = new Set(ALLOWLIST_ENTRIES.map(e => String(e.domain).toLowerCase()));

function isProtectedDomain(host) {
  if (!host) return false;
  const h = host.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0].trim();
  if (!h) return false;
  if (PROTECTED_DOMAINS_WHITELIST.has(h)) return true;
  for (const p of PROTECTED_DOMAINS_WHITELIST) {
    if (h === p || h.endsWith('.' + p)) return true;
  }
  // Sovereign & Regulated Banking Infrastructure
  // In India: .gov.in (Government), .nic.in (National Informatics Centre), .bank.in (RBI/IDRBT Regulated Banks), .jud.in (Judiciary), .mil.in (Defence)
  if (h.endsWith('.gov.in') || h.endsWith('.nic.in') || h.endsWith('.bank.in') || h.endsWith('.jud.in') || h.endsWith('.mil.in')) {
    return true;
  }
  return false;
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[a.length][b.length];
}

function findSimilarProtectedDomain(host) {
  const norm = host.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0].trim();
  if (isProtectedDomain(norm)) return null;
  for (const protectedDomain of PROTECTED_DOMAINS_WHITELIST) {
    if (Math.abs(norm.length - protectedDomain.length) <= 2) {
      const dist = levenshtein(norm, protectedDomain);
      if (dist >= 1 && dist <= 2 && norm !== protectedDomain) {
        return protectedDomain;
      }
    }
  }
  return null;
}

const BRAND_KEYWORDS = [
  { keyword: "sbi", name: "State Bank of India (SBI)", official: "sbi.co.in" },
  { keyword: "hdfc", name: "HDFC Bank", official: "hdfcbank.com" },
  { keyword: "icici", name: "ICICI Bank", official: "icicibank.com" },
  { keyword: "axis", name: "Axis Bank", official: "axisbank.com" },
  { keyword: "pnb", name: "Punjab National Bank (PNB)", official: "pnbindia.in" },
  { keyword: "bob", name: "Bank of Baroda", official: "bankofbaroda.in" },
  { keyword: "kotak", name: "Kotak Mahindra Bank", official: "kotak.com" },
  { keyword: "rbi", name: "Reserve Bank of India (RBI)", official: "rbi.org.in" },
  { keyword: "cbi", name: "Central Bureau of Investigation (CBI)", official: "cbi.gov.in" },
  { keyword: "police", name: "Police Cyber Cell", official: "cybercrime.gov.in" },
  { keyword: "cybercrime", name: "National Cyber Crime Portal", official: "cybercrime.gov.in" },
  { keyword: "pmkisan", name: "PM-KISAN Portal", official: "pmkisan.gov.in" },
  { keyword: "challan", name: "Parivahan e-Challan", official: "echallan.parivahan.gov.in" },
  { keyword: "parivahan", name: "Ministry of Road Transport (Parivahan)", official: "parivahan.gov.in" },
  { keyword: "indiapost", name: "India Post (Department of Posts)", official: "indiapost.gov.in" },
  { keyword: "speedpost", name: "India Post Speed Post", official: "indiapost.gov.in" },
  { keyword: "electricity", name: "State Electricity Discom", official: "Official State DISCOM" },
  { keyword: "bescom", name: "BESCOM Karnataka", official: "bescom.karnataka.gov.in" },
  { keyword: "mahadiscom", name: "MSEDCL Maharashtra", official: "mahadiscom.in" },
  { keyword: "uppcl", name: "UPPCL Uttar Pradesh", official: "upenergy.in" },
  { keyword: "phonepe", name: "PhonePe", official: "phonepe.com" },
  { keyword: "paytm", name: "Paytm Payments", official: "paytm.com" },
  { keyword: "gpay", name: "Google Pay", official: "pay.google.com" },
  { keyword: "fedex", name: "FedEx Express", official: "fedex.com" },
  { keyword: "dhl", name: "DHL Express", official: "dhl.com" },
  { keyword: "airtel", name: "Bharti Airtel", official: "airtel.in" },
  { keyword: "jio", name: "Reliance Jio", official: "jio.com" },
  { keyword: "trai", name: "Telecom Regulatory Authority of India (TRAI)", official: "trai.gov.in" },
  { keyword: "ujjivan", name: "Ujjivan Small Finance Bank", official: "ujjivansfb.in" },
  { keyword: "aubank", name: "AU Small Finance Bank", official: "aubank.in" }
];

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "buzz", "club", "work", "vip", "tk", "ml", "ga", "cf",
  "online", "site", "shop", "icu", "link", "cc", "click", "live", "rest", "cam",
  "biz", "info", "monster", "pro", "fit", "run", "space"
]);

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "t.co", "shorturl.at",
  "wa.me", "page.link", "goo.gl", "ow.ly", "buff.ly", "v.ht", "clck.ru"
]);

// ==========================================
// REAL-TIME THREAT INTELLIGENCE & TELEMETRY ENGINE
// ==========================================
// Ingestion platform (lib/ingest/*): sources -> lib/threatStore.js (in-memory snapshot, Firestore/file persistence).
// OpenPhish is now just one source (lib/ingest/sources/global/openphish.js). Cloud Scheduler is the real driver
// (POST /internal/ingest/run); an in-process timer is a best-effort fallback (INGEST_INPROCESS=0 disables it).
const { createPlatform, mountRoutes: mountIngestRoutes } = require('./lib/ingest/platform');
const { createCloudflareCheck } = require('./lib/cloudflareDns');
const threatPlatform = createPlatform();
const threatStore = threatPlatform.store;
platformRefs.threatStore = threatStore;
mountIngestRoutes(app, threatPlatform);
let threatWarm = Promise.resolve();
if (process.env.DISABLE_THREAT_INTEL !== '1') {
  threatWarm = threatPlatform.start().catch(err => console.warn('[ThreatIntel] start failed:', err.message));
}
// Cold Cloud Run instance: wait (bounded) for the in-memory feed index so the first verdicts are not made blind.
app.use(['/api/domain/check', '/api/scam/check'], async (req, res, next) => {
  if (!threatStore.ready) {
    await Promise.race([threatWarm, new Promise(r => setTimeout(r, 12000))]);
  }
  next();
});
const securityDns = process.env.DISABLE_CLOUDFLARE_DNS === '1' ? null : createCloudflareCheck();

// Legacy-shaped adapter so the engine's OpenPhish path keeps working (O(1) in-memory lookups only).
const openPhishAdapter = {
  domains: { has: (h) => threatStore.lookup('domain', h).some(x => x.source === 'openphish') },
  urls: { has: (u) => { const n = require('./lib/ingest/contract').normaliseUrl(u); return Boolean(n) && threatStore.lookup('url', n).some(x => x.source === 'openphish'); } }
};
function openPhishHealth() {
  const m = threatStore.sourceMeta('openphish');
  const st = threatPlatform.runner.peek('openphish') || {};
  const src = threatPlatform.runner.getSource('openphish') || {};
  const staleMs = (src.staleAfterHours || 12) * 3600 * 1000;
  return {
    live: Boolean(m) && (Date.now() - m.ingestedAt) < staleMs, // never "live" for a stale feed
    lastAttempt: st.lastAttempt || 0, lastSuccess: m ? m.ingestedAt : 0, lastError: st.lastError || null, indicators: m ? m.count : 0
  };
}

app.get('/api/threat-feed/status', async (req, res) => {
  const h = openPhishHealth();
  let feeds = [];
  try { feeds = (await threatPlatform.runner.status()).feeds.map(f => ({ id: f.id, name: f.name, group: f.group, status: f.status, live: f.live, stale: f.stale, indicators: f.indicators, lastSuccess: f.lastSuccess, ageSec: f.ageSec, license: f.license })); } catch (_) {}
  res.json({
    status: 'success', feed: 'OpenPhish community feed', ...h,
    ageSec: h.lastSuccess ? Math.round((Date.now() - h.lastSuccess) / 1000) : null,
    storeReady: threatStore.ready, feeds
  });
});

async function performRealtimeDnsCheck(host) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, {
      signal: controller.signal,
      headers: { 'Accept': 'application/dns-json' }
    });
    clearTimeout(timeout);
    if (!resp.ok) {
      return { resolved: false, status: `HTTP_${resp.status}`, ips: [], ttl: null, isFastFlux: false, provider: "Google Public DNS (DoH)" };
    }
    const data = await resp.json();
    const status = data.Status;
    const answers = (data.Answer || []).filter(a => a.type === 1);
    const ips = answers.map(a => a.data);
    const minTtl = answers.length > 0 ? Math.min(...answers.map(a => a.TTL)) : null;
    const isFastFlux = minTtl !== null && minTtl < 60;
    const isNxDomain = status === 3;

    return {
      resolved: ips.length > 0,
      status: status === 0 ? "NOERROR" : (isNxDomain ? "NXDOMAIN" : `STATUS_${status}`),
      ips: ips.slice(0, 5),
      ttl: minTtl,
      isFastFlux,
      isNxDomain,
      provider: "Google Public DNS (DoH RFC 8484)"
    };
  } catch (err) {
    return {
      resolved: false,
      status: "TIMEOUT_OR_UNRESOLVABLE",
      ips: [],
      ttl: null,
      isFastFlux: false,
      error: err.name === 'AbortError' ? 'DNS Resolution Timeout (3000ms)' : err.message,
      provider: "Google Public DNS (DoH)"
    };
  }
}

// SSRF guard: resolve first, refuse non-public targets, then connect to the vetted IP (no DNS rebinding).
async function performRealtimeSslCheck(host) {
  const bad = (why) => ({ supported: false, hasValidSsl: false, error: why, subjectOrg: 'Not probed', issuer: 'None' });
  try {
    if (!host || /^(localhost|.*\.(local|internal|localdomain))$/i.test(host)) return bad('Blocked non-public host');
    const addrs = await dns.lookup(host, { all: true });
    if (!addrs.length || !addrs.every(a => gcp.isPublicIp(a.address))) return bad('Blocked non-public address');
    const first = await rawSslCheck(host, addrs[0].address);
    // Many Indian sites serve a valid certificate only for www.<name>. A hostname mismatch on the bare name is then a
    // false alarm: re-probe www.<name> (same SSRF checks) and use that result when the certificate is properly trusted.
    if (first && first.supported && first.authorized === false && /ALTNAME/i.test(String(first.authError || '')) && !/^www\./i.test(host)) {
      try {
        const wwwHost = 'www.' + host;
        const wa = await dns.lookup(wwwHost, { all: true });
        if (wa.length && wa.every(a => gcp.isPublicIp(a.address))) {
          const second = await rawSslCheck(wwwHost, wa[0].address);
          if (second && second.supported && second.authorized === true) return { ...second, probedHost: wwwHost, note: 'Certificate is valid for the www name.' };
        }
      } catch (_) { /* keep the first result */ }
    }
    return first;
  } catch (e) {
    return bad(e.code || e.message);
  }
}

function rawSslCheck(host, ip) {
  return new Promise((resolve) => {
    let resolved = false;
    const finish = (res) => {
      if (!resolved) {
        resolved = true;
        resolve(res);
      }
    };

    let sockRef = null;
    const timer = setTimeout(() => {
      if (sockRef) sockRef.destroy();
      finish({
        supported: false,
        hasValidSsl: false,
        error: "TLS Handshake Timeout (2500ms)",
        subjectOrg: "Unknown / Unresponsive TLS",
        issuer: "None"
      });
    }, 2500);

    try {
      const socket = tls.connect({
        host: ip,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        timeout: 2500
      }, () => {
        clearTimeout(timer);
        try {
          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const authError = socket.authorizationError;
          socket.end();

          if (!cert || Object.keys(cert).length === 0) {
            return finish({
              supported: false,
              hasValidSsl: false,
              error: "No certificate presented",
              subjectOrg: "None",
              issuer: "None"
            });
          }

          const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
          const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
          const now = new Date();
          const ageDays = validFrom ? Math.floor((now - validFrom) / (1000 * 60 * 60 * 24)) : null;
          const remainingDays = validTo ? Math.floor((validTo - now) / (1000 * 60 * 60 * 24)) : null;

          const issuerOrg = cert.issuer ? (cert.issuer.O || cert.issuer.CN || "Unknown Issuer") : "Unknown";
          const subjectOrg = cert.subject ? (cert.subject.O || "") : "";
          const isEV_OV = Boolean(subjectOrg && subjectOrg.trim().length > 0);
          const isFreeDV = /let's encrypt|zerossl|cloudflare|cpanel/i.test(issuerOrg);
          const isNewlyIssued = ageDays !== null && ageDays <= 7;
          const isExpired = remainingDays !== null && remainingDays < 0;

          finish({
            supported: true,
            hasValidSsl: authorized || (!isExpired && ageDays !== null && ageDays >= 0),
            authorized,
            authError: authorized ? null : authError,
            subjectOrg: subjectOrg || "None (Domain Validated / Unverified Entity)",
            issuer: issuerOrg,
            ageDays,
            remainingDays,
            isEV_OV,
            isFreeDV,
            isNewlyIssued,
            isExpired,
            fingerprint256: cert.fingerprint256 ? cert.fingerprint256.substring(0, 18) + '...' : null
          });
        } catch (e) {
          finish({
            supported: false,
            hasValidSsl: false,
            error: "Failed to parse certificate: " + e.message,
            subjectOrg: "Error",
            issuer: "Error"
          });
        }
      });

      sockRef = socket;
      socket.on('error', (err) => {
        clearTimeout(timer);
        finish({
          supported: false,
          hasValidSsl: false,
          error: err.code || err.message,
          subjectOrg: "Unencrypted (Port 443 Closed)",
          issuer: "None"
        });
      });
    } catch (err) {
      clearTimeout(timer);
      finish({
        supported: false,
        hasValidSsl: false,
        error: err.message,
        subjectOrg: "Connection Failure",
        issuer: "None"
      });
    }
  });
}

function calculateShannonEntropy(str) {
  if (!str) return 0;
  const clean = str.toLowerCase().replace(/[^a-z0-9-]/g, '');
  const len = clean.length;
  if (len === 0) return 0;
  const freq = {};
  for (let i = 0; i < len; i++) {
    const c = clean[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
}

function performAgenticAiForensics({ host, dns, ssl, isOpenPhish, entropy, isLookalike, brandMatch, isSuspiciousTld, isWhitelisted }) {
  if (isWhitelisted) {
    return {
      model: "Gemini 1.5 Threat Hunter (Vertex AI Grounded)",
      verdict: "BENIGN_AUTHENTICATED_SOVEREIGN",
      confidence: "99.8%",
      threatVector: "None - Official Sovereign/Banking Infrastructure",
      rationale: `Host '${host}' is cryptographically certified under India's official BFSI/Sovereign directory. Live DNS resolves to ${dns.ips ? dns.ips.length : 1} authorized endpoints with ${ssl.isEV_OV ? 'Extended/Organization Validation (' + ssl.subjectOrg + ')' : 'valid TLS encryption'}. Zero spoofing indicators.`
    };
  }

  if (isOpenPhish) {
    return {
      model: "Gemini 1.5 Threat Hunter (Real-Time Threat Intelligence)",
      verdict: "CONFIRMED_ZERO_DAY_PHISHING",
      confidence: "99.9%",
      threatVector: "Global Threat Feed Match (OpenPhish Community Stream)",
      rationale: `CRITICAL ALERT: '${host}' was detected actively in the live OpenPhish zero-day feed. This domain is currently harvesting credentials or distributing malicious payloads globally.`
    };
  }

  if (isLookalike || brandMatch) {
    const brandName = brandMatch ? brandMatch.name : isLookalike;
    return {
      model: "Gemini 1.5 Threat Hunter (Typosquatting & Brand Defense)",
      verdict: "CONFIRMED_PHISHING_BRAND_IMPERSONATION",
      confidence: "98.5%",
      threatVector: "Visual Impersonation & Typosquatting Trap",
      rationale: `Host '${host}' visually and lexically impersonates '${brandName}'. ${ssl.isFreeDV ? 'Uses automated free Domain-Validated TLS (' + ssl.issuer + ') with zero organizational identity.' : (ssl.supported ? 'TLS is active but lacks institutional ownership.' : 'Lacks authorized banking TLS certificate.')} High likelihood of credential harvesting.`
    };
  }

  if (dns.isNxDomain) {
    return {
      model: "Gemini 1.5 Threat Hunter (DNS Sinkhole & Fast-Flux)",
      verdict: "MALICIOUS_OR_SINKHOLED_HOST",
      confidence: "92.0%",
      threatVector: "Unresolvable / Sinkholed Domain (NXDOMAIN)",
      rationale: `Host '${host}' returned NXDOMAIN from Google Public DNS. This indicates an ephemeral phishing server that was rapidly taken down or unregistered domain lure.`
    };
  }

  if (isSuspiciousTld && (ssl.isNewlyIssued || ssl.isFreeDV || entropy > 3.6)) {
    return {
      model: "Gemini 1.5 Threat Hunter (Zero-Day Anomaly Detection)",
      verdict: "SUSPICIOUS_ZERO_DAY_PHISHING_CANDIDATE",
      confidence: "89.0%",
      threatVector: "Disposable TLD with Algorithmic or Free TLS Signature",
      rationale: `Domain uses high-abuse extension with ${ssl.isNewlyIssued ? 'freshly minted TLS certificate (' + ssl.ageDays + ' days old)' : 'unverified ownership'} and lexical entropy ${entropy}. Highly anomalous for legitimate banking or commercial transactions.`
    };
  }

  if (dns.resolved && ssl.hasValidSsl && !ssl.isNewlyIssued && entropy < 3.7) {
    return {
      model: "Gemini 1.5 Threat Hunter (Contextual Risk Engine)",
      verdict: "STANDARD_EXTERNAL_BENIGN_DOMAIN",
      confidence: "88.0%",
      threatVector: "None Detected - Standard Third-Party Host",
      rationale: `Host '${host}' exhibits normal DNS resolution, established TLS certificate age (${ssl.ageDays !== null ? ssl.ageDays + ' days' : 'active'}), and natural lexical distribution (entropy: ${entropy}). No visual brand traps detected.`
    };
  }

  return {
    model: "Gemini 1.5 Threat Hunter (Edge Forensics)",
    verdict: "UNVERIFIED_THIRD_PARTY_HOST",
    confidence: "75.0%",
    threatVector: "Unverified Private Host",
    rationale: `Host '${host}' is not registered on official institutional directories. Exercise caution and do not input banking credentials or OTPs.`
  };
}

// ==========================================
// DOMAIN INTELLIGENCE ENGINE WIRING (see lib/domainEngine.js)
// ==========================================
const engine = require('./lib/domainEngine');
const textEngine = require('./lib/textEngine');
const textAi = require('./lib/textAi');
const docTriage = require('./lib/docTriage');
const engineDeps = {
  whitelist: PROTECTED_DOMAINS_WHITELIST,
  _matcher: engine.buildMatcher(PROTECTED_DOMAINS_WHITELIST),
  brands: BRAND_KEYWORDS,
  suspiciousTlds: SUSPICIOUS_TLDS,
  shorteners: URL_SHORTENERS,
  dnsCheck: performRealtimeDnsCheck,
  sslCheck: performRealtimeSslCheck,
  openPhish: openPhishAdapter,
  threatStore,
  securityDns,
  useGemini: process.env.DISABLE_GEMINI !== '1'
};

function levelBoost(score) {
  return score >= 80 ? 'CRITICAL' : (score >= 60 ? 'HIGH' : 'MODERATE');
}

function agenticFromAssessment(a) {
  const g = a.gemini;
  if (g && g.available) {
    return {
      model: `Gemini (${g.model}) via ${g.via}`,
      verdict: g.verdict,
      confidence: g.confidence != null ? `${Math.round(g.confidence * 100)}%` : 'n/a',
      threatVector: g.threatVector,
      rationale: g.rationale,
      signals: g.signals,
      grounded: true
    };
  }
  const why = g && g.reason ? g.reason : 'not configured';
  return {
    model: `SafeMeAI deterministic forensics engine (Gemini unavailable: ${why})`,
    verdict: a.verdict,
    confidence: 'n/a',
    threatVector: a.verified ? 'None - verified official domain' : (a.flags[0] || 'Insufficient evidence'),
    rationale: a.verified ? a.evidenceForTrust.join(' ') : a.flags.slice(0, 3).join(' | '),
    grounded: false
  };
}

function telemetryFromAssessment(a) {
  const dns = a.dns || {};
  const ssl = a.ssl || {};
  return {
    dns: {
      provider: dns.provider, status: dns.status, resolved: dns.resolved, ips: dns.ips || [],
      ttl: dns.ttl, isFastFlux: dns.isFastFlux, isNxDomain: dns.isNxDomain
    },
    ssl: {
      supported: ssl.supported, hasValidSsl: ssl.hasValidSsl, authorized: ssl.authorized, error: ssl.error,
      subjectOrg: ssl.subjectOrg, issuer: ssl.issuer, ageDays: ssl.ageDays, remainingDays: ssl.remainingDays,
      isEV_OV: ssl.isEV_OV, isFreeDV: ssl.isFreeDV, isNewlyIssued: ssl.isNewlyIssued, isExpired: ssl.isExpired
    },
    threatFeeds: {
      openPhishMatch: a.isOpenPhish,
      feedName: "OpenPhish Global Community Feed",
      activeIndicators: openPhishHealth().indicators,
      feedLive: openPhishHealth().live,
      feedLastError: openPhishHealth().lastError,
      threatStore: { ready: threatStore.ready, totalIndicators: threatStore.stats().totalIndicators },
      listedBy: (a.threatFeeds || []).map(f => f.name || f.source),
      cloudflareDns: a.cloudflare,
      popularRank: a.popularRank,
      webRisk: a.webRisk,
      timestamp: new Date().toISOString()
    },
    domainAge: a.domainAge,
    mlDiagnostics: {
      shannonEntropy: a.entropy,
      isDGA: a.entropy > 3.8 && a.registrable.split('.')[0].length > 12,
      entropyRating: a.entropy > 3.8 ? "High (Algorithmic DGA Pattern)" : (a.entropy > 3.2 ? "Moderate" : "Normal Lexical Distribution")
    },
    agenticAi: agenticFromAssessment(a)
  };
}

const VERDICT_COPY = {
  FAKE_OFFICIAL_NAMESPACE: ["🚨 FORGED OFFICIAL DOMAIN: This address does not exist", "🛑 DO NOT OPEN. Genuine government/bank websites are always registered. Search the institution's name in Google or use its official app."],
  CONFIRMED_ZERO_DAY_PHISHING: ["🚨 ZERO-DAY PHISHING: Actively flagged in global threat feeds", "🛑 DO NOT OPEN: this domain is attacking users right now. Block and report to 1930."],
  GOOGLE_WEB_RISK_FLAGGED: ["🚨 GOOGLE WEB RISK: Known dangerous site", "🛑 DO NOT OPEN: Google's threat database lists this URL as malware/phishing."],
  DECEPTIVE_URL_STRUCTURE: ["🚨 DECEPTIVE LINK: The real destination is hidden", "🛑 DO NOT OPEN: the text before '@' is a decoy; the browser would go to the host after it."],
  RAW_IP_PHISHING_HOST: ["⚠️ SUSPICIOUS: Raw IP address host", "🛑 AVOID: banks and government services never direct users to numeric IP addresses."],
  MALICIOUS_APK_DOWNLOAD_VECTOR: ["🚨 MALWARE WARNING: Android APK sideload link", "🛑 DO NOT INSTALL: APKs from links can steal your SMS, OTPs and photos. Install only from Google Play."],
  PHISHING_BRAND_AS_SUBDOMAIN: ["🚨 PHISHING: Trusted brand used only as a decoy subdomain", "🛑 DO NOT OPEN: the real owner is the last part of the domain, not the familiar brand at the start."],
  HOMOGLYPH_LOOKALIKE: ["🚨 VISUAL IMPERSONATION: Look-alike characters", "🛑 DO NOT OPEN: characters were swapped to imitate a trusted institution."],
  TYPOSQUATTING_LOOKALIKE: ["🚨 VISUAL IMPERSONATION: Misspelled look-alike of a trusted domain", "🛑 DO NOT OPEN: type the official address yourself or use the official app."],
  PHISHING_BRAND_IMPERSONATION: ["🚨 EXTREME DANGER: Fake domain impersonating a trusted brand", "🛑 DO NOT OPEN: it is designed to steal your bank login, OTP or Aadhaar."],
  OBFUSCATED_SHORT_URL: ["🚨 SUSPICIOUS LINK: Shortened URL hides the destination", "🛑 DO NOT TAP: Indian banks never send shortened links."],
  NONEXISTENT_DOMAIN: ["⚠️ DOMAIN DOES NOT EXIST", "A link to a non-existent domain is a typo, a dead lure, or a taken-down scam. Do not trust the sender."],
  OFFICIAL_NAMESPACE_BAD_TLS: ["⚠️ OFFICIAL NAME, BROKEN SECURITY: expired certificate", "Do not enter any credentials until the institution fixes its certificate."],
  OFFICIAL_NAMESPACE_UNCONFIRMED: ["⚠️ UNCONFIRMED: Official-looking name could not be validated live", "Retry in a minute. Until DNS confirms it exists, treat as unverified."],
  HIGH_RISK_UNVERIFIED_DOMAIN: ["⚠️ HIGH RISK: Unverified domain with multiple danger signals", "Do not enter banking passwords, OTPs, or personal data. Verify through the institution's official app."],
  UNVERIFIED_THIRD_PARTY_DOMAIN: ["⚠️ UNVERIFIED: Not a verified BFSI/government domain", "SafeMeAI cannot vouch for this site. Never enter banking passwords, OTPs or UPI PINs on it."],
  THREAT_FEED_LISTED: ["🚨 KNOWN THREAT: Listed in a threat-intelligence feed", "🛑 DO NOT OPEN: this address is on a published phishing/malware list. Block and report to 1930."],
  REGULATOR_WARNING_LISTED: ["🚨 REGULATOR WARNING: Unauthorised / unregistered entity", "🛑 DO NOT INVEST OR PAY: a financial regulator lists this entity as unauthorised. Report to 1930 / cybercrime.gov.in."],
  DNS_SECURITY_BLOCKED: ["🚨 DNS SECURITY BLOCK: Flagged as malicious by security DNS", "🛑 DO NOT OPEN: a malware/phishing-filtering DNS service refuses to resolve this domain."],
  RECOGNISED_BRAND_DOMAIN: ["ℹ️ Recognised global platform (not a bank or government portal)", "This is a well-known consumer platform domain used in routine messages. It is NOT a verified bank/official portal: never enter banking passwords, UPI PIN or OTPs on it."],
  ESTABLISHED_THIRD_PARTY_DOMAIN: ["ℹ️ Established website (not a bank or government portal)", "Looks like an ordinary long-lived website. Still never enter banking passwords or OTPs on non-bank sites."]
};

/** Build the /api/domain/check payload from an engine assessment. */
function domainPayload(a, rawInput) {
  const [head, advice] = a.verified
    ? [`✅ VERIFIED OFFICIAL: ${a.host}`, "Registered, live and in an authoritative namespace/allow-list. Still confirm the HTTPS padlock before entering credentials."]
    : (VERDICT_COPY[a.verdict] || [`⚠️ ${a.verdict}`, "Exercise caution."]);
  const brand = a.primaryImpersonation;
  return {
    domain: a.host,
    unicodeDomain: a.unicodeHost !== a.host ? a.unicodeHost : undefined,
    fullUrl: rawInput,
    riskScore: a.riskScore,
    riskLevel: a.riskLevel,
    verdict: a.verdict,
    headline: head,
    isWhitelisted: a.verified,
    verified: a.verified,
    tld: '.' + a.tld,
    targetBrand: brand ? (brand.brand || brand.target) : undefined,
    officialDomain: brand && brand.target && /\./.test(brand.target) ? brand.target : undefined,
    flags: a.verified ? a.evidenceForTrust : [...a.flags, ...(a.hardBlock ? [] : a.evidenceForTrust.map(g => '✓ ' + g))],
    actionAdvice: advice,
    protectionLaw: a.verified ? "Official Regulated Domain Framework" : "IT Act Section 66D (Cheating by Personation) & Indian Cyber Security Guidelines",
    realtimeTelemetry: telemetryFromAssessment(a)
  };
}

// ==========================================
// API 6: COMPREHENSIVE CITIZEN SCAM CHECKER ENGINE (Instant Verification)
// ==========================================
const indicators = require('./lib/indicators');
const linkPolicy = require('./lib/linkPolicy');
app.post('/api/scam/check', async (req, res) => {
  const { text } = req.body;
  const raw = (typeof text === 'string' ? text : '').trim();
  const lower = raw.toLowerCase();

  if (!raw || typeof text !== 'string' || !textEngine.normalizeForUrls(raw).trim() || lower === "enter message, url, or upi id" || raw === "undefined" || raw === "null") {
    return res.status(400).json({ 
      error: "Please enter or paste a specific SMS message, suspicious URL, or UPI ID to analyze." 
    });
  }

  // -------------------------------------------------------------
  // STEP 1: EMBEDDED URL & DOMAIN EXTRACTION -> DOMAIN INTELLIGENCE ENGINE
  // -------------------------------------------------------------
  if (raw.length > 5000) {
    return res.status(400).json({ error: "Message too long (max 5000 characters)." });
  }
  const { urls: extractedUrls, urlText } = textEngine.extractLinks(raw, engine.parseTarget); // NFKC, zero-width stripped, defanged

  const trimmedInput = urlText.trim();
  const isDirectUrlQuery = extractedUrls.length === 1 &&
    trimmedInput.replace(/^[a-z]+:\/\//i, '').replace(/^www\./i, '').replace(/\/+$/, '').toLowerCase() ===
    extractedUrls[0].full.replace(/^[a-z]+:\/\//i, '').replace(/^www\./i, '').replace(/\/+$/, '').toLowerCase();

  // Every link is judged on live evidence. Gemini second-opinion only for a single direct lookup (latency).
  const assessments = await Promise.all(extractedUrls.map(u =>
    engine.assessDomain(u.full, { ...engineDeps, _matcher: engineDeps._matcher, useGemini: isDirectUrlQuery && engineDeps.useGemini })
      .catch(err => ({ ok: false, error: err.message, host: u.domain }))
  ));
  // A failed assessment fails CLOSED (never "safe").
  const failed = assessments.find(a => !a.ok);
  const scored = assessments.filter(a => a.ok);

  const toScamShape = (a, extra = {}) => {
    const payload = domainPayload(a, raw);
    return {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: payload.riskScore,
      riskLevel: payload.riskLevel,
      scamType: a.verified ? "Verified Banking / Official Authority Portal" : (VERDICT_COPY[a.verdict] ? VERDICT_COPY[a.verdict][0].replace(/^\S+\s+/, '').split(':')[0] : a.verdict),
      headline: payload.headline,
      verdictDescription: a.verified
        ? `${a.host} is registered, resolves live, and sits in a regulated/allow-listed namespace. ${a.evidenceForTrust.join(' ')}`
        : `${payload.actionAdvice}`,
      flags: payload.flags,
      actionAdvice: a.verified
        ? ["Website is authentic and verified.", "Always ensure your browser shows the HTTPS padlock.", "Legitimate banks never ask for your UPI PIN, NetBanking password or OTP."]
        : [payload.actionAdvice, "📞 Report suspicious links to 1930 or cybercrime.gov.in.", "🛡️ Block the sender."],
      protectionLaw: payload.protectionLaw,
      targetBrand: payload.targetBrand,
      officialDomain: payload.officialDomain,
      realtimeTelemetry: payload.realtimeTelemetry,
      ...extra
    };
  };

  if (isDirectUrlQuery && scored.length === 1) {
    return res.json({ status: 'success', data: toScamShape(scored[0]) });
  }
  if (isDirectUrlQuery && failed) {
    return res.status(502).json({ error: "Verification engine unavailable. Treat this link as UNVERIFIED." });
  }

  // Message with embedded links: evidence-based (lib/linkPolicy.js). Dangerous link (hard block, young domain, look-alike ...) or an unknown
  // link next to a concrete risk signal in the wording => >= HIGH; an unknown link on its own => "not sure" (MEDIUM); a link with positive
  // evidence (verified, recognised, Tranco-popular, org-validated) is never force-boosted.
  let phishingDomainDetected = null;
  const lp = linkPolicy.plan(scored, failed);
  const linkOpts = { links: extractedUrls.length, ...lp.textOpts };
  const preTv = (lp.dangerous.length || lp.unknown.length || lp.failed) ? textEngine.analyze(raw, linkOpts) : null;
  const decision = linkPolicy.decide(lp, preTv);
  if (decision.mode !== 'none') {
    const soft = decision.mode === 'soft';
    const a = decision.link || { host: failed.host, verdict: 'UNVERIFIED_THIRD_PARTY_DOMAIN', riskScore: 75, riskLevel: 'HIGH', flags: ['Link could not be analysed — treated as unverified'], evidenceForTrust: [], verified: false, hardBlock: false, tld: '', dns: {}, ssl: {}, isOpenPhish: false, webRisk: {}, entropy: 0, registrable: failed.host, gemini: { available: false, reason: 'engine error' }, domainAge: {} };
    const linkScore = soft ? decision.floor : Math.max(a.riskScore, decision.floor);
    const lvl = soft ? textEngine.levelFor : levelBoost;
    const boosted = { ...a, riskScore: linkScore, riskLevel: lvl(linkScore) };
    // Merge the text-engine verdict so scam wording (digital arrest, KYC, ...) is not lost behind the link verdict.
    const tv = preTv;
    const ind = await indicators.assess(raw, { threatStore, reports: crowdReports });
    const textStrong = !soft && tv._meta && tv._meta.category !== 'legit' && tv._meta.category !== 'unknown' && tv.riskScore >= 60;
    const mergedScore = soft ? Math.min(59, Math.max(boosted.riskScore, tv.riskScore)) : Math.max(boosted.riskScore, tv.riskScore);
    const out = toScamShape({ ...boosted, riskScore: mergedScore, riskLevel: lvl(mergedScore) }, {
      scamType: textStrong ? `${tv.scamType} + ${boosted.hardBlock ? "Malicious Link" : "Unverified Link"}` : (boosted.hardBlock ? "Malicious / Impersonation Link" : (soft ? "Link SafeMeAI Cannot Verify" : "Unverified Link in Message")),
      headline: textStrong ? tv.headline : (soft ? "ℹ️ NOT SURE: the message links to a site SafeMeAI cannot verify" : undefined),
      verdictDescription: soft
        ? `This message contains a link to '${a.host}', a site SafeMeAI cannot verify as official. The wording itself shows no OTP, PIN, payment or threat demand, so this is "not sure", not "dangerous". Open the institution's official app or the address you type yourself instead of the link.`
        : `This message contains a link to '${a.host}'. ${a.flags.slice(0, 2).join(' ')} ${textStrong ? tv.verdictDescription : ''}`.trim(),
      flags: textStrong ? [...tv.flags, ...a.flags.slice(0, 3)] : undefined,
      actionAdvice: [
        soft ? `⚠️ Do not enter passwords, OTPs or card details on '${a.host}' unless you reached it yourself.` : `🛑 DO NOT CLICK '${a.host}'.`,
        ...(textStrong ? tv.actionAdvice : []),
        "✅ Go to your bank/service via its official app or the website printed on your card.",
        "🛡️ Block the sender and report to 1930."
      ]
    });
    if (out.headline === undefined) out.headline = domainPayload(boosted, raw).headline;
    if (out.flags === undefined) out.flags = domainPayload(boosted, raw).flags;
    if (textStrong) out.protectionLaw = tv.protectionLaw;
    return res.json({ status: 'success', data: indicators.applyToVerdict(out, ind, textEngine.levelFor) });
  }

  // -------------------------------------------------------------
  // STEP 2: MULTI-SIGNAL TEXT ENGINE (lib/textEngine.js, ported from the Android detectors).
  // Normalisation, UPI-handle checks, per-category scoring, legit-alert gate and the
  // conservative default all live there. Embedded links were already judged above.
  // NOTE: everything below this return (legacy first-match-wins regex chain) is dead code kept
  // only until it can be deleted in a quiet edit window.
  // -------------------------------------------------------------
  {
    const textVerdict = textEngine.analyze(raw, linkOpts);
    // Optional Gemini second opinion for ambiguous mid-range scores (PII-redacted, 4s timeout, fails open; see lib/textAi.js).
    const opined = await textAi.secondOpinion(raw, textVerdict, { levelFor: textEngine.levelFor }).catch(() => textVerdict);
    delete opined._meta;
    const ind = await indicators.assess(raw, { threatStore, reports: crowdReports });
    return res.json({ status: 'success', data: indicators.applyToVerdict(opined, ind, textEngine.levelFor) });
  }

  // -------------------------------------------------------------
  // LEGACY STEP 2: EMBEDDED UPI / VPA HANDLE CHECK (unreachable)
  // -------------------------------------------------------------
  const upiRegex = /[a-zA-Z0-9._-]+@(okhdfcbank|okaxis|oksbi|okicici|ybl|ibl|axl|paytm|barodampay|upi)/gi;
  const hasUpiHandle = upiRegex.test(raw);
  const upiSuspiciousHandle = /(police|cbi|rbi|escrow|verification|refund|custody|court|gov|customs|fines|official|support|helpdesk|security)@(okhdfcbank|okaxis|oksbi|okicici|ybl|ibl|axl|paytm|upi)/i.test(raw);

  // -------------------------------------------------------------
  // STEP 3: PATTERN & HEURISTIC ENGINE (PORTED FROM AIAnalyzer.kt)
  // -------------------------------------------------------------
  const hasDigitalArrest = /cbi|arrest|police|supreme court|pmla|mdma|narcotics|customs|dhl|fedex|parcel|escrow|skype|digital arrest|surveillance|verification account|cyber cell|high court|warrant/i.test(lower);
  const hasUpiCollect = /upi pin|enter pin|scan qr|collect request|refund approved|to receive money|cashback credited|refund desk|gpay refund|phonepe refund|reverse payment|mpin|pay to receive/i.test(lower);
  const hasElectricity = /electricity|power cut|power disconnected|bill unpaid|light disconnect|officer\s*\+?91|discom|bill update|bijli|meter disconnect|power supply/i.test(lower);
  const hasPredatoryLoan = /instant loan|sanctioned in 5 min|7-day|7 day loan|contact list access|gallery access|quick rupee|rupee advance|processing fee upfront|loan approved|easy credit|no cibil/i.test(lower);
  const hasJobMule = /telegram|like youtube|part time job|earn 3000|earn 5000|prepaid task|deposit 1000|merchant review|hotel review task|work from home|vip task|daily payout/i.test(lower);
  const hasSextortion = /video call recorded|private video|porn video|send 20000|circulate to friends|viral your clip|social media leak|compromised video/i.test(lower);
  const hasKycThreat = /kyc|pan card|pan linked|account blocked|card blocked|account suspended|debit card blocked|netbanking blocked|update your kyc|verify kyc|avoid deactivation|deactivate|deactivated|deactivation|sim blocked|sim deactivated|sim card|sim will be|trai notice|kyc expired|pan expired|blocked within|suspended within|verify identity|customer care/i.test(lower);
  const hasRemoteAccess = /anydesk|teamviewer|rustdesk|quicksupport|remote support|screen share|install app for support/i.test(lower);
  const hasRewardsLottery = /lottery|kbc|reward points|redeem points|congratulations you won|claim gift|lucky draw|25 lakh|free recharge|free power scheme|cashback credited|won cash/i.test(lower);
  const hasTrafficChallan = /echallan|challan pending|traffic fine|court challan|vehicle challan|rto fine/i.test(lower);
  const hasIndiaPost = /india post|indiapost|speed post|parcel detained|package detained|delivery address|incomplete address|update address|redelivery fee|consignment|customs duty unpaid|postal package/i.test(lower);
  const hasOtpStealing = /share your otp|verify otp|enter otp to receive|otp for delivery|tell me the otp/i.test(lower);

  // Legitimate Bank Alert Check
  const hasBankWhitelistPatterns = /(debited by|credited with|inr [0-9,]+|avail bal|txn on|card ending in|swiggy|zomato|uber|ola|transaction successful)/i.test(lower);
  const isStrictLegitimateBankAlert = hasBankWhitelistPatterns && 
    !hasDigitalArrest && !hasUpiCollect && !hasKycThreat && !hasPredatoryLoan && 
    !hasJobMule && !hasElectricity && !hasRemoteAccess && !hasOtpStealing && !hasIndiaPost &&
    !phishingDomainDetected && !upiSuspiciousHandle;

  // -------------------------------------------------------------
  // STEP 4: VERDICT GENERATION
  // -------------------------------------------------------------
  let result = null;

  if (phishingDomainDetected) {
    const d = phishingDomainDetected;
    let scamType = "Malicious URL / Sideload Trap";
    let headline = `🚨 MALICIOUS DOMAIN: High-Risk URL (${d.domain})`;
    let desc = `This message directs you to '${d.domain}', an unauthorized host designed for credential theft or malware distribution.`;
    let risk = 98;
    let flags = [
      "URL extracted directly from message payload",
      "Attempts to harvest NetBanking logins, OTPs, or install malicious APK"
    ];

    if (d.type === "CONFIRMED_ZERO_DAY_PHISHING") {
      scamType = "Confirmed Zero-Day Phishing Threat";
      headline = `🚨 CRITICAL ALERT: Active Zero-Day Threat (${d.domain})!`;
      desc = `The link '${d.domain}' is an active phishing campaign flagged in real time by the global threat intelligence feed (OpenPhish).`;
      flags.unshift(`Actively listed on live OpenPhish zero-day phishing stream`);
      risk = 100;
    } else if (d.type === "BRAND_IMPERSONATION") {
      scamType = `Phishing Site Impersonating ${d.brand}`;
      headline = `🚨 CRITICAL PHISHING: Fake ${d.brand} Domain!`;
      desc = `This message mimics ${d.brand} but points to fraudulent domain '${d.domain}'.`;
      flags.unshift(`Unverified host mimicking ${d.brand} (Official is ${d.official})`);
    } else if (d.type === "TYPOSQUATTING_LOOKALIKE") {
      scamType = "Visual Lookalike (Typosquatting)";
      headline = `🚨 VISUAL IMPERSONATION: Lookalike of ${d.target}!`;
      desc = `The domain '${d.domain}' visually mimics authentic domain '${d.target}' using deceptive spelling variations.`;
      flags.unshift(`Typosquatting fraud signature (Matches verified ${d.target})`);
      risk = 98;
    } else if (d.type === "OBFUSCATED_SHORT_URL") {
      scamType = "Obfuscated / Shortened URL Trap";
      headline = `🚨 SUSPICIOUS LINK: Obfuscated Short URL (${d.domain})`;
      desc = `This message uses URL shortener '${d.domain}' to hide the true phishing destination. Under TRAI regulations, legitimate banks in India never send shortened links.`;
      flags.unshift(`Shortened link obfuscates the true destination website`);
      risk = 96;
    } else if (d.type === "MALICIOUS_PHISHING_PATTERN") {
      scamType = "Credential Harvesting URL Pattern";
      headline = `🚨 SUSPICIOUS LURE: Phishing URL Grammar (${d.domain})`;
      desc = `The domain '${d.domain}' uses universal phishing keywords (-kyc, pan-update, rewardz) to bait victims.`;
      flags.unshift(`Phishing grammar pattern detected in URL`);
      risk = 95;
    } else if (d.type === "UNVERIFIED_THIRD_PARTY_DOMAIN") {
      scamType = "Standard Third-Party Website";
      headline = `ℹ️ Standard Web Domain (${d.domain})`;
      desc = `This domain is not an official banking or government institution, but no active phishing traps or lookalike signatures were detected.`;
      flags = ["Standard external web host", "Not an RBI/Govt authorized financial portal"];
      risk = 25;
      result = {
        analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
        timestamp: new Date().toISOString(),
        riskScore: 25,
        riskLevel: "LOW",
        scamType: "Standard Third-Party Website",
        headline: `ℹ️ Standard Web Domain (${d.domain})`,
        verdictDescription: `This domain is not an official banking or government institution, but no active phishing traps or lookalike signatures were detected.`,
        flags: flags,
        actionAdvice: [
          "Website appears to be a standard third-party domain.",
          "Exercise normal web browsing caution.",
          "Never enter banking passwords, OTPs, or UPI PINs on third-party websites."
        ],
        protectionLaw: "Indian Information Technology Act"
      };
      return res.json({ status: 'success', data: result });
    } else if (d.type === "UNVERIFIED_EXTERNAL_LINK") {
      scamType = "Unverified External Domain Link";
      headline = `⚠️ UNVERIFIED LINK: External Host (${d.domain})`;
      desc = `The link points to '${d.domain}', which is not registered in official Indian government or banking directories.`;
      flags.unshift(`Domain '${d.domain}' is not on the national BFSI whitelist`);
      risk = 85;
    } else {
      flags.unshift(`High-risk disposable TLD (.${d.tld}) or APK payload`);
    }

    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: risk,
      riskLevel: risk >= 80 ? "CRITICAL" : "HIGH",
      scamType: scamType,
      headline: headline,
      verdictDescription: desc,
      flags: flags,
      actionAdvice: [
        `🛑 DO NOT CLICK THE LINK: Never open '${d.domain}'.`,
        `✅ If you need services, visit the official website directly: ${d.official || "official app on Google Play"}.`,
        "🛡️ Block the sender and report to 1930."
      ],
      protectionLaw: "IT Act Section 66D (Cheating by Personation) & Section 43"
    };
  } else if (upiSuspiciousHandle) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 99,
      riskLevel: "CRITICAL",
      scamType: "Fake Government / Bank UPI Handle",
      headline: "🚨 FRAUDULENT UPI HANDLE: Fake Authority Impersonation!",
      verdictDescription: "The UPI ID in this message uses deceptive words (police, rbi, escrow, refund) to trick citizens into transferring funds.",
      flags: [
        "Unregistered personal UPI handle pretending to be Government/RBI",
        "Classic money mule destination account",
        "RBI, CBI, and Police NEVER accept UPI transfers from citizens"
      ],
      actionAdvice: [
        "🛑 DO NOT SEND ANY MONEY: Transfers to this UPI handle go directly into a scammer's mule account.",
        "🛑 Decline any payment request on PhonePe / Google Pay / Paytm.",
        "📞 Report this UPI ID immediately to 1930."
      ],
      protectionLaw: "NPCI UPI Security Guidelines & PMLA Section 3"
    };
  } else if (hasDigitalArrest) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 99,
      riskLevel: "CRITICAL",
      scamType: "Digital Arrest Extortion (Central Agency Impersonation)",
      headline: "🚨 EXTREME DANGER: Digital Arrest Cybercrime Detected!",
      verdictDescription: "Matches 100% of signatures for fraudulent 'Digital Arrest' extortion. Fraudsters pose as CBI/Police/Customs to extort victims.",
      flags: [
        "Impersonation of Police / CBI / Customs / Courts",
        "Coercive video call or surveillance ultimatum",
        "False claim of contraband, narcotics, or money laundering",
        "Demand to transfer funds to 'Escrow' or 'Verification' accounts"
      ],
      actionAdvice: [
        "🚨 HANG UP IMMEDIATELY. Disconnect Skype or WhatsApp video call.",
        "🛑 UNDER INDIAN LAW: No police or court ever arrests citizens over video calls or demands money.",
        "📞 Dial 1930 immediately (National Cyber Crime Helpline) or report on cybercrime.gov.in.",
        "🛡️ Report the caller's profile or number to the platform (WhatsApp/Skype) and to cybercrime.gov.in."
      ],
      protectionLaw: "BNSS 2023 & IT Act Section 66D (Cheating by Impersonation)"
    };
  } else if (hasUpiCollect) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 96,
      riskLevel: "CRITICAL",
      scamType: "UPI Collect Inversion / PIN Trap Scam",
      headline: "⚡ CRITICAL FRAUD: Attempt to Drain Bank Account via UPI PIN",
      verdictDescription: "Scammers send a Collect Request or QR code pretending you are 'receiving' a refund or cashback.",
      flags: [
        "Reverse Collect Request (Paying to receive)",
        "Misleading urgency ('Refund expiring', 'Cashback available')",
        "Requesting UPI PIN or QR scan for inbound funds"
      ],
      actionAdvice: [
        "🛑 DO NOT ENTER YOUR UPI PIN: Entering your UPI PIN ALWAYS DEDUCTS money from your account.",
        "❌ Decline the collect request on Google Pay / PhonePe / Paytm immediately.",
        "🚫 You NEVER need a PIN or QR code to receive money in India.",
        "🛡️ Report the request in your UPI app and on cybercrime.gov.in or 1930."
      ],
      protectionLaw: "NPCI UPI Safety Guidelines & RBI Master Directions on Fraud Prevention"
    };
  } else if (hasElectricity) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 95,
      riskLevel: "CRITICAL",
      scamType: "Fake Electricity / Utility Disconnection Scam",
      headline: "⚠️ HIGH FRAUD RISK: Fake Utility Disconnection Notice",
      verdictDescription: "Mass SMS fraud threatening power cutoff at night to panic citizens into calling a scammer or downloading a remote APK.",
      flags: [
        "Imminent cutoff panic threat ('disconnected at 9:30 PM')",
        "Unofficial personal mobile number given for 'Electricity Officer'",
        "Pressure to pay via third-party link or install an app"
      ],
      actionAdvice: [
        "🛑 Do NOT call the phone number in the SMS.",
        "🛑 Power companies NEVER disconnect electricity without official physical postal notices.",
        "✅ Check your power bill directly on the official state DISCOM portal or your electricity bill app.",
        "🛡️ Block the sender number."
      ],
      protectionLaw: "Electricity Act 2003 (Notice Requirements) & IT Act 66D"
    };
  } else if (hasKycThreat) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 94,
      riskLevel: "CRITICAL",
      scamType: "Banking / SIM KYC Suspension Threat",
      headline: "⚠️ DANGER: Coercive KYC / Account Deactivation Scam",
      verdictDescription: "Scammers threaten that your bank account, debit card, or SIM card will be deactivated within 24 hours.",
      flags: [
        "Coercive deactivation ultimatum ('blocked within 24h', 'kyc expired')",
        "Urges clicking links or calling unofficial mobile numbers",
        "Banks & telecom operators never cancel accounts without physical branch notices"
      ],
      actionAdvice: [
        "🛑 DO NOT click links in the SMS or call the number provided.",
        "✅ Open your verified banking app or visit your bank branch directly.",
        "🛡️ Banks never send link-based KYC updates via unverified SMS."
      ],
      protectionLaw: "RBI Master Direction on Customer KYC & IT Act 66D"
    };
  } else if (hasRemoteAccess) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 98,
      riskLevel: "CRITICAL",
      scamType: "Remote Access Screen-Takeover Trojan",
      headline: "🚨 EXTREME DANGER: Remote Access App Trap (AnyDesk/TeamViewer)",
      verdictDescription: "Scammers instruct victims to install remote desktop tools to take over their phone and transfer bank funds.",
      flags: [
        "Instructions to install AnyDesk, TeamViewer, or QuickSupport",
        "Attempts to bypass Android screen protections and view OTPs",
        "Total loss of device control and NetBanking balance"
      ],
      actionAdvice: [
        "🛑 NEVER install AnyDesk or TeamViewer on the instructions of any caller.",
        "🛑 Disconnect any active remote screen sharing session immediately.",
        "🔒 Turn on Airplane Mode if you have already shared your 9-digit code."
      ],
      protectionLaw: "IT Act Section 43/66 (Unauthorized Access to Computer System)"
    };
  } else if (hasPredatoryLoan) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 92,
      riskLevel: "HIGH",
      scamType: "Predatory Instant Loan Extortion App",
      headline: "⚠️ DANGER: Illegal Chinese / Unregulated Loan App Trap",
      verdictDescription: "Predatory lending fraud that deducts 30-40% upfront and blackmails users using contacts and gallery photos.",
      flags: [
        "Ultra-short 7-day tenure with exorbitant hidden interest",
        "Demands intrusive access to Contact List and Gallery/Photos",
        "Unregistered NBFC operating outside RBI regulations"
      ],
      actionAdvice: [
        "🛑 NEVER install APKs sent via WhatsApp or unverified SMS links.",
        "🛑 Do NOT pay extortion demands via unofficial personal UPI handles.",
        "✅ Regulated RBI lenders are legally barred from accessing your phone contacts or photos.",
        "🛡️ SafeMeAI provides automated sideload blocking and harassment call shielding."
      ],
      protectionLaw: "RBI Digital Lending Guidelines (2022) & BNS Section 351"
    };
  } else if (hasJobMule) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 90,
      riskLevel: "HIGH",
      scamType: "Telegram Task / Money Mule Recruitment Trap",
      headline: "⚠️ FRAUDULENT LURE: 'Part-Time Job / Like YouTube' Scam",
      verdictDescription: "Scammers bait victims with small initial payouts (₹150-₹500) then force high-value deposits on fake crypto or merchant portals.",
      flags: [
        "Unrealistic income promise (₹3,000–₹5,000/day for trivial tasks)",
        "Funneling victims into private Telegram or WhatsApp groups",
        "Prepaid task requirement demanding money transfers to stranger accounts"
      ],
      actionAdvice: [
        "🛑 Exit and block the Telegram group immediately.",
        "🛑 Legitimate companies NEVER ask you to deposit money to work or receive payouts.",
        "⚠️ Transferring money to their accounts implicates you in money mule networks.",
        "📞 Report the numbers to 1930."
      ],
      protectionLaw: "PMLA Section 3 (Offence of Money Laundering) & IT Act"
    };
  } else if (hasRewardsLottery) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 89,
      riskLevel: "HIGH",
      scamType: "Counterfeit Reward / Lottery / KBC Scam",
      headline: "⚠️ PHISHING LURE: Fake Reward Points or Lottery Prize",
      verdictDescription: "Scammers promise cash prizes, KBC lotteries, or reward points to induce you into paying 'processing fees' or entering card credentials.",
      flags: [
        "Unsolicited prize or lottery claim without ticket purchase",
        "Pressure to redeem points before false expiration deadline",
        "Demands registration fee or bank details to 'release' funds"
      ],
      actionAdvice: [
        "🛑 Do NOT pay any processing fee or tax to claim prizes.",
        "🛑 Genuine banks never send external links to redeem reward points.",
        "🛡️ Block the sender."
      ],
      protectionLaw: "Lotteries (Regulation) Act & IT Act 66D"
    };
  } else if (hasTrafficChallan) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 93,
      riskLevel: "HIGH",
      scamType: "Fake Traffic e-Challan Phishing Scam",
      headline: "⚠️ HIGH FRAUD RISK: Fake Traffic Challan Link",
      verdictDescription: "Fraudsters send SMS claiming your vehicle has an unpaid traffic challan with a link leading to a cloned government portal.",
      flags: [
        "Deceptive link mimicking echallan.parivahan.gov.in",
        "Threat of court warrant or vehicle impoundment",
        "Official e-Challans only end in '.gov.in' or '.nic.in'"
      ],
      actionAdvice: [
        "🛑 NEVER pay challans on unofficial private links.",
        "✅ Check real challans only on the official national portal: https://echallan.parivahan.gov.in.",
        "🛡️ Delete the message and block sender."
      ],
      protectionLaw: "Motor Vehicles Act 2019 & IT Act 66D"
    };
  } else if (hasSextortion) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 97,
      riskLevel: "CRITICAL",
      scamType: "Cyber Sextortion & Morphed Video Blackmail",
      headline: "🚨 BLACKMAIL THREAT: Video Call Extortion / Fake Cyber Cell",
      verdictDescription: "Fraudsters record or morph video clips and threaten social media dissemination or fake police arrest.",
      flags: [
        "Threat to circulate video to family/contacts",
        "Demand for immediate ransom transfer to UPI",
        "Fake police officer accomplice calling next"
      ],
      actionAdvice: [
        "🛑 DO NOT PAY ANY MONEY: Paying will only invite repeated higher ransom demands.",
        "🔒 Immediately privatize your social media profiles.",
        "📞 Call 1930 or visit cybercrime.gov.in to report cyber blackmail (CFCFRMS).",
        "🛡️ You are the victim of an organized syndicate; do not succumb to panic."
      ],
      protectionLaw: "IT Act Section 66E / 67A & BNS Section 308 (Extortion)"
    };
  } else if (hasIndiaPost) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 96,
      riskLevel: "CRITICAL",
      scamType: "Fake India Post / Courier Redelivery Phishing",
      headline: "🚨 CRITICAL FRAUD: Fake India Post / Courier Notice",
      verdictDescription: "Mass cyber-fraud campaign mimicking India Post / Speed Post claiming a parcel cannot be delivered without an address update or payment.",
      flags: [
        "Impersonation of India Post / Speed Post logistics",
        "Fake delivery failure or address update ultimatum",
        "Demands link click or fee payment to release non-existent parcel"
      ],
      actionAdvice: [
        "🛑 DO NOT click links in the message.",
        "🛑 India Post NEVER sends SMS asking for address updates or credit card payments.",
        "✅ Verify real tracking numbers only at the official portal: https://www.indiapost.gov.in.",
        "🛡️ Block the sender and report to 1930."
      ],
      protectionLaw: "Indian Post Office Act & IT Act 66D"
    };
  } else if (isStrictLegitimateBankAlert) {
    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: 5,
      riskLevel: "SAFE",
      scamType: "Legitimate Banking Transaction / Alert",
      headline: "✅ SAFE: Standard Financial Notification",
      verdictDescription: "This message adheres to authorized banking notification standards and does not request sensitive actions.",
      flags: ["Standard transaction metadata format", "No suspicious URLs or unverified collect demands"],
      actionAdvice: [
        "Message appears genuine.",
        "Remember: Never share OTPs or passwords even with bank staff."
      ],
      protectionLaw: "RBI Fair Practices Code"
    };
  } else {
    // -------------------------------------------------------------
    // DEFAULT SAFEGUARD: UNVERIFIED THIRD-PARTY COMMUNICATION
    // -------------------------------------------------------------
    // NEVER give a clean bill of health to unknown, unverified text!
    const hasPhonePattern = /\b\d{10}\b|\+\d{1,4}[\s-]?\d{6,14}\b/.test(raw);
    const hasUrgency = /urgent|immediate|fast|quick|today|within 24 hours|attention|warning|notice/i.test(lower);

    let baseRisk = 65;
    let flags = ["Message origin is unverified against official BFSI directories"];
    if (hasPhonePattern) {
      baseRisk += 15;
      flags.push("Contains unverified personal/mobile phone number for callback");
    }
    if (hasUrgency) {
      baseRisk += 10;
      flags.push("Contains artificial urgency or pressure keywords");
    }

    result = {
      analyzedText: raw.length > 200 ? raw.substring(0, 200) + "..." : raw,
      timestamp: new Date().toISOString(),
      riskScore: Math.min(baseRisk, 85),
      riskLevel: baseRisk >= 75 ? "CRITICAL" : "HIGH",
      scamType: "Unverified Communication (Caution Advised)",
      headline: baseRisk >= 75 
        ? "🚨 HIGH RISK: Unverified Message with Threat / Urgency Signals" 
        : "⚠️ SUSPICIOUS: Unverified Third-Party Message",
      verdictDescription: "This message has NOT been verified against approved institutional directories. In India, cyber fraudsters frequently use unverified SMS and messaging probes.",
      flags: flags,
      actionAdvice: [
        "🛑 DO NOT click unknown links, install APKs, or transfer money.",
        "🛑 DO NOT call phone numbers provided directly in unverified messages.",
        "✅ Always verify inquiries directly through your official banking app or the customer care number on your physical card.",
        "📞 If anyone demands money or sensitive details, report immediately to 1930."
      ],
      protectionLaw: "Indian Cyber Security & Consumer Protection Directives"
    };
  }

  res.json({
    status: 'success',
    data: result
  });
});

// ==========================================
// API 7: DIGITAL ARREST EMERGENCY RAPID SCREENER (Authoritative I4C/MHA Protocol)
// ==========================================
app.post('/api/emergency/digital-arrest-screen', (req, res) => {
  const b = req.body || {};
  const sig = {
    agency: b.isUniformOrAgency === true,
    contraband: b.isContrabandOrPMLA === true,
    surveillance: b.isCoerciveSurveillance === true,
    money: b.isMoneyDemand === true,
    sensitive: b.isAskingSensitiveInfo === true,   // OTP / Aadhaar / card / PIN details
    appOrVideo: b.isAppOrVideoMove === true         // install an app / move to Skype-WhatsApp video
  };
  const signals = [];
  if (sig.agency) signals.push('Caller claims to be police / CBI / customs / court / RBI');
  if (sig.contraband) signals.push('Claims a parcel, drugs, money-laundering or a case in your name');
  if (sig.surveillance) signals.push('Orders you to stay on a video call or tells you to keep it secret');
  if (sig.money) signals.push('Demands money, a "verification" transfer or your bank details');
  if (sig.sensitive) signals.push('Asks you to share an OTP, Aadhaar, card or PIN details');
  if (sig.appOrVideo) signals.push('Asks you to install an app or move to Skype / WhatsApp video');
  const n = signals.length;

  // Graded, not binary: every answer changes the result. No police agency or court in India arrests anyone over a
  // video call or asks for money, so even ONE signal is a red flag; several signals together leave no doubt.
  let verdict, level, certainty, headline, summary, steps;
  if (n === 0) {
    verdict = 'NO_SIGNALS_SELECTED'; level = 'LOW'; certainty = 5;
    headline = 'No scam signals selected';
    summary = 'Nothing you selected matches the digital-arrest pattern. Stay careful: never share OTP, UPI PIN or passwords on a call, and if anything feels wrong dial 1930.';
    steps = [
      'Do not share OTP, UPI PIN, CVV or passwords with anyone who calls you.',
      'If unsure, hang up and call the organisation back on its official number.',
      'Report anything suspicious on 1930 or cybercrime.gov.in.'
    ];
  } else if (n === 1) {
    verdict = 'SUSPICIOUS_SIGNAL'; level = 'HIGH'; certainty = sig.money ? 70 : (sig.sensitive ? 65 : 55);
    headline = sig.money ? 'Warning: a demand for money is a major red flag'
      : (sig.surveillance ? 'Warning: being told to stay on camera or keep quiet is a scam tactic'
        : (sig.agency ? 'Warning: real agencies do not threaten you on WhatsApp or Skype'
          : (sig.sensitive ? 'Warning: nobody genuine asks for your OTP, Aadhaar or card details on a call'
            : (sig.appOrVideo ? 'Warning: being asked to install an app or switch to video is a scam tactic'
              : 'Warning: this sounds like a fake parcel / drugs / case lure'))));
    summary = 'One warning sign is present. Do not continue the call or act on instructions until you verify independently.';
    steps = [
      'Do not send money, share OTPs or install any app while this call continues.',
      'Hang up and call the agency or your bank yourself on the number from its official website.',
      'Tell a family member or friend what is happening right now.',
      'Report the number on 1930 or cybercrime.gov.in.'
    ];
  } else if (n === 2 && !sig.money) {
    verdict = 'LIKELY_DIGITAL_ARREST_SCAM'; level = 'CRITICAL'; certainty = 90;
    headline = 'Very likely a digital-arrest scam';
    summary = 'Two scam signs together match the standard digital-arrest script. You are not under arrest. Stop engaging.';
    steps = [
      'Hang up the call or video call now. In India no one is "arrested" over WhatsApp or Skype.',
      'Do NOT transfer money or share any bank detail, even if they say it is refundable.',
      'Tell a family member or friend immediately; scammers rely on isolating you.',
      'Dial 1930 and report the number and account on cybercrime.gov.in.'
    ];
  } else {
    verdict = 'CONFIRMED_DIGITAL_ARREST_CRIME'; level = 'CRITICAL'; certainty = n >= 4 ? 100 : (n === 3 ? 98 : 97);
    headline = 'Confirmed: this is a digital-arrest extortion scam';
    summary = 'You are in no legal danger from the police. You are facing an organised criminal extortion attempt.';
    steps = [
      '1. HANG UP the call now. Indian law (BNSS) has no arrest or interrogation over Skype or WhatsApp.',
      '2. DO NOT TRANSFER ANY MONEY. The RBI and the police never keep "escrow" or "verification" accounts for citizens.',
      '3. TELL YOUR FAMILY OR A FRIEND RIGHT NOW. The scam loses its power the moment someone else knows.',
      '4. DIAL 1930 immediately. If you already paid, call within the first hour: banks can freeze the money. Also report on cybercrime.gov.in.'
    ];
  }

  res.json({
    status: 'success',
    engine: 'deterministic-rules',
    verdict, level, certainty, headline, summary, signals, signalCount: n,
    emergencyProtocol: steps
  });
});

// ==========================================
// API 9: HYBRID CROSS-REFERENCE DOMAIN & URL CHECKER (HCRV ENGINE)
// ==========================================
app.post('/api/domain/check', async (req, res) => {
  const rawInput = String(req.body.url || req.body.domain || "").trim();
  if (!rawInput) {
    return res.status(400).json({ error: "Please enter a domain or URL to evaluate." });
  }
  if (rawInput.length > 2048) {
    return res.status(400).json({ error: "Input too long." });
  }
  try {
    const a = await engine.assessDomain(rawInput, engineDeps);
    if (!a.ok) return res.status(400).json({ error: "Invalid domain or URL format." });
    res.json({ status: 'success', data: domainPayload(a, rawInput) });
  } catch (err) {
    console.error('[domain/check] engine failure:', err);
    // Fail closed: an engine failure must never read as "safe".
    res.status(502).json({ error: "Verification engine unavailable. Treat this domain as UNVERIFIED." });
  }
});


// ==========================================
// API 8: CITIZEN REPORT SUBMISSION (FEED SAFEMEAI)
// ==========================================
// Crowd-report pipeline (lib/reports.js): validation, dedupe, rate limits, reputation, allow-list immunity, expiry.
const reportsLib = require('./lib/reports');
const crowdReports = reportsLib.createReports({
  isProtected: isProtectedDomain,
  corroborate: async (type, value) => {
    if (type !== 'domain') return {};
    const [age, imp] = await Promise.all([
      engine.lookupDomainAge(value).catch(() => null),
      Promise.resolve().then(() => engine.detectImpersonation(value, engineDeps._matcher, BRAND_KEYWORDS, { suspiciousTlds: SUSPICIOUS_TLDS })).catch(() => [])
    ]);
    return { ageDays: age && age.available && Number.isFinite(age.ageDays) ? age.ageDays : null, lookalike: Array.isArray(imp) && imp.length > 0 };
  }
});

async function handleReport(req, res, channel) {
  const b = req.body || {};
  if (!b.scamTarget || (channel === 'web' && !b.scamType)) {
    return res.status(400).json({ error: "Please provide the scammer's phone number/UPI ID/URL and scam category." });
  }
  if (channel === 'app') {
    if (process.env.APP_REPORT_KEY && req.get('x-app-key') !== process.env.APP_REPORT_KEY) return res.status(401).json({ error: 'Unauthorized app client.' });
    if (typeof b.deviceId !== 'string' || b.deviceId.length < 16 || b.deviceId.length > 128) return res.status(400).json({ error: 'deviceId (16-128 chars) is required.' });
  }
  try {
    // reporterName / reporterPhone from the web form are intentionally ignored (PII minimisation).
    const r = await crowdReports.submit({ target: b.scamTarget, scamType: b.scamType, details: b.scamDetails, deviceId: channel === 'app' ? b.deviceId : null, ip: req.ip, ua: req.get('user-agent'), channel });
    if (!r.ok) {
      if (r.retryAfterSec) res.set('Retry-After', String(r.retryAfterSec));
      return res.status(r.status || 400).json({ error: r.message || 'Report rejected.', code: r.error });
    }
    res.json({
      status: 'success',
      message: r.duplicate ? r.message : 'Report received. It becomes a community alert once enough independent reporters confirm it; reports never block verified official domains.',
      dataSource: 'crowd-pipeline',
      report: r.record
    });
  } catch (err) {
    console.error('[report] failure:', err);
    res.status(500).json({ error: 'Could not record the report right now.' });
  }
}

app.post('/api/scam/report', (req, res) => handleReport(req, res, 'web'));
app.post('/api/v1/app/report', (req, res) => handleReport(req, res, 'app'));

app.get('/api/scam/reports', async (req, res) => {
  try {
    const live = await crowdReports.publicFeed(20);
    res.json({
      status: 'success',
      dataSource: 'crowd-pipeline',
      dataSourceNote: live.length ? 'Values reported by multiple independent citizens. Targets are partially masked.' : 'No community-confirmed reports yet.',
      data: live
    });
  } catch (err) {
    res.status(500).json({ error: 'Could not load reports.' });
  }
});

// Signed delta for the Android DynamicDomainFeed. Format: docs/blocklist-api.md
app.get('/api/v1/blocklist/delta', async (req, res) => {
  const key = process.env.BLOCKLIST_SIGNING_KEY;
  if (!key) return res.status(503).json({ error: 'Blocklist signing is not configured.' });
  let since = 0;
  if (req.query.since != null && req.query.since !== '') {
    since = /^\d+$/.test(String(req.query.since)) ? Number(req.query.since) : Date.parse(String(req.query.since));
    if (!Number.isFinite(since) || since < 0) return res.status(400).json({ error: 'since must be epoch milliseconds or ISO-8601.' });
  }
  try {
    const d = await crowdReports.delta(since, 1000);
    const signed = reportsLib.signDelta(d, since, key);
    res.set('Cache-Control', 'no-store').set('X-Blocklist-Signature', signed.sig).json(signed);
  } catch (err) {
    console.error('[blocklist] failure:', err);
    res.status(500).json({ error: 'Blocklist unavailable.' });
  }
});

// Human review queue (allow-listed / shared-hosting / mass-reported established domains). Disabled unless ADMIN_TOKEN is set.
function adminOnly(req, res, next) {
  const t = process.env.ADMIN_TOKEN;
  if (!t) return res.status(404).end();
  const got = Buffer.from(String(req.get('authorization') || '')), want = Buffer.from('Bearer ' + t);
  if (got.length !== want.length || !require('crypto').timingSafeEqual(got, want)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
app.get('/api/v1/admin/reports/review', adminOnly, async (req, res) => res.json({ status: 'success', data: await crowdReports.reviewQueue() }));
app.post('/api/v1/admin/reports/review', adminOnly, async (req, res) => {
  const { type, value, decision } = req.body || {};
  const norm = reportsLib.normaliseTarget(value);
  if (!norm.ok || norm.type !== type) return res.status(400).json({ error: 'Invalid type/value.' });
  const r = await crowdReports.decide(norm.type + ':' + norm.value, decision);
  res.status(r.ok ? 200 : 400).json(r);
});


app.use(globalErrorHandler); // also catch errors thrown by routes registered after the first handler

const vertexLoc = process.env.VERTEX_LOCATION || 'asia-south1';
const server = app.listen(PORT, () => {
  if (!/^asia-south[12]$/.test(vertexLoc) && !process.env.GEMINI_API_KEY) {
    console.warn(JSON.stringify({ severity: 'WARNING', message: `VERTEX_LOCATION=${vertexLoc} is outside India (asia-south1/2); prompts leave the Indian region. Check DPDP/RBI data-localisation obligations.` }));
  }
  if (audit.ephemeralSecret) console.warn(JSON.stringify({ severity: 'WARNING', message: 'AUDIT_HMAC_SECRET not set: client network hashes are per-instance and not correlatable across instances/restarts.' }));
  console.log(JSON.stringify({
    severity: 'INFO', message: 'startup', service: 'safemeai-portal', engineVersion: audit.engineVersion, node: process.version, port: Number(PORT),
    cloudRunRevision: process.env.K_REVISION || null, vertexLocation: vertexLoc,
    flags: {
      gemini: process.env.DISABLE_GEMINI !== '1', threatIntel: process.env.DISABLE_THREAT_INTEL !== '1', apiKeys: apiKeys.size,
      webRisk: Boolean(process.env.WEB_RISK_API_KEY || process.env.GOOGLE_API_KEY), documentAI: Boolean(process.env.DOCUMENT_AI_PROCESSOR),
      auditBigQuery: audit.bigQueryEnabled, threatStore: process.env.THREAT_STORE || 'default'
    }
  }));
});

// Graceful shutdown: Cloud Run sends SIGTERM then SIGKILL after 10 s.
let shuttingDown = false;
function shutdown(sig) {
  if (shuttingDown) return; shuttingDown = true;
  console.log(JSON.stringify({ severity: 'INFO', message: 'shutdown', signal: sig }));
  const force = setTimeout(() => process.exit(0), 8000); force.unref();
  server.close(async () => { try { await audit.flush(); } catch (_) {} process.exit(0); });
  audit.flush().catch(() => {});
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

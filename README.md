# SafeMeAI BFSI Fraud-Defense Portal

Node/Express + static frontend for Indian banking-fraud defence (scam message checker, domain/URL verifier,
digital-arrest screener, document lab, Gemini advisor, analytics, citizen reports). Runs on Google Cloud Run.

## Architecture: layered domain verification (`lib/domainEngine.js`)

1. **Allow-list + DNS verification** - authoritative bank/government namespaces (e.g. `.gov.in`, `.bank.in`) count as
   VERIFIED only if the name actually resolves (Google Public DNS over HTTPS). Unknown or unresolved names are never "safe by default".
2. **Domain age** - RDAP (via rdap.org). Newly registered domains raise risk.
3. **Google Web Risk** - `uris:search` for MALWARE / SOCIAL_ENGINEERING / UNWANTED_SOFTWARE (needs `WEB_RISK_API_KEY`).
4. **OpenPhish community feed** - refreshed every 10 min; failure-safe (previous snapshot kept, status at `/api/threat-feed/status`).
5. **Live TLS audit** - handshake on port 443 (issuer, org validation, certificate age). Targets are resolved first and
   non-public addresses are refused (SSRF guard), then the vetted IP is connected to.
6. **Gemini (escalate-only)** - Vertex AI Gemini gives a second opinion on suspicious cases. It can raise risk; it never
   upgrades an unverified domain to safe. The UI shows a "Gemini live" or "rules fallback" badge.

The UI treats green/VERIFIED as meaning "confirmed official". Low-score-but-unconfirmed results are amber **UNVERIFIED**.
Any HTTP/network failure is shown as "could not verify - treat as unverified" (fail closed).

`/api/gemini/advisor` (`lib/geminiAdvisor.js`) sends the user's text to Gemini as quoted untrusted data with a JSON schema
(`riskLevel, signals, reasoning, recommendedAction`); output is validated. If Gemini is unavailable it falls back to fixed
keyword rules and labels the answer `rules-engine fallback`.

## Run locally

```bash
npm ci
DISABLE_GEMINI=1 PORT=8080 node server.js     # no Google credentials needed
GEMINI_API_KEY=... node server.js              # Gemini via API key instead of Vertex AI
```

## Environment variables

| Variable | Purpose |
|---|---|
| `PORT` | Listen port (Cloud Run sets 8080) |
| `GOOGLE_CLOUD_PROJECT` | Project for Vertex AI / BigQuery (else read from the metadata server) |
| `VERTEX_LOCATION` | Vertex AI region, default `us-central1` |
| `GEMINI_MODEL` | Default `gemini-2.5-flash` |
| `GEMINI_API_KEY` | Optional: use the Gemini API instead of Vertex AI |
| `DISABLE_GEMINI=1` | Never call Gemini (rules only) |
| `WEB_RISK_API_KEY` | Google Web Risk (store in Secret Manager) |
| `DOCUMENT_AI_PROCESSOR` | `projects/<num>/locations/<us\|eu>/processors/<id>` to enable OCR for PDF/image uploads |
| `BIGQUERY_DATASET` | Dataset holding `threat_events(vector STRING, event_ts TIMESTAMP)` to make "top vectors" live |
| `CORS_ORIGINS` | Comma-separated extra allowed origins (default: same-origin only) |
| `DISABLE_OPENPHISH=1` | Skip the OpenPhish feed (offline dev) |

## Deploy

```bash
PROJECT=<gcp-project> ./deploy-cloud-run.sh
```
Enables the APIs (aiplatform, webrisk, secretmanager, plus documentai/bigquery if configured), creates a dedicated runtime
service account with `roles/aiplatform.user`, mounts `WEB_RISK_API_KEY` from Secret Manager secret `web-risk-api-key`, and deploys
from source. The container runs as a non-root user. `/healthz` is the health endpoint.

## Hardening

Per-IP rate limit (stricter on Gemini/DNS/TLS/OCR routes, `trust proxy` = 1, pruned map), CSP without inline scripts,
`nosniff`, `frame-ancestors 'none'`, HSTS, same-origin CORS, 64 KB JSON limit, 5 MB uploads with type allow-list and
temp-file deletion, all frontend output HTML-escaped. For a global limit/WAF put the service behind an HTTPS load balancer with Cloud Armor.

## What is live vs demo

| Feature | Status |
|---|---|
| Domain checker: allow-list, Google DoH DNS, RDAP age, TLS audit, OpenPhish | **Live** |
| Google Web Risk | **Live when `WEB_RISK_API_KEY` is set**, else reported "not configured" |
| Gemini escalation and advisor | **Live on Cloud Run with `aiplatform.user`** (or API key); otherwise labelled rules fallback |
| Scam message checker (`/api/scam/check`) | Rules engine; links inside are routed through the domain engine |
| Digital-arrest screener | Deterministic rules (no AI) |
| Document lab: preset specimens | **Demo** (`dataSource: demo-simulated`), pre-written findings |
| Document lab: uploads | Document AI OCR when `DOCUMENT_AI_PROCESSOR` set; otherwise filename-only, flagged inconclusive. Verdict is keyword rules, not forensic seal/signature analysis |
| BigQuery analytics | **Demo** KPIs/mule clusters (`kpisAreSimulated`); top vectors are live only with `BIGQUERY_DATASET` |
| Compliance search | Curated static citations (Vertex AI Search is not connected) |
| Telemetry ingest | Simulated ack; nothing published to Pub/Sub or stored |
| Citizen reports | In-memory demo feed (lost on restart, not pushed to devices) |
| Hero figures ("24,510 devices", "Rs 18.42 Cr") | Illustrative demo values |

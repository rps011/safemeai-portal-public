# SafeMeAI BFSI Fraud-Defense Portal

Node/Express + static frontend for Indian banking-fraud defence (scam message checker, domain/URL verifier,
digital-arrest screener, document lab, Gemini advisor, analytics, citizen reports). Runs on Google Cloud Run.

## Architecture: layered domain verification (`lib/domainEngine.js`)

1. **Allow-list + DNS verification** - authoritative bank/government namespaces (e.g. `.gov.in`, `.bank.in`) count as
   VERIFIED only if the name actually resolves (Google Public DNS over HTTPS). Unknown or unresolved names are never "safe by default".
2. **Domain age** - RDAP (via rdap.org). Newly registered domains raise risk.
3. **Google Web Risk** - `uris:search` for MALWARE / SOCIAL_ENGINEERING / UNWANTED_SOFTWARE (needs `WEB_RISK_API_KEY`).
4. **Threat-intelligence store** (Phishing.Database, URLhaus, OpenPhish, Tranco, India regulator feeds) ingested by `lib/ingest/*` into `lib/threatStore.js`; see *Threat intelligence* below. Status at `/api/threat-feed/status`.
5. **Live TLS audit** - handshake on port 443 (issuer, org validation, certificate age). Targets are resolved first and
   non-public addresses are refused (SSRF guard), then the vetted IP is connected to.
6. **Gemini (escalate-only)** - Vertex AI Gemini gives a second opinion on suspicious cases. It can raise risk; it never
   upgrades an unverified domain to safe. The UI shows a "Gemini live" or "rules fallback" badge.

The UI treats green/VERIFIED as meaning "confirmed official". Low-score-but-unconfirmed results are amber **UNVERIFIED**.
Any HTTP/network failure is shown as "could not verify - treat as unverified" (fail closed).

`/api/gemini/advisor` (`lib/geminiAdvisor.js`) sends the user's text to Gemini as quoted untrusted data with a JSON schema
(`riskLevel, signals, reasoning, recommendedAction`); output is validated. If Gemini is unavailable it falls back to fixed
keyword rules and labels the answer `rules-engine fallback`.

## Threat intelligence (ingestion platform)

**Flow:** `lib/ingest/sources/<group>/<id>.js` (contract: `lib/ingest/contract.md`) -> `lib/ingest/runner.js` (timeout, retries with backoff, per-source isolation, run stats) -> `lib/threatStore.js` (per-source snapshot persisted to Firestore or a local file; **in-memory index for O(1) lookups, never a datastore call per request**) -> `lib/domainEngine.js`.

* Persistence: each source's latest feed is one gzip blob (split into <=800 KB chunk docs in Firestore, written under a new generation id and switched atomically). Instances reload only sources whose metadata changed (`THREAT_REFRESH_SEC`, default 300 s). Memory: bulk feeds are stored compactly (~100 B/domain); give the service 1 GiB.
* Engine: any feed hit (exact or parent-suffix; shared-hosting parents such as `github.io` are never suffix-blocked) with confidence >= 0.6 is a hard block with attribution (`Listed by Phishing.Database (ingested <ts>): phishing`). `unauthorised-forex` / `unregistered-investment` listings are CRITICAL and name the regulator. Tranco top-100k lowers the *unverified* floor (github.com -> LOW `ESTABLISHED_THIRD_PARTY_DOMAIN`) but never overrides a block, impersonation or sovereign-namespace rule, and only applies to the registrable domain itself. Cloudflare security DNS (`security.cloudflare-dns.com`, 1.5 s timeout, cached, fail-open for the signal only) hard-blocks when it sinkholes a domain that Google DNS still resolves. `engine.lookupIndicator(type, value, {threatStore})` exposes phone/UPI/entity records to the text engine.
* Honesty: a feed that has not succeeded for `INGEST_STALE_HOURS` (default 24; per source `staleAfterHours`) is reported `stale`, never `live`.

| Source | Group | Licence / terms (verified 2026-10-14 where fetchable) |
|---|---|---|
| Phishing.Database ACTIVE domains | global | MIT (repo licence; no separate data licence stated) |
| abuse.ch URLhaus (`text_online`) | global | The abuse.ch API page currently states *fair use* + Terms of Use and requires a free Auth-Key (`URLHAUS_AUTH_KEY`); it does **not** state CC0 any more. For-profit users may need abuse.ch's commercial subscription. **Confirm before launch.** |
| OpenPhish community feed | global | **Non-commercial only.** A commercial licence from OpenPhish is required for the business launch (disable with `INGEST_SOURCES_DISABLE=openphish` until then). |
| Tranco top-1M (top 100k kept) | global | tranco-list.eu states no licence of its own; it aggregates Cisco Umbrella, Majestic (CC BY 3.0), CrUX (CC BY-SA 4.0) and Cloudflare Radar (**CC BY-NC 4.0**). Treat commercial use as unverified; get it confirmed (or substitute another popularity source) before launch. Used only as "established site" context. |
| Cloudflare security DNS | live | Public DoH resolver, per-request lookups only (nothing stored); review Cloudflare's terms for commercial volume. |

**Scheduler.** Cloud Scheduler is the real driver (Cloud Run scales to zero and throttles CPU between requests, so in-process timers are unreliable): `POST /internal/ingest/run?source=<id|all>[&group=global|india][&force=1]` and `GET /internal/ingest/status`. Both require a Google OIDC bearer token: signature checked against `https://www.googleapis.com/oauth2/v3/certs`, `aud == INGEST_AUDIENCE`, `email == INGEST_SA_EMAIL`, verified, unexpired. Unconfigured => 503; bad token => 401 (failed attempts are throttled per IP). The routes live outside `/api/` so the public rate limiter and the public API are unaffected. An in-process fallback timer runs due sources every 30 min unless `INGEST_INPROCESS=0`. `scripts/setup-scheduler.sh` holds the exact gcloud commands (not executed by any code here).

| Env var | Purpose |
|---|---|
| `THREAT_STORE` | `file` (default, dev; dir `THREAT_STORE_DIR`), `memory`, or `firestore` (production) |
| `THREAT_FS_PREFIX`, `FIRESTORE_DATABASE` | Firestore collection prefix (default `threat`), database id |
| `THREAT_REFRESH_SEC` | How often an instance re-syncs changed snapshots (default 300) |
| `INGEST_AUDIENCE`, `INGEST_SA_EMAIL` | OIDC audience (the service URL) and the Scheduler service-account email; both required for the endpoints to work |
| `INGEST_INPROCESS` | `0` disables the in-process fallback timer (`INGEST_TICK_MS`, `INGEST_INITIAL_DELAY_MS` tune it) |
| `INGEST_STALE_HOURS`, `INGEST_RETRIES`, `INGEST_SOURCE_TIMEOUT_MS` | stale policy, attempts per source (3), per-attempt timeout (180 s) |
| `INGEST_SOURCES_DISABLE` | comma list of source ids to skip (`DISABLE_OPENPHISH=1` still works) |
| `INGEST_CONTACT` | contact URL put in the crawler `User-Agent` (`SafeMeAI-ThreatIntel/1.0 (+contact)`) |
| `URLHAUS_AUTH_KEY` | abuse.ch Auth-Key (send as `Auth-Key` header) |
| `DISABLE_THREAT_INTEL=1`, `DISABLE_CLOUDFLARE_DNS=1` | turn off the ingestion platform / the live Cloudflare signal |

**Status.** `GET /api/threat-feed/status` (public, back-compatible: `live, lastSuccess, lastError, indicators, ageSec` for OpenPhish) now also returns `feeds[]` with `status` (`ok|degraded|stale|failed|never-run`), `live`, `indicators`, `ageSec`, `license` per source. `GET /internal/ingest/status` (OIDC) adds run stats: count, added, removed, rejected, duration, consecutive failures.

## Platform: audit, API product, data flow, SLOs
- **Audit trail** (`lib/audit.js`, `docs/audit.md`): one JSON line per check on stdout (Cloud Logging), input SHA-256 only, client = HMAC of /24. Optional BigQuery sink `AUDIT_BIGQUERY_TABLE` (off).
- **API** (`docs/api.md`, `/api/docs`, `/api/v1/openapi.json`): v1 aliases, batch, optional API keys (`API_KEYS_JSON`), token-bucket limits per route group, `/api/system/status`, `/health`.
- **Data flow & residency**: browser/app -> Cloud Run (asia-south1) -> in-memory engines + Firestore (threat store, reports) -> optional calls out: Gemini on Vertex AI in `VERTEX_LOCATION` (default asia-south1; a startup warning is logged otherwise), Google Web Risk, public DNS (dns.google / Cloudflare), RDAP, target-site TLS handshake. Text sent to Gemini is PII-redacted first (`lib/redact.js`: phones, Aadhaar, PAN, cards, emails, UPI ids, OTP-like codes). Raw user text is not persisted; logs hold hashes only. Web Risk, DNS and RDAP lookups send the domain being checked to those providers (not the message body).
- **DPDP notes (not legal advice)**: data minimisation (hash-only audit), purpose limitation (fraud detection), no raw-IP storage, residency in India for compute/storage/Gemini by default, retention table in `docs/audit.md`. Open items: privacy notice/consent text on the UI, DPO contact, breach-notification runbook, DPA with the bank, processor list review.
- **SLO targets** (targets, not measured guarantees): availability 99.9% monthly (error budget 43 min/month; Cloud Run min-instances=0 means cold starts of a few seconds can eat budget - set min-instances=1 if affordable); p95 latency: text/UPI/phone check < 800 ms, URL/domain check < 4 s (network probes), Gemini advisor < 6 s; 5xx rate < 0.1%. Measure with Cloud Run request metrics and the audit `latencyMs`.
- **Live vs demo**: live = text/URL/UPI/phone scoring, domain verification (DNS, TLS, RDAP age, threat feeds), crowd reports, signed blocklist, audit/limits/API. Live if configured = Gemini on Vertex, Web Risk (`WEB_RISK_API_KEY`), Document AI (`DOCUMENT_AI_PROCESSOR`), BigQuery analytics (`BIGQUERY_DATASET`), audit BigQuery sink. Demo = document specimens (pre-written findings), compliance search and telemetry-ingest sample data. `/api/system/status` reports the real state.
- Env: `API_KEYS_JSON`, `AUDIT_HMAC_SECRET`, `AUDIT_BIGQUERY_TABLE`, `GIT_SHA`, `RL_*`, `SECURITY_CONTACT`, `VERTEX_LOCATION`.

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
| `DISABLE_OPENPHISH=1` | Skip the OpenPhish source (offline dev; or use `INGEST_SOURCES_DISABLE`) |

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

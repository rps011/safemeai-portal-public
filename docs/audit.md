# Audit trail

Every check request (`/api/scam/check`, `/api/domain/check`, `/api/gemini/advisor`, `/api/document-ai/analyze`,
`/api/emergency/*`, `/api/v1/batch`; v1 aliases are logged under the endpoint they dispatch to, with `route` = the
path the caller used) writes exactly one JSON line to stdout. Cloud Run ships stdout to Cloud Logging automatically
(free allocation: first 50 GiB/project/month; default `_Default` bucket retention 30 days).

```json
{"severity":"INFO","message":"audit","logType":"safemeai.audit","timestamp":"...","requestId":"uuid","endpoint":"/api/scam/check",
 "route":"/api/v1/check","httpStatus":200,"apiKeyId":"anon","clientNetHash":"24 hex","inputType":"message|url|upi|phone|domain|...",
 "inputHash":"sha256 hex","inputLength":123,"verdict":"...","riskScore":87,"engineVersion":"1.0.0+<GIT_SHA>",
 "dataSources":{"threatStoreSnapshotTs":"...","geminiUsed":false},"latencyMs":42}
```

Privacy properties: raw input and raw IPs are never logged. `inputHash` is a plain SHA-256 (lets an auditor prove
"this exact text got this verdict" by re-hashing; low-entropy inputs such as a short UPI id could be guessed, so treat
logs as confidential). `clientNetHash` is HMAC-SHA256 of the /24 (IPv4) or /48 (IPv6) keyed with `AUDIT_HMAC_SECRET`
(set it as a Secret Manager secret; without it the key is per-instance and hashes are not correlatable). For uploaded
files the hash covers metadata (type, size, name), not file content.

`requestId` is taken from an inbound `x-request-id` (8-80 chars `[A-Za-z0-9._-]`) or generated, returned as the
`x-request-id` header and as `requestId` + `engineVersion` fields in every JSON response under `/api/` (signed
blocklist responses are excluded so signatures stay valid). `engineVersion` = `package.json` version + `+GIT_SHA`
when the env var `GIT_SHA` is set (add `--set-env-vars GIT_SHA=$(git rev-parse --short HEAD)` at deploy).

## Free sink (recommended): Cloud Logging sink

```bash
PROJECT=<project>
# 1. Dataset (asia-south1 keeps data in India) - BigQuery sandbox/free tier: 10 GiB storage, 1 TiB queries/month
bq --location=asia-south1 mk -d --default_table_expiration 15552000 $PROJECT:safeme_audit   # 180 days
# 2. Sink only the audit lines, partitioned tables
gcloud logging sinks create safeme-audit-bq \
  bigquery.googleapis.com/projects/$PROJECT/datasets/safeme_audit \
  --log-filter='resource.type="cloud_run_revision" AND jsonPayload.logType="safemeai.audit"' --use-partitioned-tables
# 3. Grant the sink's writer identity BigQuery Data Editor on the dataset
WRITER=$(gcloud logging sinks describe safeme-audit-bq --format='value(writerIdentity)')
bq add-iam-policy-binding --member="$WRITER" --role=roles/bigquery.dataEditor $PROJECT:safeme_audit
# Alternative: long-term archive in Cloud Storage (cheapest; Nearline/Coldline lifecycle)
gcloud storage buckets create gs://$PROJECT-safeme-audit --location=asia-south1
gcloud logging sinks create safeme-audit-gcs storage.googleapis.com/$PROJECT-safeme-audit \
  --log-filter='jsonPayload.logType="safemeai.audit"'
# 4. Longer retention of the log bucket itself (30 days is default; extra retention beyond 30 days is billed)
```

## Optional in-app BigQuery sink (OFF by default)

Set `AUDIT_BIGQUERY_TABLE=<dataset>.<table>`. Rows are buffered (flush every 5 s or 50 rows, max 1000 buffered,
oldest dropped when the sink is down), written with `tabledata.insertAll` using metadata ADC; failures never affect
requests. Streaming inserts are not in the BigQuery free tier, so prefer the log sink above. Table schema:

```bash
bq mk --table $PROJECT:safeme_audit.checks \
  timestamp:TIMESTAMP,request_id:STRING,endpoint:STRING,api_key_id:STRING,client_net_hash:STRING,input_type:STRING,\
input_hash:STRING,input_length:INTEGER,verdict:STRING,risk_score:INTEGER,engine_version:STRING,gemini_used:BOOLEAN,\
snapshot_ts:STRING,latency_ms:INTEGER,http_status:INTEGER
```
The service account needs `roles/bigquery.dataEditor` on the dataset. SIGTERM flushes the buffer.

## Reading it back: Live analytics

`GET /api/bigquery/analytics` runs fixed, parameterised SQL (jobs.query, location asia-south1, `maximumBytesBilled` 100 MB,
5 s timeout) against `AUDIT_BIGQUERY_TABLE` as the runtime service account, cached in memory for 60 s. It needs
`roles/bigquery.jobUser` on the project and read access (dataset WRITER includes it). Output: checks in 24 h / 7 d / 30 d,
unique anonymised networks, checks per day (14 d), risk buckets (SAFE <20, LOW <40, MEDIUM <60, HIGH <80, CRITICAL),
mix by endpoint and input type, Gemini share, p50/p95 latency per endpoint, top verdicts, and the SQL used. If BigQuery is
not configured, unreachable or empty the response is `available:false` with an honest `reason`. Only aggregate counts
leave the service: no input text, hashes or network hashes are returned.

## Retention policy (proposal - confirm with counsel/DPO)

| Data | Where | Retention |
| --- | --- | --- |
| Audit lines (hashes only, no raw input/IP) | Cloud Logging `_Default` | 30 days |
| Same, in BigQuery / GCS sink | asia-south1 | 180 days online, then delete (or archive up to the bank's regulatory period) |
| Crowd reports | Firestore | per `lib/reports.js` expiry rules |
| Raw user text | not stored by the platform | n/a (processed in memory; PII-redacted before Gemini) |

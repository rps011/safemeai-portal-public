# API reference (platform)

Live docs: `GET /api/docs` (human) and `GET /api/v1/openapi.json` (OpenAPI 3.0).

## Auth
Optional. `X-API-Key: <keyId>.<secret>`. Anonymous requests use the free tier, so the public site works unchanged.
Invalid key => `401 {"error","code":"INVALID_API_KEY"}`. Keys come from env `API_KEYS_JSON` (store in Secret Manager):

```json
{"acme-pilot":{"secretHash":"<sha256 hex of the secret>","tier":"pilot","rpm":150}}
```
Generate: `SECRET=$(openssl rand -hex 24); printf %s "$SECRET" | shasum -a 256` then give the customer `acme-pilot.$SECRET`.
Hash comparison is constant-time. Tiers: `free` (x1), `pilot` (x5 of the base limits); `rpm` overrides the multiplier
(multiplier = rpm/30 against the check group's 30/min base).

## Endpoints
`POST /api/v1/check {input}` (auto-detects message/URL/UPI/phone; same engine as `/api/scam/check`),
`POST /api/v1/message/check {text}`, `POST /api/v1/domain/check {url|domain|input}`,
`POST /api/v1/batch {items:[string|{input,type?:"domain"}] (1..20)}` (concurrency 4, per-item results, costs `1 + ceil(n/10)` check-quota units),
legacy routes unchanged. Ops: `GET /health`, `/api/health` (`/healthz` is swallowed by Cloud Run's front end),
`GET /api/system/status` (cached 30 s; truthful liveness of Gemini, Web Risk, Document AI, BigQuery, threat store, audit sink).

## Rate limits (token bucket, per instance)
| Group | Routes | Burst | Refill/min |
| --- | --- | --- | --- |
| check | scam/check, domain/check, v1/batch | 20 | 30 |
| gemini | gemini/* | 10 | 10 |
| doc | document-ai/analyze | 6 | 6 |
| general | other /api | 60 | 120 |

Keyed by API key id, else client IP. Env overrides: `RL_<CHECK|GEMINI|DOC|GENERAL>_<BURST|PER_MIN>`.
Headers on every limited route: `X-RateLimit-Limit/Remaining/Reset/Group`; 429 adds `Retry-After` and body
`{"error","code":"RATE_LIMITED","retryAfterSec"}`.

## Errors
`400 BAD_REQUEST | BAD_JSON`, `401 INVALID_API_KEY`, `413 PAYLOAD_TOO_LARGE` (64 KB JSON / 5 MB upload), `429 RATE_LIMITED`,
`500 INTERNAL` (with `requestId`; no stack/parser text is ever returned).

## Exact multi-instance limits: Cloud Armor (recommended for production; NOT executed)
The in-app limiter is per Cloud Run instance. For a global limit put an external HTTPS load balancer (serverless NEG) in
front and attach Cloud Armor. Note: the load balancer and Cloud Armor policies are billed services - do this only when
budget allows (this is why it is not enabled by default).

```bash
gcloud compute network-endpoint-groups create safeme-neg --region=asia-south1 --network-endpoint-type=serverless --cloud-run-service=<SERVICE>
gcloud compute backend-services create safeme-bes --global --load-balancing-scheme=EXTERNAL_MANAGED
gcloud compute backend-services add-backend safeme-bes --global --network-endpoint-group=safeme-neg --network-endpoint-group-region=asia-south1
gcloud compute security-policies create safeme-policy --description="SafeMeAI rate limits"
gcloud compute security-policies rules create 1000 --security-policy=safeme-policy --expression="request.path.matches('/api/.*')" \
  --action=throttle --rate-limit-threshold-count=120 --rate-limit-threshold-interval-sec=60 \
  --conform-action=allow --exceed-action=deny-429 --enforce-on-key=IP
gcloud compute backend-services update safeme-bes --global --security-policy=safeme-policy
# then: url-map, target-https-proxy (managed cert), forwarding rule; and restrict Cloud Run ingress:
gcloud run services update <SERVICE> --region=asia-south1 --ingress=internal-and-cloud-load-balancing
```
Behind a load balancer set `trust proxy` hops accordingly (currently 1 = Google front end only).

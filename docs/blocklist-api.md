# Client API (optional): blocklist & client report

These endpoints are for optional third-party/native clients. The SafeMeAI website does not use or advertise them.

## GET /api/v1/blocklist/delta?since=<ts>

`since`: epoch milliseconds (or ISO-8601). Use `0` for a full pull, then the previous response's `next`.
Returns 503 if `BLOCKLIST_SIGNING_KEY` is not set (the endpoint never serves unsigned data).

Response (`Cache-Control: no-store`; signature also in `X-Blocklist-Signature`):

```json
{ "payload": "<JSON string>", "sig": "<hex>", "alg": "HMAC-SHA256" }
```

`sig = hex(HMAC-SHA256(BLOCKLIST_SIGNING_KEY, UTF-8 bytes of the payload string))`. Verify over the exact
`payload` string BEFORE parsing it (no canonical-JSON problem). Compare in constant time.

Parsed payload:

```json
{ "format": 1, "generatedAt": 1792001528069, "since": 0, "next": 1792001000000, "hasMore": false,
  "entries": [
    { "action": "add", "type": "domain", "value": "evil-kyc.xyz", "level": "block", "category": "kyc-phishing",
      "reporters": 7, "updatedAt": 1792001000000, "expiresAt": 1807553000000 },
    { "action": "remove", "type": "phone", "value": "+919820144102", "updatedAt": 1792001100000 } ] }
```

- `type`: `domain` | `phone` | `upi`. Domains are exact hostnames (no scheme/path); match the host and, if you want, its subdomains.
- `level`: `block` (BLOCK quality: show a hard warning) or `warn` (community-reported: soft warning).
- `action: remove`: drop the entry (expired, dismissed by a human, or added to the allow-list since).
- If `hasMore` is true, call again with `since=next`. Persist `next` only after the whole page verified and applied.
- Never trust an entry for an allow-listed/sovereign domain even if present; the server filters them, the app should too.

Android verification sketch:

```kotlin
val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }
val ok = MessageDigest.isEqual(mac.doFinal(payload.toByteArray(Charsets.UTF_8)), hex(sig))
```

Caveat: a symmetric key shipped in an APK can be extracted. HMAC protects integrity against network/CDN
tampering and casual forgery, not against a motivated attacker with the APK. For a hard guarantee switch to
Ed25519 (public key in the app); the envelope stays the same.

## POST /api/v1/app/report

Same pipeline as the web form. JSON body: `{ "scamTarget": "<url|domain|phone|upi>", "scamType": "KYC", "scamDetails": "<optional>", "deviceId": "<16-128 chars, stable per install>" }`.
Optional header `X-App-Key` is enforced when `APP_REPORT_KEY` is set. `deviceId` is HMAC-hashed with `REPORTER_HASH_SECRET`; never stored raw.
Response matches `/api/scam/report`: `{ status, message, dataSource, report: {id, scamType, target, details, time, status} }`.
`status`: `RECEIVED` | `COMMUNITY_REPORTED` | `BLOCKED` | `QUEUED_FOR_REVIEW`. Errors: 400 invalid input, 401 bad app key, 429 (with `Retry-After`).

## Pipeline rules (defaults in `lib/reports.js` DEFAULTS)

- N=3 independent reporters -> community-reported (warn). Independence = distinct reporter key AND distinct network (/24 v4, /48 v6).
- BLOCK: N and engine corroboration (domain age < 30 d or lookalike), or 6 reporters spread over >= 10 minutes.
- Allow-listed, sovereign (.gov.in/.bank.in/...), shared-hosting parents/shorteners, toll-free/helpline numbers, and
  old (>= 730 d) non-lookalike domains: never auto-blocked; queued for human review.
- Rate limits: 10/h and 30/day per reporter, 60/day per network. Reporters whose reports were repeatedly dismissed stop counting.
- TTL: pending 30 d, community-reported 90 d, blocked 180 d, human-confirmed 365 d (from last report). Removals are emitted as tombstones for 30 d.

## Env vars

`BLOCKLIST_SIGNING_KEY` (required for delta), `REPORTER_HASH_SECRET` (set a stable value in prod; otherwise random per restart),
`APP_REPORT_KEY` (optional), `ADMIN_TOKEN` (enables `GET/POST /api/v1/admin/reports/review`; body `{type,value,decision:"confirm"|"dismiss"}`),
`REPORTS_FILE` (file backend path; default `data/runtime/reports.json`). Cloud Run disk is ephemeral: wire `lib/threatStore.js`
(export `reportsAdapter` with get/set/del/all) for durable storage.

## Ed25519 signing (recommended for production)
If `BLOCKLIST_SIGNING_KEY` holds a PEM Ed25519 private key, the envelope is `{payload, sig, alg:"Ed25519"}` with `sig = base64(Ed25519(payload UTF-8 bytes))`.
Ship only the PUBLIC key in the Android app and verify with it; extracting it from the APK then cannot be used to forge feeds.
Generate: `openssl genpkey -algorithm ed25519 -out blocklist-ed25519.pem && openssl pkey -in blocklist-ed25519.pem -pubout -out blocklist-ed25519.pub.pem`

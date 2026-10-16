# Hosting: safemeai.in (Firebase Hosting in front of Cloud Run)

- `safemeai.in` -> Firebase Hosting site `fraudshield-daa79c8e` (config: `firebase.json`).
- Static files (`public/`) are served by Firebase's CDN; `/api/**` is forwarded to Cloud Run service `safemeai-bfsi` (asia-south1).
- NOT reachable via safemeai.in: `/internal/**` (Cloud Scheduler calls the run.app URL directly, with OIDC).
- Android app and Cloud Scheduler keep using the Cloud Run URL; nothing changes for them.
- Visitor IP: Firebase puts the real visitor in `Fastly-Client-IP`; `lib/clientIp.js` trusts it only when the connecting hop is a Google address and `Via: Firebase Hosting` is present, so rate limits and audit hashes are per visitor.

## Deploy / preview / rollback (uses the gcloud login, no `firebase login`)
```
node scripts/deploy-hosting.js --channel preview-migrate   # free temporary preview URL (24h)
node scripts/deploy-hosting.js --live                      # release to safemeai.in (prints the previous version id)
node scripts/deploy-hosting.js --rollback <versionId>      # restore an older release
```
Pre-migration site (Sept 2025 marketing page) = version `59f79f11d173a3a7`:
`node scripts/deploy-hosting.js --rollback 59f79f11d173a3a7`  (a file backup is also kept outside the repo).
The old home page is kept at `/about`, and `/delete-account` (needed for Play Store policy) is preserved.

## Known gaps
- `www.safemeai.in` has no DNS record (Firebase reports DNS_MISSING): add a CNAME `www` -> `fraudshield-daa79c8e.web.app` at the DNS provider.
- `safemeai.com` / `www.safemeai.com` are attached to the site but have lost verification.

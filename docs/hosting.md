# Hosting: safemeai.in (Firebase Hosting in front of Cloud Run)

- `safemeai.in` -> Firebase Hosting site `fraudshield-daa79c8e` (config: `firebase.json`).
- Static files (`public/`) are served by Firebase's CDN; `/api/**` is forwarded to Cloud Run service `safemeai-bfsi` (asia-south1).
- NOT reachable via safemeai.in: `/internal/**` (Cloud Scheduler calls the run.app URL directly, with OIDC).
- Cloud Scheduler (and any optional API client) keeps using the Cloud Run URL; nothing changes for them.
- Visitor IP: Firebase puts the real visitor in `Fastly-Client-IP`; `lib/clientIp.js` trusts it only when the connecting hop is a Google address and `Via: Firebase Hosting` is present, so rate limits and audit hashes are per visitor.

## Deploy / preview / rollback (uses the gcloud login, no `firebase login`)
```
node scripts/deploy-hosting.js --channel preview-migrate   # free temporary preview URL (24h)
node scripts/deploy-hosting.js --live                      # release to safemeai.in (prints the previous version id)
node scripts/deploy-hosting.js --rollback <versionId>      # restore an older release
```
Pre-migration site (Sept 2025 marketing page) = version `59f79f11d173a3a7`:
`node scripts/deploy-hosting.js --rollback 59f79f11d173a3a7`  (a file backup is also kept outside the repo).
`/delete-account` (needed for store policy) is preserved. The old marketing page (`about.html`) and the APK were moved out of `public/` to `../archive-not-deployed/` and are no longer served.

## Known gaps
- `www.safemeai.in`: CNAME `www` -> `fraudshield-daa79c8e.web.app` is set at Hostinger; Firebase may take a few hours to see it and issue the certificate.
- Contact address for privacy, grievance and security reports: `support@safemeai.in`.
- `safemeai.com` / `www.safemeai.com` are attached to the site but have lost verification.

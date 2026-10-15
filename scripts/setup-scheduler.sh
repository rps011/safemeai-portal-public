#!/usr/bin/env bash
# Provision Cloud Scheduler + Firestore + IAM for the SafeMeAI threat-intel ingestion.
# DO NOT RUN BLINDLY: review, then run each step yourself (or `bash scripts/setup-scheduler.sh` once happy).
# Idempotency: `create` commands fail if the resource exists; use the `update` variants shown in comments.
set -euo pipefail

PROJECT="${PROJECT:-fraudshield-daa79c8e}"
REGION="${REGION:-asia-south1}"
SERVICE="${SERVICE:-safemeai-bfsi}"            # your Cloud Run service name
SA_NAME="${SA_NAME:-safeme-ingest-scheduler}"
SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"

gcloud config set project "$PROJECT"

# 1. APIs
gcloud services enable cloudscheduler.googleapis.com firestore.googleapis.com run.googleapis.com

# 2. Firestore (Native mode) in the same region. Skip if the database already exists.
gcloud firestore databases create --location="$REGION" --type=firestore-native || echo "Firestore database already exists"

# 3. Service account used by Cloud Scheduler to mint the OIDC token
gcloud iam service-accounts create "$SA_NAME" --display-name="SafeMeAI ingest scheduler" || echo "SA exists"

# 4. Scheduler SA may invoke the Cloud Run service (needed if the service ever requires IAM auth; harmless otherwise)
gcloud run services add-iam-policy-binding "$SERVICE" --region="$REGION" \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/run.invoker"

# 5. The Cloud Run RUNTIME service account needs Firestore access (NOT the scheduler SA).
RUNTIME_SA="$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(spec.template.spec.serviceAccountName)')"
RUNTIME_SA="${RUNTIME_SA:-$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')-compute@developer.gserviceaccount.com}"
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${RUNTIME_SA}" --role="roles/datastore.user"
# Let the scheduler SA also hold datastore.user only if you run ingestion outside Cloud Run with that identity:
# gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA_EMAIL}" --role="roles/datastore.user"

# 6. App configuration: the OIDC audience is the exact URL Scheduler targets (service URL, no path).
URL="$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(status.url)')"
gcloud run services update "$SERVICE" --region="$REGION" \
  --update-env-vars="THREAT_STORE=firestore,INGEST_AUDIENCE=${URL},INGEST_SA_EMAIL=${SA_EMAIL},INGEST_INPROCESS=1,GOOGLE_CLOUD_PROJECT=${PROJECT}" \
  --memory=1Gi --timeout=1800
# URLhaus now needs a free abuse.ch Auth-Key; store it in Secret Manager and mount it:
#   gcloud secrets create urlhaus-auth-key --data-file=-   (paste key, Ctrl-D)
#   gcloud run services update "$SERVICE" --region="$REGION" --update-secrets=URLHAUS_AUTH_KEY=urlhaus-auth-key:latest

# 7. Jobs. Staggered cron (Asia/Kolkata). attempt-deadline covers a full run incl. retries.
mk_job () {  # name  cron  query
  local name="$1" cron="$2" query="$3"
  gcloud scheduler jobs create http "$name" \
    --location="$REGION" --schedule="$cron" --time-zone="Asia/Kolkata" \
    --uri="${URL}/internal/ingest/run?${query}" --http-method=POST \
    --oidc-service-account-email="$SA_EMAIL" --oidc-token-audience="$URL" \
    --attempt-deadline=1800s --max-retry-attempts=1 --min-backoff=120s \
  || gcloud scheduler jobs update http "$name" \
    --location="$REGION" --schedule="$cron" --time-zone="Asia/Kolkata" \
    --uri="${URL}/internal/ingest/run?${query}" --http-method=POST \
    --oidc-service-account-email="$SA_EMAIL" --oidc-token-audience="$URL" \
    --attempt-deadline=1800s --max-retry-attempts=1 --min-backoff=120s
}

# Global feeds every 3h (Phishing.Database, URLhaus, OpenPhish, Tranco: ETag/If-Modified-Since make unchanged runs ~free)
mk_job safeme-ingest-global-fast  "7 */3 * * *"  "group=global&source=all"
# India regulators every 12h, offset so they never overlap with global runs
mk_job safeme-ingest-india        "25 5,17 * * *" "group=india&source=all"

# Long crawl (about 200 SEBI pages at 1 request / 3 s) gets its own weekly job so it fits the request timeout alone.
mk_job safeme-ingest-sebi-brokers "40 2 * * 0" "source=sebi-stock-brokers&force=1"

echo "Done. Test one job:  gcloud scheduler jobs run safeme-ingest-global-fast --location=${REGION}"
echo "Check:  curl -H \"Authorization: Bearer \$(gcloud auth print-identity-token --impersonate-service-account=${SA_EMAIL} --audiences=${URL})\" ${URL}/internal/ingest/status"

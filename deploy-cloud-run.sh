#!/usr/bin/env bash
# SafeMeAI BFSI portal - Google Cloud Run deployment.
# Usage: PROJECT=my-proj ./deploy-cloud-run.sh
# Optional: VERTEX_LOCATION, GEMINI_MODEL, DOCUMENT_AI_PROCESSOR, BIGQUERY_DATASET
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-safemeai-bfsi}"
REGION="${REGION:-asia-south1}"
PROJECT="${PROJECT:-${GOOGLE_CLOUD_PROJECT:-fraudshield-daa79c8e}}"
VERTEX_LOCATION="${VERTEX_LOCATION:-asia-south1}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.5-flash}"
SA_NAME="safemeai-run"
SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
SECRET_NAME="web-risk-api-key"
# BigQuery audit sink (Mumbai): every check is logged as a hashed-input row; the analytics tab reads it back.
AUDIT_BIGQUERY_TABLE="${AUDIT_BIGQUERY_TABLE:-safemeai_audit.checks}"
# Document AI OCR processor (Mumbai, OCR_PROCESSOR "safemeai-ocr"); documents stay in India.
DOCUMENT_AI_PROCESSOR="${DOCUMENT_AI_PROCESSOR:-projects/846801666760/locations/asia-south1/processors/37cbfc50db1e85d3}"

ACCOUNT=$(gcloud config get-value account 2>/dev/null || true)
if [ -z "$ACCOUNT" ] || [ "$ACCOUNT" = "(unset)" ]; then
  echo "Error: gcloud is not logged in. Run: gcloud auth login" >&2
  exit 1
fi
gcloud config set project "$PROJECT" >/dev/null
echo "Account: $ACCOUNT | Project: $PROJECT | Region: $REGION | Service: $SERVICE_NAME"

echo "Enabling APIs..."
APIS="run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com aiplatform.googleapis.com webrisk.googleapis.com secretmanager.googleapis.com"
[ -n "${DOCUMENT_AI_PROCESSOR:-}" ] && APIS="$APIS documentai.googleapis.com"
[ -n "${AUDIT_BIGQUERY_TABLE:-}" ] && APIS="$APIS bigquery.googleapis.com"
gcloud services enable $APIS

echo "Ensuring dedicated runtime service account..."
gcloud iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1 || \
  gcloud iam service-accounts create "$SA_NAME" --display-name "SafeMeAI Cloud Run runtime"

grant() { gcloud projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:${SA_EMAIL}" --role "$1" --condition=None --quiet >/dev/null; }
grant roles/aiplatform.user                       # Gemini on Vertex AI
grant roles/datastore.user                        # Firestore: threat store + crowd reports
[ -n "${DOCUMENT_AI_PROCESSOR:-}" ] && grant roles/documentai.apiUser
if [ -n "${AUDIT_BIGQUERY_TABLE:-}" ]; then grant roles/bigquery.jobUser; fi   # dataset WRITER access is set on safemeai_audit itself (least privilege)

# Web Risk API key lives in Secret Manager. Create it once with:
#   gcloud services enable webrisk.googleapis.com
#   (Console > APIs & Services > Credentials > Create API key, restrict to the Web Risk API)
#   printf '%s' "$KEY" | gcloud secrets create web-risk-api-key --data-file=-
SECRET_ARGS=()
SECRET_MAP=""
add_secret() {  # ENV_NAME secret-name
  if gcloud secrets describe "$2" >/dev/null 2>&1; then
    gcloud secrets add-iam-policy-binding "$2" --member "serviceAccount:${SA_EMAIL}" --role roles/secretmanager.secretAccessor --quiet >/dev/null
    SECRET_MAP="${SECRET_MAP:+$SECRET_MAP,}$1=$2:latest"
  else
    echo "WARNING: secret '$2' not found; $1 will be unset."
  fi
}
add_secret WEB_RISK_API_KEY "$SECRET_NAME"
add_secret REPORTER_HASH_SECRET reporter-hash-secret
add_secret ADMIN_TOKEN admin-token
add_secret BLOCKLIST_SIGNING_KEY blocklist-signing-key
add_secret URLHAUS_AUTH_KEY urlhaus-auth-key
add_secret AUDIT_HMAC_SECRET audit-hmac-secret
add_secret API_KEYS_JSON api-keys-json
[ -n "$SECRET_MAP" ] && SECRET_ARGS=(--set-secrets "$SECRET_MAP")

INGEST_SA_NAME="safeme-ingest-scheduler"
INGEST_SA_EMAIL="${INGEST_SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --format 'value(status.url)' 2>/dev/null || true)

ENV_VARS="NODE_ENV=production,AUDIT_BIGQUERY_TABLE=${AUDIT_BIGQUERY_TABLE},GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown),THREAT_STORE=firestore,INGEST_SA_EMAIL=${INGEST_SA_EMAIL},INGEST_AUDIENCE=${SERVICE_URL},INGEST_CONTACT=${INGEST_CONTACT:-https://safemeai.in/},INGEST_SOURCES_DISABLE=${INGEST_SOURCES_DISABLE:-openphish},GOOGLE_CLOUD_PROJECT=${PROJECT},VERTEX_LOCATION=${VERTEX_LOCATION},GEMINI_MODEL=${GEMINI_MODEL}"
[ -n "${DOCUMENT_AI_PROCESSOR:-}" ] && ENV_VARS="$ENV_VARS,DOCUMENT_AI_PROCESSOR=${DOCUMENT_AI_PROCESSOR}"

echo "Deploying from source..."
gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --platform managed \
  --region "$REGION" \
  --service-account "$SA_EMAIL" \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 5 \
  --concurrency 40 \
  --cpu 1 --memory 1Gi \
  --timeout 1800 \
  --port 8080 \
  --set-env-vars "$ENV_VARS" \
  ${SECRET_ARGS[@]+"${SECRET_ARGS[@]}"} \
  --quiet

URL=$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --format 'value(status.url)')
echo "Deployed: $URL"
echo "Health:   $URL/healthz"
echo "For a global rate limit / WAF put the service behind an external HTTPS load balancer with Cloud Armor."

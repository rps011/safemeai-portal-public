#!/usr/bin/env bash
# SafeMeAI BFSI portal - Google Cloud Run deployment.
# Usage: PROJECT=my-proj ./deploy-cloud-run.sh
# Optional: VERTEX_LOCATION, GEMINI_MODEL, DOCUMENT_AI_PROCESSOR, BIGQUERY_DATASET
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-safemeai-bfsi}"
REGION="${REGION:-asia-south1}"
PROJECT="${PROJECT:-${GOOGLE_CLOUD_PROJECT:-fraudshield-daa79c8e}}"
VERTEX_LOCATION="${VERTEX_LOCATION:-us-central1}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.5-flash}"
SA_NAME="safemeai-run"
SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
SECRET_NAME="web-risk-api-key"

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
[ -n "${BIGQUERY_DATASET:-}" ] && APIS="$APIS bigquery.googleapis.com"
gcloud services enable $APIS

echo "Ensuring dedicated runtime service account..."
gcloud iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1 || \
  gcloud iam service-accounts create "$SA_NAME" --display-name "SafeMeAI Cloud Run runtime"

grant() { gcloud projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:${SA_EMAIL}" --role "$1" --condition=None --quiet >/dev/null; }
grant roles/aiplatform.user                       # Gemini on Vertex AI
[ -n "${DOCUMENT_AI_PROCESSOR:-}" ] && grant roles/documentai.apiUser
if [ -n "${BIGQUERY_DATASET:-}" ]; then grant roles/bigquery.jobUser; grant roles/bigquery.dataViewer; fi

# Web Risk API key lives in Secret Manager. Create it once with:
#   gcloud services enable webrisk.googleapis.com
#   (Console > APIs & Services > Credentials > Create API key, restrict to the Web Risk API)
#   printf '%s' "$KEY" | gcloud secrets create web-risk-api-key --data-file=-
SECRET_ARGS=()
if gcloud secrets describe "$SECRET_NAME" >/dev/null 2>&1; then
  gcloud secrets add-iam-policy-binding "$SECRET_NAME" --member "serviceAccount:${SA_EMAIL}" --role roles/secretmanager.secretAccessor --quiet >/dev/null
  SECRET_ARGS=(--set-secrets "WEB_RISK_API_KEY=${SECRET_NAME}:latest")
else
  echo "WARNING: secret '$SECRET_NAME' not found; Google Web Risk checks will be reported as 'not configured'."
fi

ENV_VARS="NODE_ENV=production,GOOGLE_CLOUD_PROJECT=${PROJECT},VERTEX_LOCATION=${VERTEX_LOCATION},GEMINI_MODEL=${GEMINI_MODEL}"
[ -n "${DOCUMENT_AI_PROCESSOR:-}" ] && ENV_VARS="$ENV_VARS,DOCUMENT_AI_PROCESSOR=${DOCUMENT_AI_PROCESSOR}"
[ -n "${BIGQUERY_DATASET:-}" ] && ENV_VARS="$ENV_VARS,BIGQUERY_DATASET=${BIGQUERY_DATASET}"

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
  --cpu 1 --memory 512Mi \
  --timeout 60 \
  --port 8080 \
  --set-env-vars "$ENV_VARS" \
  ${SECRET_ARGS[@]+"${SECRET_ARGS[@]}"} \
  --quiet

URL=$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --format 'value(status.url)')
echo "Deployed: $URL"
echo "Health:   $URL/healthz"
echo "For a global rate limit / WAF put the service behind an external HTTPS load balancer with Cloud Armor."

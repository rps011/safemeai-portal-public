#!/usr/bin/env bash
# ==============================================================================
# SafeMeAI BFSI Command Center — Google Cloud Run 1-Click Deployment Script
# ==============================================================================

set -e

SERVICE_NAME="safemeai-bfsi"
REGION="asia-south1"
DEFAULT_PROJECT="fraudshield-daa79c8e"

echo "=========================================================="
echo " Deploying SafeMeAI BFSI Command Center to Google Cloud Run"
echo " Service: $SERVICE_NAME"
echo " Region:  $REGION"
echo "=========================================================="

# Check if gcloud is logged in
ACCOUNT=$(gcloud config get-value account 2>/dev/null)
PROJECT=$(gcloud config get-value project 2>/dev/null)

if [ -z "$ACCOUNT" ] || [ "$ACCOUNT" = "(unset)" ]; then
  echo "Error: gcloud is not logged in. Please run: gcloud auth login"
  exit 1
fi

# Set project to SafeMeAI project
gcloud config set project "$DEFAULT_PROJECT"
PROJECT="$DEFAULT_PROJECT"

echo "Active Account: $ACCOUNT"
echo "Active Project: $PROJECT"

echo ""
echo "Building and deploying container directly from source to Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --platform managed \
  --region "$REGION" \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 5 \
  --port 8080 \
  --set-env-vars "NODE_ENV=production" \
  --quiet

echo ""
echo "=========================================================="
echo " DEPLOYMENT COMPLETE!"
echo " SafeMeAI BFSI is live on Google Cloud Run!"
echo " Map your subdomain in GCP Console > Cloud Run > Manage Custom Domains."
echo "=========================================================="

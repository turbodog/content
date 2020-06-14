#!/usr/bin/env bash

# exit on errors
set -e


if [[ -z "$GCS_MARKET_KEY" ]]; then
    echo "GCS_MARKET_KEY not set aborting!"
    exit 1
fi

echo "Copying master bucket ..."

KF=$(mktemp)
echo "$GCS_MARKET_KEY" > "$KF"
gcloud auth activate-service-account --key-file="$KF" > auth.out 2>&1
echo "Auth loaded successfully."

GCS_MARKET_BUCKET="marketplace-dist"
GCS_BUILD_BUCKET="marketplace-dist-dev"
SOURCE_PATH="content/packs"

echo "Copying master files"
gsutil -m cp -r "gs://$GCS_MARKET_BUCKET/$SOURCE_PATH" "gs://$GCS_BUILD_BUCKET/backup/$SOURCE_PATH"
echo "Finished copying successfully."

#!/bin/bash
set -euo pipefail

EDGEADC_IMAGE="${EDGEADC_IMAGE:-edgeadc:latest}"
EDGEADC_CONTAINER_NAME="${EDGEADC_CONTAINER_NAME:-edgeadc-test}"
EDGEADC_API_HOST="${EDGEADC_API_HOST:-127.0.0.1}"
EDGEADC_API_PORT="${EDGEADC_API_PORT:-8443}"
EDGEADC_API_USER="${EDGEADC_API_USER:-admin}"
EDGEADC_API_PASS="${EDGEADC_API_PASS:-jetnexus}"
EDGEADC_WAIT_SECONDS="${EDGEADC_WAIT_SECONDS:-60}"
# Override settings with EDGEADC_* environment variables as needed.

if ! [[ "$EDGEADC_WAIT_SECONDS" =~ ^[0-9]+$ ]]; then
  echo "EDGEADC_WAIT_SECONDS must be a non-negative integer, got '${EDGEADC_WAIT_SECONDS}'." >&2
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd curl

cleanup() {
  docker rm -f "$EDGEADC_CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Starting EdgeADC container ${EDGEADC_CONTAINER_NAME}..."
docker run -d --rm \
  --name "$EDGEADC_CONTAINER_NAME" \
  -p "${EDGEADC_API_PORT}:443" \
  "$EDGEADC_IMAGE" >/dev/null

echo "Waiting for EdgeADC API on https://${EDGEADC_API_HOST}:${EDGEADC_API_PORT} ..."
waited=0
until curl -k -s -o /dev/null "https://${EDGEADC_API_HOST}:${EDGEADC_API_PORT}/"; do
  waited=$((waited + 1))
  if [ "$waited" -ge "$EDGEADC_WAIT_SECONDS" ]; then
    echo "EdgeADC API did not become ready within ${EDGEADC_WAIT_SECONDS}s." >&2
    exit 1
  fi
  sleep 1
done

export EDGE_TEST=docker
export EDGE_TEST_API_HOST="$EDGEADC_API_HOST"
export EDGE_TEST_API_PORT="$EDGEADC_API_PORT"
export EDGE_TEST_API_USER="$EDGEADC_API_USER"
export EDGE_TEST_API_PASS="$EDGEADC_API_PASS"

if command -v prove >/dev/null 2>&1; then
  prove -I manager/lib manager/t/test_samples.t
else
  perl -I manager/lib manager/t/test_samples.t
fi

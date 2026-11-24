#!/bin/sh
# Lab only: build deca-lab-temporal:1.32.2 from the binaries fetched by fetch-temporal.sh, with a minimal
# build context (works with the classic builder; no buildx needed).
set -eu
BIN=${1:?usage: build-temporal.sh BIN_DIR}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
CTX=$(mktemp -d)
trap 'rm -rf "$CTX"' EXIT
mkdir -p "$CTX/temporal-bin" "$CTX/deploy"
cp "$BIN/temporal-server" "$BIN/temporal-sql-tool" "$BIN/temporal" "$CTX/temporal-bin/"
cp -R "$REPO/deploy/temporal" "$CTX/deploy/temporal"
docker build -f "$REPO/deploy/lab/temporal.Dockerfile" -t "${TEMPORAL_IMAGE:-deca-lab-temporal:1.32.2}" "$CTX"

#!/bin/sh
# Lab only: download Temporal server 1.32.2 and CLI 1.10.1 (both MIT) from the official GitHub releases
# into OUT_DIR and verify the extracted binaries against deploy/temporal/SOURCE.txt.
set -eu
OUT=${1:?usage: fetch-temporal.sh OUT_DIR}
mkdir -p "$OUT"
cd "$OUT"
curl -fsSL -o server.tgz https://github.com/temporalio/temporal/releases/download/v1.32.2/temporal_1.32.2_linux_amd64.tar.gz
curl -fsSL -o cli.tgz https://github.com/temporalio/cli/releases/download/v1.10.1/temporal_cli_1.10.1_linux_amd64.tar.gz
tar xzf server.tgz temporal-server temporal-sql-tool
tar xzf cli.tgz temporal
rm -f server.tgz cli.tgz
sha256sum -c - <<'SUMS'
f4a52911a0ce909d623475d048a1994329dada035c66a050d0440d8b6958b85e  temporal-server
c90014f9a3400fa245205f6dc402ebd105f5cbbd65139985a092a360d70bd71b  temporal-sql-tool
960afddde142595ea4bf6c74f0213b4634a4ef2ef8778c2e930af2cce30d7c8a  temporal
SUMS

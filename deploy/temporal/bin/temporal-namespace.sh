#!/bin/sh
# Register the DECA namespace (once) with the temporal CLI over mTLS, as an operator cert.
set -eu
: "${TEMPORAL_CLI:=/opt/temporal/cli/temporal}"
: "${TEMPORAL_ADDRESS:?host:port of the frontend}"
: "${DECA_TEMPORAL_NAMESPACE:=deca-soar}"
: "${DECA_TEMPORAL_RETENTION:=720h}"
set -- --address "$TEMPORAL_ADDRESS"
if [ -n "${TEMPORAL_TLS_CERT:-}" ]; then
  set -- "$@" --tls-cert-path "$TEMPORAL_TLS_CERT" --tls-key-path "${TEMPORAL_TLS_KEY:?}" \
    --tls-ca-path "${TEMPORAL_TLS_CA:?}" ${TEMPORAL_TLS_SERVER_NAME:+--tls-server-name "$TEMPORAL_TLS_SERVER_NAME"}
fi
if "$TEMPORAL_CLI" operator namespace describe "$@" --namespace "$DECA_TEMPORAL_NAMESPACE" >/dev/null 2>&1; then
  echo "namespace $DECA_TEMPORAL_NAMESPACE exists"
else
  "$TEMPORAL_CLI" operator namespace create "$@" --namespace "$DECA_TEMPORAL_NAMESPACE" \
    --retention "$DECA_TEMPORAL_RETENTION" --description "DECA SOAR alert workflows"
fi

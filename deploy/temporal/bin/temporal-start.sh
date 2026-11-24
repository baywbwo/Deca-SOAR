#!/bin/sh
# Start Temporal server 1.32.2 with the DECA production config.
# The RDS password comes from a credential file (systemd LoadCredential=), never from an env file.
set -eu
: "${TEMPORAL_BIN_DIR:=/opt/temporal/1.32.2}"
: "${TEMPORAL_CONFIG_DIR:=/etc/deca-soar/temporal/config}"
: "${TEMPORAL_DB_PASSWORD_FILE:=${CREDENTIALS_DIRECTORY:-/nonexistent}/temporal_db_password}"
POSTGRES_PWD="$(cat "$TEMPORAL_DB_PASSWORD_FILE")"
export POSTGRES_PWD
# No authorizer is configured, so the server needs --allow-no-auth. Access control is the frontend's
# mTLS (requireClientAuth, DECA client CA only) plus the network: see RUNBOOK "Temporal access".
exec "$TEMPORAL_BIN_DIR/temporal-server" --root / --config "${TEMPORAL_CONFIG_DIR#/}" --env deca-production \
  --allow-no-auth start

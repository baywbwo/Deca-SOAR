#!/bin/sh
# Create or upgrade the Temporal schemas on RDS PostgreSQL. Idempotent: safe to run before every start.
# The two databases must already exist and be owned by POSTGRES_USER (RUNBOOK step 2).
set -eu
: "${TEMPORAL_BIN_DIR:=/opt/temporal/1.32.2}"
: "${TEMPORAL_DB_PASSWORD_FILE:=${CREDENTIALS_DIRECTORY:-/nonexistent}/temporal_db_password}"
: "${POSTGRES_SEEDS:?}" "${POSTGRES_USER:?}"
SQL_PASSWORD="$(cat "$TEMPORAL_DB_PASSWORD_FILE")"
export SQL_PASSWORD
set -- --plugin postgres12_pgx --endpoint "$POSTGRES_SEEDS" --port "${DB_PORT:-5432}" --user "$POSTGRES_USER"
if [ "${SQL_TLS_ENABLED:-true}" = "true" ]; then
  set -- "$@" --tls --tls-ca-file "${SQL_CA:?SQL_CA is required with TLS}"
  [ -n "${SQL_HOST_NAME:-}" ] && set -- "$@" --tls-server-name "$SQL_HOST_NAME"
  [ "${SQL_HOST_VERIFICATION:-true}" = "true" ] || set -- "$@" --tls-disable-host-verification
fi
for pair in "${DBNAME:-temporal}:postgresql/v12/temporal" "${VISIBILITY_DBNAME:-temporal_visibility}:postgresql/v12/visibility"; do
  db=${pair%%:*}; schema=${pair#*:}
  # setup-schema -v 0.0 only creates the version table; it is a no-op error on an existing schema.
  "$TEMPORAL_BIN_DIR/temporal-sql-tool" "$@" --database "$db" setup-schema -v 0.0 >/dev/null 2>&1 || true
  "$TEMPORAL_BIN_DIR/temporal-sql-tool" "$@" --database "$db" update-schema --schema-name "$schema"
done

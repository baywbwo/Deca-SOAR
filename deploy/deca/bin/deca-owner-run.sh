#!/bin/sh
# Run one deca-soar command as the database owner without keeping the owner DSN on the host (review N2).
#
#   <ops-vault get deca_db_url_owner> | sudo deploy/deca/bin/deca-owner-run.sh migrate
#   <ops-vault get deca_db_url_owner> | sudo deploy/deca/bin/deca-owner-run.sh create-principal \
#       --name temporal-worker --kind service --role analyst --token-file /out/worker.token
#
# The DSN is read from stdin (hidden prompt on a terminal), never from argv or a long-lived env. It is
# written to a 0400 file in a fresh tmpfs directory, mounted into exactly one `docker compose run --rm`
# of docker-compose.owner.yml, and the directory is removed when this script exits, fails or is
# interrupted. Afterwards no file on the host holds the owner DSN; rotate the password in the ops
# vault if the job was ever run any other way.
set -eu

usage() { echo "usage: <owner DSN on stdin> | $0 migrate|create-principal [args]" >&2; exit 64; }
[ $# -ge 1 ] || usage
case "$1" in migrate|create-principal) ;; *) usage ;; esac

REPO=${DECA_REPO:-$(cd "$(dirname "$0")/../../.." && pwd)}
ENV_FILE=${DECA_ENV_FILE:-/etc/deca-soar/deca.env}
SECRETS_DIR=${DECA_SECRETS_DIR:-/etc/deca-soar/secrets}
TMPBASE=${DECA_OWNER_TMPDIR:-/dev/shm}

if [ -e "$SECRETS_DIR/deca_db_url_owner" ]; then
  echo "$SECRETS_DIR/deca_db_url_owner exists: the owner DSN must not be stored on the host; shred it first" >&2
  exit 65
fi

umask 077
DIR=$(mktemp -d "$TMPBASE/deca-owner.XXXXXX")
trap 'rm -rf "$DIR"' EXIT
trap 'exit 130' HUP INT TERM

if [ -t 0 ]; then
  printf 'owner DSN (hidden): ' >&2
  stty -echo
  IFS= read -r DSN || DSN=
  stty echo
  printf '\n' >&2
else
  IFS= read -r DSN || [ -n "${DSN:-}" ] || DSN=
fi
case "$DSN" in
  postgres://*sslmode=verify-full*|postgresql://*sslmode=verify-full*) ;;
  *) echo "stdin must be the owner postgres URL with sslmode=verify-full" >&2; exit 65 ;;
esac
printf '%s\n' "$DSN" > "$DIR/deca_db_url_owner"
DSN=
if [ "$(id -u)" = 0 ]; then
  chown 10001 "$DIR/deca_db_url_owner"   # the image runs as uid 10001
  chmod 0711 "$DIR"
fi
chmod 0400 "$DIR/deca_db_url_owner"

DECA_OWNER_DSN_FILE="$DIR/deca_db_url_owner" \
  docker compose -f "$REPO/deploy/deca/docker-compose.owner.yml" --env-file "$ENV_FILE" \
  run --rm owner-job deca-soar "$@"

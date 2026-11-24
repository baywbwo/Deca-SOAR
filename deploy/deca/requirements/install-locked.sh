#!/bin/sh
# Hash-locked install of HyperSoar into a fresh venv (review N3). The Dockerfile runs exactly this,
# and so does the local check before a build, so what is tested is what ships.
#   install-locked.sh <python> <venv-dir> <source-dir> [--dev]
# Every third-party package comes from a *.lock file pinned with ==, verified by sha256
# (--require-hashes), installed from wheels only (no sdist builds that would fetch unpinned tools).
# The deca-soar wheel itself is built from <source-dir> with the hash-locked hatchling, offline.
set -eu
PY=$1 VENV=$2 SRC=$3 DEV=${4:-}
REQ=$SRC/deploy/deca/requirements
PIP="--no-cache-dir --disable-pip-version-check --require-hashes --no-deps --only-binary :all:"
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

"$PY" -m venv "$BUILD/env"
"$BUILD/env/bin/pip" install $PIP -r "$REQ/build.lock"
"$BUILD/env/bin/pip" wheel --no-cache-dir --disable-pip-version-check --no-build-isolation --no-deps --no-index \
    -w "$BUILD/wheel" "$SRC"

"$PY" -m venv "$VENV"
if [ "$DEV" = "--dev" ]; then LOCK=$REQ/dev.lock; else LOCK=$REQ/runtime.lock; fi
"$VENV/bin/pip" install $PIP -r "$LOCK"
"$VENV/bin/pip" install --no-cache-dir --disable-pip-version-check --no-deps --no-index "$BUILD"/wheel/hypersoar-*.whl
"$VENV/bin/pip" check

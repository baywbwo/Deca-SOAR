# Locked Python dependencies (review N3)

| File | Used for |
|---|---|
| `runtime.lock` | the image: every runtime package, `==` pinned, sha256 hashes |
| `build.lock` | hatchling, to build the deca-soar wheel without network-fetched build tools |
| `dev.lock` | `runtime.lock` + pytest, for the test venv |

`install-locked.sh` installs from these with `--require-hashes --no-deps --only-binary :all:`; the
Dockerfile calls it, and `scripts/preflight.py` fails if a lock is missing a hash, pins with anything
other than `==`, or no longer covers a dependency in `pyproject.toml`.

The pinned versions are the ones the test suite and the e2e run were last green on. To update:
change `pyproject.toml` if needed, then regenerate all three with uv (any machine with PyPI access):

```sh
C="--generate-hashes --python-version 3.12 --python-platform x86_64-manylinux_2_28 --no-header --no-annotate"
uv pip compile pyproject.toml $C -o deploy/deca/requirements/runtime.lock
uv pip compile pyproject.toml --extra dev -c deploy/deca/requirements/runtime.lock $C -o deploy/deca/requirements/dev.lock
echo hatchling | uv pip compile - $C -o deploy/deca/requirements/build.lock
```

then rebuild the test venv with `install-locked.sh <python3.12> .venv . --dev`, run pytest and the
e2e, and commit the locks together with the evidence of that run.

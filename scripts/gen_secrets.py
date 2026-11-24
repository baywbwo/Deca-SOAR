#!/usr/bin/env python3
"""Generate fresh DECA keys, one 0600 file each, into a directory outside the repository.
Values are never printed. Existing files are never overwritten.

  python scripts/gen_secrets.py /etc/deca-soar/secrets

DB URLs, the broker worker token (hypersoar create-principal) and TLS material are created separately
(see deploy/RUNBOOK.md).
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

ROOT = Path(__file__).resolve().parents[1]


def generate() -> dict[str, str]:
    vault = X25519PrivateKey.generate()
    return {
        # Gateway: HMAC tokenisation key + vault public key (seal only).
        "deca_tokenization_key": secrets.token_hex(32),
        "deca_vault_public_key": vault.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        # Broker only: opens vault entries to check targets.
        "deca_vault_private_key": vault.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
        # Gateway + worker: Temporal payload codec (AES-256-GCM). The Temporal server never sees it.
        "deca_temporal_payload_key": secrets.token_hex(32),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out = Path(sys.argv[1]).resolve()
    if out == ROOT.resolve() or ROOT.resolve() in out.parents:
        print("refusing to write secrets inside the repository", file=sys.stderr)
        return 2
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    values = generate()
    clash = [n for n in values if (out / n).exists()]
    if clash:
        print("refusing to overwrite existing: " + ", ".join(clash), file=sys.stderr)
        return 2
    for name, value in values.items():
        fd = os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value + "\n")
    print(f"wrote {len(values)} keys to {out} (mode 0600): " + ", ".join(values))
    return 0


if __name__ == "__main__":
    sys.exit(main())

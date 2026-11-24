#!/usr/bin/env python3
"""Generate fresh platform secrets into a new 0600 file outside the repository. Values are never printed.

  python scripts/gen_secrets.py /etc/deca-soar/secrets.env
The file holds only generated keys; append the RDS/Tair/OSS connection values by hand (see RUNBOOK).
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def generate() -> dict[str, str]:
    return {
        # Tracecat platform secrets (docs/self-hosting/security.mdx)
        "TRACECAT__DB_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        "TRACECAT__SERVICE_KEY": secrets.token_urlsafe(48),
        "TRACECAT__SIGNING_SECRET": secrets.token_urlsafe(48),
        "USER_AUTH_SECRET": secrets.token_urlsafe(48),
        "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING": json.dumps(
            {"current_key_id": "v1", "keys": {"v1": secrets.token_hex(32)}}, separators=(",", ":")
        ),
        # DECA gateway/broker
        "DECA_TOKENIZATION_KEY": secrets.token_hex(32),
        "DECA_VAULT_KEY": secrets.token_hex(32),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out = Path(sys.argv[1]).resolve()
    try:
        out.relative_to(ROOT.resolve())
        print("refusing to write secrets inside the repository", file=sys.stderr)
        return 2
    except ValueError:
        pass
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        for k, v in generate().items():
            f.write(f"{k}='{v}'\n")
    print(f"wrote {len(generate())} generated secrets to {out} (mode 0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""AES-256-GCM payload codec: workflow inputs, results and failure messages are encrypted before
they reach the Temporal server, so its database and UI only ever hold ciphertext.

Only the gateway (starts workflows) and the worker hold the key; the Temporal server does not.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from temporalio.api.common.v1 import Payload
from temporalio.converter import PayloadCodec

ENCODING = b"binary/encrypted"
KEY_ID_META = "encryption-key-id"


class CodecError(ValueError):
    pass


class AesGcmCodec(PayloadCodec):
    def __init__(self, key: bytes, key_id: str = "k1", old_keys: dict[str, bytes] | None = None) -> None:
        if len(key) != 32:
            raise CodecError("payload key must be 32 bytes")
        self.key_id = key_id
        self._keys = {**(old_keys or {}), key_id: key}

    async def encode(self, payloads: Sequence[Payload]) -> list[Payload]:
        aead = AESGCM(self._keys[self.key_id])
        out = []
        for p in payloads:
            nonce = os.urandom(12)
            ct = aead.encrypt(nonce, p.SerializeToString(), self.key_id.encode())
            out.append(Payload(metadata={"encoding": ENCODING, KEY_ID_META: self.key_id.encode()}, data=nonce + ct))
        return out

    async def decode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out = []
        for p in payloads:
            if p.metadata.get("encoding") != ENCODING:
                out.append(p)  # e.g. server-generated payloads
                continue
            kid = p.metadata.get(KEY_ID_META, b"").decode()
            key = self._keys.get(kid)
            if key is None:
                raise CodecError(f"unknown payload key id {kid[:16]!r}")
            plain = AESGCM(key).decrypt(p.data[:12], p.data[12:], kid.encode())
            out.append(Payload.FromString(plain))
        return out

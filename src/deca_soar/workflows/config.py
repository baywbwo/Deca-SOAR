"""Temporal connection settings shared by the gateway (starter) and the worker.

  DECA_TEMPORAL_ADDRESS            host:port of the frontend (internal network only)
  DECA_TEMPORAL_NAMESPACE          default deca-soar
  DECA_TEMPORAL_TASK_QUEUE         default deca-soar-alerts
  DECA_TEMPORAL_TLS_CA_FILE        CA that signed the frontend cert         } required with
  DECA_TEMPORAL_TLS_CERT_FILE      this client's cert (mTLS)                } DECA_ENV=production
  DECA_TEMPORAL_TLS_KEY_FILE       this client's private key                }
  DECA_TEMPORAL_TLS_SERVER_NAME    expected name in the frontend cert (optional)
  DECA_TEMPORAL_PAYLOAD_KEY(_FILE) 32-byte AES key for the payload codec (always required)
  DECA_TEMPORAL_PAYLOAD_KEY_ID     default k1
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass
from pathlib import Path

from temporalio.client import Client
from temporalio.converter import DataConverter, DefaultFailureConverterWithEncodedAttributes, default
from temporalio.service import TLSConfig

from deca_soar.common.config import ConfigError, read_key32
from deca_soar.workflows import TASK_QUEUE
from deca_soar.workflows.codec import AesGcmCodec

TLS_FILES = ("DECA_TEMPORAL_TLS_CA_FILE", "DECA_TEMPORAL_TLS_CERT_FILE", "DECA_TEMPORAL_TLS_KEY_FILE")


@dataclass(frozen=True)
class TemporalSettings:
    address: str
    namespace: str
    task_queue: str
    payload_key: bytes
    payload_key_id: str = "k1"
    tls: TLSConfig | None = None

    @classmethod
    def from_env(cls) -> "TemporalSettings":
        address = os.environ.get("DECA_TEMPORAL_ADDRESS", "").strip()
        if not address:
            raise ConfigError("DECA_TEMPORAL_ADDRESS is required")
        given = [n for n in TLS_FILES if os.environ.get(n)]
        if given and len(given) != len(TLS_FILES):
            raise ConfigError("Temporal mTLS needs all of " + ", ".join(TLS_FILES))
        if not given and os.environ.get("DECA_ENV") == "production":
            raise ConfigError("production requires mTLS to Temporal (" + ", ".join(TLS_FILES) + ")")
        tls = None
        if given:
            try:
                ca, cert, key = (Path(os.environ[n]).read_bytes() for n in TLS_FILES)
            except OSError as e:
                raise ConfigError("a Temporal TLS file could not be read") from e
            tls = TLSConfig(
                server_root_ca_cert=ca,
                client_cert=cert,
                client_private_key=key,
                domain=os.environ.get("DECA_TEMPORAL_TLS_SERVER_NAME") or None,
            )
        return cls(
            address=address,
            namespace=os.environ.get("DECA_TEMPORAL_NAMESPACE", "deca-soar"),
            task_queue=os.environ.get("DECA_TEMPORAL_TASK_QUEUE", TASK_QUEUE),
            payload_key=read_key32("DECA_TEMPORAL_PAYLOAD_KEY"),
            payload_key_id=os.environ.get("DECA_TEMPORAL_PAYLOAD_KEY_ID", "k1"),
            tls=tls,
        )

    def data_converter(self) -> DataConverter:
        return data_converter(self.payload_key, self.payload_key_id)

    async def connect(self, *, identity: str) -> Client:
        return await Client.connect(
            self.address,
            namespace=self.namespace,
            tls=self.tls or False,
            data_converter=self.data_converter(),
            identity=identity,
        )


def data_converter(key: bytes, key_id: str = "k1") -> DataConverter:
    # Encoded failure attributes: exception messages and stack traces go through the codec too.
    return dataclasses.replace(
        default(),
        payload_codec=AesGcmCodec(key, key_id),
        failure_converter_class=DefaultFailureConverterWithEncodedAttributes,
    )

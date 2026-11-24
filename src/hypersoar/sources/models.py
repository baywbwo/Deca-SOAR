"""Settings of the data-source connectors. Non-secret fields only; secrets live in secretbox."""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Source types an alert can carry (gateway.inbox_event.source). "siem" is any third-party SIEM.
SOURCE_TYPES = ("waf", "actiontrail", "sas", "internal", "siem")
SEVERITIES = ("info", "low", "medium", "high", "critical")
PATH = r"^[A-Za-z0-9_@.-]{1,64}$"
HTTPS = r"^https://[A-Za-z0-9.-]+(:[0-9]{2,5})?$"


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FieldMap(_M):
    """Where each alert field is found in an incoming record (a dotted path for nested JSON)."""
    rule_id: str = Field(default="rule_id", pattern=PATH)
    severity: str | None = Field(default="severity", pattern=PATH)
    detected_at: str | None = Field(default="detected_at", pattern=PATH)
    src_ip: str | None = Field(default="src_ip", pattern=PATH)
    principal: str | None = Field(default=None, pattern=PATH)
    access_key_id: str | None = Field(default=None, pattern=PATH)
    dst_asset: str | None = Field(default=None, pattern=PATH)
    uri: str | None = Field(default=None, pattern=PATH)
    ua: str | None = Field(default=None, pattern=PATH)
    events: str | None = Field(default=None, pattern=PATH)


class SourceSettings(_M):
    source_type: Literal["waf", "actiontrail", "sas", "internal", "siem"] = "siem"
    # Prepended to the record's rule id ("wazuh." + "5710"), so ids from different tools never collide.
    rule_prefix: str = Field(default="", pattern=r"^([a-z0-9_]{1,24}\.)?$")
    fields: FieldMap = FieldMap()
    # The record's severity value (lower-cased) -> HyperSoar severity. Numbers 0-10 map by default.
    severity_map: dict[str, Literal["info", "low", "medium", "high", "critical"]] = Field(default_factory=dict,
                                                                                         max_length=32)

    @field_validator("severity_map")
    @classmethod
    def _keys(cls, v: dict) -> dict:
        if any(not (0 < len(k) <= 32) for k in v):
            raise ValueError("severity_map keys must be 1 to 32 characters")
        return {k.lower(): s for k, s in v.items()}


class WebhookSettings(SourceSettings):
    max_body_kb: int = Field(default=256, ge=1, le=1024)
    max_skew_s: Literal[60, 300, 600] = 300


class SyslogSettings(SourceSettings):
    format: Literal["cef"] = "cef"
    # Syslog has no sender authentication: only these networks are accepted.
    allowed_senders: tuple[str, ...] = Field(min_length=1, max_length=32)
    fields: FieldMap = FieldMap(rule_id="signature_id", severity="severity", detected_at="rt", src_ip="src",
                                principal="suser", dst_asset="dhost", uri="request", ua="requestClientApplication",
                                events="cnt")

    @field_validator("allowed_senders")
    @classmethod
    def _cidrs(cls, v: tuple) -> tuple:
        out = []
        for c in v:
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError:
                raise ValueError(f"{c[:45]!r} is not an IP network") from None
            if net.prefixlen == 0:
                raise ValueError("allowed_senders may not be the whole internet")
            out.append(str(net))
        return tuple(out)


class SlsSettings(SourceSettings):
    # Region endpoint, e.g. https://ap-southeast-5.log.aliyuncs.com (the project becomes a subdomain).
    endpoint: str = Field(pattern=r"^https://[a-z0-9-]+(-intranet)?\.log\.aliyuncs\.com$")
    project: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
    logstore: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$")
    query: str = Field(default="*", min_length=1, max_length=1000)
    # Pull complete windows only: logs are read up to lag_s seconds ago, window_s seconds at a time.
    window_s: int = Field(default=60, ge=10, le=3600)
    lag_s: int = Field(default=60, ge=10, le=900)
    page: int = Field(default=500, ge=10, le=1000)

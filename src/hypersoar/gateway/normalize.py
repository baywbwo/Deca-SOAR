"""Normalise a raw detection result into the HyperSoar alert schema (design 7.1), tokenising PII."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from hypersoar.common import geo as geo_mod
from hypersoar.common.pii import Tokenizer, mask_access_key, tokens_in
from hypersoar.gateway import detections as detections_mod
from hypersoar.gateway.detections import Detection

SEVERITIES = ("info", "low", "medium", "high", "critical")
SOURCES = ("waf", "actiontrail", "sas", "internal", "siem")
URI_MAX = 512
UA_MAX = 256
DEFAULT_WINDOW_S = 300
TRUTHS = ("benign", "malicious")


class NormalizeError(ValueError):
    pass


@dataclass
class NormalizedAlert:
    alert_id: str
    fingerprint: str
    source: str
    rule_id: str
    severity_hint: str
    detected_at: datetime
    event_count: int
    alert: dict
    evidence_tokens: list[str]
    found: dict[str, tuple[str, str]]


def _parse_ts(value) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC)
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    raise NormalizeError("detected_at missing or invalid")


def _clip(s: str | None, n: int) -> str | None:
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n]


def _path(det: Detection, ends: dict[str, str | None]) -> dict | None:
    src, dst = ends.get(det.path_from), ends.get(det.path_to)
    if not src or not dst or (det.path_from, src) == (det.path_to, dst):
        return None
    return {"from": {"kind": det.path_from, "value": src}, "rel": det.rel, "to": {"kind": det.path_to, "value": dst}}


def normalize(raw: dict, tok: Tokenizer, *, source_name: str, detections: dict[str, Detection] | None = None,
              geo: tuple | None = None, keep_truth: bool = False) -> NormalizedAlert:
    source = raw.get("source")
    if source not in SOURCES:
        raise NormalizeError("unknown source")
    rule_id = str(raw.get("rule_id") or "").strip()
    if not rule_id or len(rule_id) > 64:
        raise NormalizeError("rule_id missing or too long")
    severity = raw.get("severity_hint", "medium")
    if severity not in SEVERITIES:
        raise NormalizeError("invalid severity_hint")
    detected_at = _parse_ts(raw.get("detected_at"))
    window_s = int(raw.get("window_s") or DEFAULT_WINDOW_S)
    events = max(1, int(raw.get("events") or 1))

    # Origin comes from the raw address before it is tokenised; only city/ASN/map position is kept.
    origin = geo_mod.lookup(str(raw["src_ip"]), geo) if raw.get("src_ip") else None
    src_ip = tok.token_ip(raw["src_ip"]) if raw.get("src_ip") else None
    principal = tok.token("user", str(raw["principal"])) if raw.get("principal") else None
    ak_token = tok.token("ak", str(raw["access_key_id"])) if raw.get("access_key_id") else None
    # Untrusted, attacker-controlled fields: clip first (bounded work), scrub PII, clip again.
    uri = _clip(tok.scrub(_clip(raw.get("uri"), URI_MAX * 2) or ""), URI_MAX) if raw.get("uri") else None
    ua = _clip(tok.scrub(_clip(raw.get("ua"), UA_MAX * 2) or ""), UA_MAX) if raw.get("ua") else None

    primary = src_ip or principal or ""
    bucket = int(detected_at.timestamp()) // window_s
    fingerprint = hashlib.sha256(f"{rule_id}|{primary}|{bucket}".encode()).hexdigest()

    det = (detections_mod.load() if detections is None else detections).get(rule_id)
    if det is not None and det.source != source:
        det = None
    dst_asset = _clip(raw.get("dst_asset"), 128)
    ak_masked = mask_access_key(raw.get("access_key_id"))
    if det is not None:
        # Category, MITRE mapping and path come from the reviewed catalog, never from the raw alert.
        attack = det.mitre()
        mitre = [det.technique]
        path = _path(det, {"ip": src_ip, "user": principal, "ak": ak_token, "asset": dst_asset})
        enrich = {"category": det.category, "title": det.title, "outcome": det.outcome,
                  "step_title": det.step_title(events=events, asset=dst_asset, ak=ak_masked)}
    else:
        attack, path, mitre = None, None, [str(t)[:16] for t in raw.get("mitre", [])][:10]
        enrich = {"category": "Uncatalogued", "title": f"Uncatalogued rule {rule_id}", "outcome": "attempted",
                  "step_title": f"Rule {rule_id} fired"}

    alert = {
        "alert_id": str(uuid.uuid4()),
        "fingerprint": fingerprint,
        "source": source,
        "rule_id": rule_id,
        "detected_at": detected_at.isoformat(),
        "severity_hint": severity,
        "mitre": mitre,
        "attack": attack,
        "path": path,
        "origin": origin.public() if origin else None,
        **enrich,
        "entities": {
            "src_ip": src_ip,
            "dst_asset": dst_asset,
            "principal": principal,
            "access_key_id": ak_masked,
            "access_key_token": ak_token,
        },
        "counts": {"events": events, "window_s": window_s},
        "raw_ref": _clip(raw.get("raw_ref"), 512) or f"replay://{source_name}",
        "untrusted_fields": {"uri": uri, "ua": ua},
    }
    # Synthetic ground truth feeds the promotion progress in sandbox; a production gateway drops it.
    truth = raw.get("truth")
    if keep_truth and truth in TRUTHS and alert["raw_ref"].startswith("synthetic://"):
        alert["synthetic_truth"] = truth
    # Targets may only come from structured source fields. Tokens inside the URI/UA are attacker
    # text and stay context only, so "/login?next=8.8.8.8" cannot make 8.8.8.8 blockable (review F1).
    evidence = tokens_in([src_ip or "", principal or "", ak_token or ""])
    return NormalizedAlert(
        alert_id=alert["alert_id"],
        fingerprint=fingerprint,
        source=source,
        rule_id=rule_id,
        severity_hint=severity,
        detected_at=detected_at,
        event_count=events,
        alert=alert,
        evidence_tokens=evidence,
        found=dict(tok.found),
    )

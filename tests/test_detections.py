"""Detections as code (G3): every file in detections/ is valid and its fixtures produce what it says.
This runs in CI without a database."""

from pathlib import Path

import pytest
import yaml

from hypersoar.common import geo
from hypersoar.common.config import ConfigError
from hypersoar.common.pii import Tokenizer
from hypersoar.gateway import detections
from hypersoar.gateway.normalize import normalize

ROOT = Path(__file__).resolve().parents[1]
CATALOG = detections.load_dir(ROOT / "detections")
GEO = geo.parse(yaml.safe_load((ROOT / "geo" / "origins.yaml").read_text()))


def test_catalog_loads_and_ids_are_unique():
    assert len(CATALOG) >= 10
    files = sorted(p.stem for p in (ROOT / "detections").glob("*.yaml"))
    assert files == sorted(CATALOG)


@pytest.mark.parametrize("det", CATALOG.values(), ids=lambda d: d.id)
def test_fixtures_normalise_to_the_catalog_mapping(det):
    for case in det.tests:
        raw = {"detected_at": "2026-11-24T03:00:00Z", **case["raw"]}
        na = normalize(raw, Tokenizer(b"\x01" * 32), source_name="ci", detections=CATALOG, geo=GEO)
        got = {"category": na.alert["category"], "tactic": na.alert["attack"]["tactic"],
               "technique": na.alert["attack"]["technique"], "outcome": na.alert["outcome"],
               "step": na.alert["step_title"]}
        for k, v in case["expect"].items():
            assert got[k] == v, (det.id, k)
        assert na.alert["mitre"] == [det.technique]
        assert na.alert["path"] is not None, f"{det.id}: fixture does not fill the path {det.path_from}->{det.path_to}"


def test_raw_alert_cannot_override_the_mapping():
    raw = {"source": "waf", "rule_id": "waf.sqli.burst", "detected_at": "2026-11-24T03:00:00Z",
           "src_ip": "203.0.113.20", "mitre": ["T1486"], "category": "Benign", "attack": {"tactic": "x"}}
    a = normalize(raw, Tokenizer(b"\x01" * 32), source_name="ci", detections=CATALOG, geo=GEO).alert
    assert a["mitre"] == ["T1190"] and a["category"] == "SQL injection" and a["attack"]["tactic"] == "TA0001"


def test_rule_from_another_source_is_not_mapped():
    raw = {"source": "sas", "rule_id": "waf.sqli.burst", "detected_at": "2026-11-24T03:00:00Z", "src_ip": "203.0.113.2"}
    a = normalize(raw, Tokenizer(b"\x01" * 32), source_name="ci", detections=CATALOG, geo=GEO).alert
    assert a["category"] == "Uncatalogued" and a["attack"] is None


@pytest.mark.parametrize("patch,msg", [
    ({"mitre": {"tactic": "TA9999", "tactic_name": "x", "technique": "T1190", "technique_name": "y"}}, "mitre.tactic"),
    ({"mitre": {"tactic": "TA0001", "tactic_name": "Initial access", "technique": "1190", "technique_name": "y"}},
     "technique"),
    ({"mitre": {"tactic": "TA0001", "tactic_name": "Execution", "technique": "T1190", "technique_name": "y"}},
     "tactic_name"),
    ({"step": "{events} by {uri}"}, "step may only use"),
    ({"path": {"from": "asset", "rel": "targets", "to": "ip"}}, "actor"),
    ({"source": "sas"}, "start with its source"),
    ({"tests": []}, "fixture"),
    ({"extra": 1}, "unknown keys"),
])
def test_invalid_detection_is_rejected(patch, msg):
    doc = yaml.safe_load((ROOT / "detections" / "waf.sqli.burst.yaml").read_text())
    doc.update(patch)
    with pytest.raises(ConfigError, match=msg):
        detections.parse(doc, "waf.sqli.burst.yaml")


def test_geo_origin_without_the_address():
    raw = {"source": "waf", "rule_id": "waf.sqli.burst", "detected_at": "2026-11-24T03:00:00Z", "src_ip": "203.0.113.5"}
    a = normalize(raw, Tokenizer(b"\x01" * 32), source_name="ci", detections=CATALOG, geo=GEO).alert
    assert a["origin"] == {"city": "Amsterdam", "country": "NL", "asn": "AS208294", "as_name": "Tor exit",
                           "tor": True, "xy": [579.6, 91.7]}
    assert "203.0.113" not in str(a)
    raw["src_ip"] = "192.0.2.10"
    assert normalize(raw, Tokenizer(b"\x01" * 32), source_name="ci", detections=CATALOG, geo=GEO).alert["origin"] is None


def test_geo_table_rejects_overlap_and_off_map():
    with pytest.raises(ConfigError, match="overlaps"):
        geo.parse({"version": 1, "origins": [
            {"cidr": "203.0.113.0/28", "city": "a", "country": "x", "asn": "1", "as_name": "a", "xy": [1, 1]},
            {"cidr": "203.0.113.0/27", "city": "b", "country": "x", "asn": "1", "as_name": "a", "xy": [1, 1]}]})
    with pytest.raises(ConfigError, match="outside"):
        geo.parse({"version": 1, "origins": [
            {"cidr": "203.0.113.0/28", "city": "a", "country": "x", "asn": "1", "as_name": "a", "xy": [5000, 1]}]})


def test_synthetic_truth_kept_only_when_asked_and_synthetic():
    raw = {"source": "waf", "rule_id": "waf.sqli.burst", "detected_at": "2026-11-24T03:00:00Z",
           "src_ip": "203.0.113.5", "truth": "malicious", "raw_ref": "synthetic://lab"}
    tok = Tokenizer(b"\x01" * 32)
    assert normalize(raw, tok, source_name="ci", detections=CATALOG, geo=GEO, keep_truth=True).alert[
        "synthetic_truth"] == "malicious"
    assert "synthetic_truth" not in normalize(raw, tok, source_name="ci", detections=CATALOG, geo=GEO).alert
    raw["raw_ref"] = "sls://prod"
    assert "synthetic_truth" not in normalize(raw, tok, source_name="ci", detections=CATALOG, geo=GEO,
                                              keep_truth=True).alert

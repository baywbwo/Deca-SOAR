"""Lab overlay (deploy/lab): nothing published on the host, images pinned, console isolated."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
LAB = REPO / "deploy/lab"


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_constructor("!reset", lambda loader, node: {"__reset__": loader.construct_sequence(node)}
                        if isinstance(node, yaml.SequenceNode) else {"__reset__": None})


def _lab() -> dict:
    return yaml.load((LAB / "docker-compose.lab.yml").read_text(), Loader=_Loader)


def test_lab_publishes_no_host_port():
    svcs = _lab()["services"]
    assert svcs["broker"]["ports"] == {"__reset__": []}
    assert all("ports" not in s for n, s in svcs.items() if n != "broker")


def test_lab_images_pinned_by_digest():
    svcs = _lab()["services"]
    for name in ("postgres", "tunnel"):
        assert re.search(r"@sha256:[0-9a-f]{64}$", svcs[name]["image"]), name
    assert re.search(r"^FROM \S+@sha256:[0-9a-f]{64}$", (LAB / "temporal.Dockerfile").read_text(), re.M)


def test_temporal_dockerfile_checks_release_hashes():
    source = (REPO / "deploy/temporal/SOURCE.txt").read_text()
    df = (LAB / "temporal.Dockerfile").read_text()
    for digest in re.findall(r"^([0-9a-f]{64})\s", source, re.M):
        assert digest in df
    assert "sha256sum -c" in df


def test_console_is_read_only_and_only_tunnel_is_trusted():
    svcs = _lab()["services"]
    con, tun = svcs["console"], svcs["tunnel"]
    assert set(con["secrets"]) == {"deca_db_url_console", "deca_db_ca", "console_password_hash",
                                   "console_tls_cert", "console_tls_key"}
    tunnel_ip = tun["networks"]["deca"]["ipv4_address"]
    assert con["environment"]["HYPERSOAR_CONSOLE_TRUSTED_PROXIES"] == f"{tunnel_ip}/32"
    assert con["environment"]["HYPERSOAR_CONSOLE_SYNTHETIC"] == "1"
    assert "--no-proxy-headers" in con["command"]
    assert tun["command"][tun["command"].index("--url") + 1] == "https://console:8300"
    assert "--origin-ca-pool" in tun["command"]


def test_owner_override_adds_only_network_and_db_ca():
    doc = yaml.safe_load((LAB / "docker-compose.owner.lab.yml").read_text())
    job = doc["services"]["owner-job"]
    assert set(job) == {"environment", "secrets", "networks"} and job["secrets"] == ["deca_db_ca"]
    assert job["environment"] == {"HYPERSOAR_ENV": "lab", "HYPERSOAR_MODE": "sandbox"}
    runner = (REPO / "deploy/deca/bin/deca-owner-run.sh").read_text()
    assert '${OVERRIDE:+-f "$OVERRIDE"}' in runner



def test_lab_is_a_sandbox_install_and_keeps_the_service_controls():
    svcs = _lab()["services"]
    for name in ("broker", "gateway", "synth", "scenario"):
        assert svcs[name]["environment"]["HYPERSOAR_MODE"] == "sandbox", name
    # The gateway leaves HYPERSOAR_ENV=production only because that refuses sandbox mode; it does not
    # drop the base file's Temporal mTLS or payload key.
    assert set(svcs["gateway"]) == {"environment", "secrets", "depends_on"}
    assert set(svcs["gateway"]["environment"]) == {"HYPERSOAR_ENV", "HYPERSOAR_MODE"}
    assert "--interval" in svcs["synth"]["command"] and "120" in svcs["synth"]["command"][-1]


def test_scenario_runner_is_a_tool_with_the_broker_login_only():
    sc = _lab()["services"]["scenario"]
    assert sc["profiles"] == ["tools"] and sc["restart"] == "no" and "ports" not in sc
    assert sc["read_only"] is True and sc["cap_drop"] == ["ALL"]
    assert set(sc["secrets"]) == {"deca_db_url_broker", "deca_db_ca"}
    assert sc["environment"]["HYPERSOAR_DB_URL_FILE"] == "/run/secrets/deca_db_url_broker"
    assert sc["entrypoint"][:3] == ["hypersoar", "scenario", "run"]

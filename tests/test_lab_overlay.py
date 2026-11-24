"""Lab overlays (deploy/lab): nothing published on the host, images pinned, console isolated, and the sandbox
and production stacks kept apart (no seeding bot, replay file or scenario runner in production)."""

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


def _lab(name: str = "lab") -> dict:
    return yaml.load((LAB / f"docker-compose.{name}.yml").read_text(), Loader=_Loader)


def _base() -> dict:
    return yaml.safe_load((REPO / "deploy/deca/docker-compose.yml").read_text())


def test_lab_publishes_no_host_port():
    svcs = _lab()["services"]
    assert svcs["broker"]["ports"] == {"__reset__": []}
    assert all("ports" not in s for n, s in svcs.items() if n != "broker")
    for name in ("sandbox", "production"):
        assert all("ports" not in s for s in _lab(name)["services"].values()), name


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


def test_console_writes_through_the_broker_and_only_tunnel_is_trusted():
    svcs = _lab()["services"]
    con, tun = svcs["console"], svcs["tunnel"]
    assert set(con["secrets"]) == {"deca_db_url_console", "deca_db_ca", "console_password_hash",
                                   "console_tls_cert", "console_tls_key", "deca_broker_console_token",
                                   "broker_tls_ca"}
    env = con["environment"]
    assert env["HYPERSOAR_BROKER_URL"].startswith("https://") and env["HYPERSOAR_BROKER_CA_FILE"]
    tunnel_ip = tun["networks"]["deca"]["ipv4_address"]
    assert env["HYPERSOAR_CONSOLE_TRUSTED_PROXIES"] == f"{tunnel_ip}/32"
    assert "HYPERSOAR_CONSOLE_SYNTHETIC" not in env
    assert _lab("sandbox")["services"]["console"]["environment"]["HYPERSOAR_CONSOLE_SYNTHETIC"] == "1"
    assert _lab("production")["services"]["console"]["environment"]["HYPERSOAR_CONSOLE_SYNTHETIC"] == "0"
    assert "--no-proxy-headers" in con["command"]
    assert tun["command"][tun["command"].index("--url") + 1] == "https://console:8300"
    assert "--origin-ca-pool" in tun["command"]


def test_each_stack_has_its_own_network_and_secret_directory():
    lab, base = _lab(), _base()
    for doc in (lab, base, yaml.safe_load((LAB / "docker-compose.owner.lab.yml").read_text())):
        assert all(v["file"].startswith("${HYPERSOAR_ETC:-/etc/deca-soar}/") for v in doc["secrets"].values())
    assert lab["services"]["temporal"]["volumes"][0].startswith("${HYPERSOAR_ETC:-/etc/deca-soar}/lab/")
    assert lab["networks"]["deca"]["ipam"]["config"] == [{"subnet": "${HYPERSOAR_LAB_NET:-172.30.124}.0/24"}]
    for name, svc in lab["services"].items():
        for net in svc.get("networks", {}).values() if isinstance(svc.get("networks"), dict) else []:
            assert net["ipv4_address"].startswith("${HYPERSOAR_LAB_NET:-172.30.124}."), name


def test_owner_override_adds_only_network_and_db_ca():
    doc = yaml.safe_load((LAB / "docker-compose.owner.lab.yml").read_text())
    job = doc["services"]["owner-job"]
    assert set(job) == {"environment", "secrets", "networks"} and job["secrets"] == ["deca_db_ca"]
    assert job["environment"] == {"HYPERSOAR_ENV": "lab", "HYPERSOAR_MODE": "${HYPERSOAR_LAB_MODE:?sandbox or production}"}
    runner = (REPO / "deploy/deca/bin/deca-owner-run.sh").read_text()
    assert '${OVERRIDE:+-f "$OVERRIDE"}' in runner


def test_shared_lab_file_has_no_mode_and_no_sandbox_tools():
    svcs = _lab()["services"]
    assert not {"synth", "scenario"} & set(svcs)
    assert all("HYPERSOAR_MODE" not in s.get("environment", {}) for s in svcs.values())
    # The gateway keeps the base file's Temporal mTLS and payload key settings.
    assert set(svcs["gateway"]) == {"environment", "secrets", "depends_on"}
    assert set(svcs["gateway"]["environment"]) == {"HYPERSOAR_ENV"}


def test_base_gateway_reads_configured_sources_only():
    gw = _base()["services"]["gateway"]
    assert gw["environment"]["HYPERSOAR_GATEWAY_SOURCE"] == "connectors"
    assert "HYPERSOAR_REPLAY_FILE" not in gw["environment"] and "volumes" not in gw
    assert "deca_integration_key" in gw["secrets"]


def test_sandbox_stack_has_the_dev_tools():
    svcs = _lab("sandbox")["services"]
    for name in ("broker", "gateway", "scenario"):
        assert svcs[name]["environment"]["HYPERSOAR_MODE"] == "sandbox", name
    assert svcs["synth"]["environment"]["HYPERSOAR_MODE"] == "sandbox"
    assert svcs["gateway"]["environment"]["HYPERSOAR_GATEWAY_SOURCE"] == "replay"
    assert svcs["broker"]["environment"]["HYPERSOAR_INTEGRATION_WRITES"] == "1"
    assert svcs["broker"]["environment"]["HYPERSOAR_ALLOW_TEST_NETS"] == "1"
    assert "--interval" in svcs["synth"]["command"] and "120" in svcs["synth"]["command"][-1]
    for s in svcs.values():
        assert s.get("read_only", True) is True and s.get("cap_drop", ["ALL"]) == ["ALL"]


def test_production_stack_has_no_synthetic_parts():
    doc = _lab("production")
    svcs = doc["services"]
    assert set(svcs) == {"broker", "gateway", "console"}
    for name in ("broker", "gateway"):
        env = svcs[name]["environment"]
        assert env["HYPERSOAR_MODE"] == "production", name
        assert not {"HYPERSOAR_ALLOW_TEST_NETS", "HYPERSOAR_INTEGRATION_WRITES", "HYPERSOAR_GATEWAY_SOURCE",
                    "HYPERSOAR_REPLAY_FILE"} & set(env), name
    text = (LAB / "docker-compose.production.yml").read_text()
    assert "synth" not in text.replace("synthetic", "") and "replay:" not in text


def test_scenario_runner_is_a_tool_with_the_broker_login_only():
    sc = _lab("sandbox")["services"]["scenario"]
    assert sc["profiles"] == ["tools"] and sc["restart"] == "no" and "ports" not in sc
    assert sc["read_only"] is True and sc["cap_drop"] == ["ALL"]
    assert set(sc["secrets"]) == {"deca_db_url_broker", "deca_db_ca"}
    assert sc["environment"]["HYPERSOAR_DB_URL_FILE"] == "/run/secrets/deca_db_url_broker"
    assert sc["entrypoint"][:3] == ["hypersoar", "scenario", "run"]

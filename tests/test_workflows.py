"""Temporal workflow tests. Integration tests need DECA_TEST_TEMPORAL_BIN (the `temporal` CLI): a private
dev server is started on loopback. Nothing here talks to a real broker; the e2e run covers that."""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import time
import uuid

import httpx
import pytest
from temporalio import activity
from temporalio.api.common.v1 import Payload
from temporalio.client import Client, WorkflowExecutionStatus, WorkflowFailureError
from temporalio.converter import DataConverter
from temporalio.exceptions import ActivityError, ApplicationError
from temporalio.worker import Worker

from deca_soar.common.config import ConfigError
from deca_soar.gateway.starter import TemporalStarter
from deca_soar.workflows import WORKFLOW_NAME, workflow_id
from deca_soar.workflows.activities import BrokerSubmitter, triage_mock
from deca_soar.workflows.codec import AesGcmCodec, CodecError
from deca_soar.workflows.config import TemporalSettings, data_converter
from deca_soar.workflows.shadow import AlertShadowWorkflow, build_request
from deca_soar.workflows.worker import check_env

KEY = b"\x07" * 32
NS = "deca-soar"
TOKEN = "tok_ip_0123456789abcdef"


def _alert(**kw) -> dict:
    a = {
        "alert_id": str(uuid.uuid4()),
        "source": "waf",
        "rule_id": "waf.sqli.burst",
        "severity_hint": "high",
        "entities": {"src_ip": TOKEN},
        "counts": {"events": 40, "window_s": 300},
    }
    a.update(kw)
    return a


# --- pure units -------------------------------------------------------------------------------


def test_codec_round_trip_and_ciphertext():
    codec = AesGcmCodec(KEY, "k1")
    plain = [Payload(metadata={"encoding": b"json/plain"}, data=f'{{"src_ip":"{TOKEN}"}}'.encode())]
    enc = asyncio.run(codec.encode(plain))
    assert enc[0].metadata["encoding"] == b"binary/encrypted"
    assert TOKEN.encode() not in enc[0].SerializeToString()
    assert asyncio.run(codec.decode(enc)) == plain
    # Server-generated (unencrypted) payloads pass through; an unknown key id fails loudly.
    assert asyncio.run(codec.decode(plain)) == plain
    with pytest.raises(CodecError):
        asyncio.run(AesGcmCodec(KEY, "k2").decode(enc))
    # Rotation: the new key decrypts nothing old unless the old key is kept for decoding.
    rotated = AesGcmCodec(b"\x08" * 32, "k2", old_keys={"k1": KEY})
    assert asyncio.run(rotated.decode(enc)) == plain


def test_triage_mock_and_request_shape():
    d = asyncio.run(triage_mock(_alert()))
    assert (d["verdict"], d["source"], d["model"]) == ("malicious", "rule", "mock-phase0")
    assert "LLM not tested" in d["rationale_summary"] and d["evidence_refs"] == [TOKEN]
    assert asyncio.run(triage_mock(_alert(severity_hint="low")))["verdict"] == "suspicious"
    a = _alert()
    req = build_request(a, d)
    assert req["params"] == {"ip_token": TOKEN, "waf_instance": "waf-jkt-01"}
    assert req["idempotency_key"] == f"wf-{a['alert_id']}"
    assert build_request(_alert(source="actiontrail"), d) is None
    assert build_request(_alert(entities={"src_ip": None}), d) is None


def _submitter(handler) -> BrokerSubmitter:
    return BrokerSubmitter("http://broker.invalid:8100", "svc-secret-token", transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    "status,retryable",
    [(500, True), (502, True), (503, True), (408, True), (429, True), (400, False), (401, False),
     (403, False), (404, False), (409, False), (413, False), (422, False)],
)
def test_broker_submit_error_classes(status, retryable):
    s = _submitter(lambda req: httpx.Response(status, json={"detail": "nope"}))
    with pytest.raises(ApplicationError) as ei:
        asyncio.run(s.submit({"alert_id": "x"}))
    assert ei.value.non_retryable is (not retryable)
    assert ei.value.type == ("BrokerUnavailable" if retryable else "BrokerRejected")
    assert "svc-secret-token" not in str(ei.value) and "broker.invalid" not in str(ei.value)


def test_broker_submit_success_and_unreachable():
    seen = []

    def ok(req: httpx.Request):
        seen.append(req)
        return httpx.Response(201, json={"request_id": "r1", "status": "validated", "reasons": [], "x": 1})

    out = asyncio.run(_submitter(ok).submit({"alert_id": "a"}))
    assert out == {"request_id": "r1", "status": "validated", "reasons": [], "idempotent_replay": False}
    assert seen[0].headers["authorization"] == "Bearer svc-secret-token"
    assert seen[0].url.path == "/v1/actions/requests"

    def down(req):
        raise httpx.ConnectError("connection refused to broker.invalid")

    with pytest.raises(ApplicationError) as ei:
        asyncio.run(_submitter(down).submit({}))
    assert not ei.value.non_retryable and "broker.invalid" not in str(ei.value)


def test_worker_refuses_db_and_vault_credentials(monkeypatch):
    for name in ("DECA_DB_URL", "DECA_VAULT_PRIVATE_KEY", "DECA_TOKENIZATION_KEY"):
        monkeypatch.setenv(name, "x")
        with pytest.raises(ConfigError):
            check_env()
        monkeypatch.delenv(name)
    check_env()


def test_temporal_settings_require_mtls_in_production(monkeypatch, tmp_path):
    monkeypatch.setenv("DECA_TEMPORAL_ADDRESS", "temporal:7233")
    monkeypatch.setenv("DECA_TEMPORAL_PAYLOAD_KEY", KEY.hex())
    assert TemporalSettings.from_env().tls is None
    monkeypatch.setenv("DECA_ENV", "production")
    with pytest.raises(ConfigError, match="mTLS"):
        TemporalSettings.from_env()
    for n in ("ca", "cert", "key"):
        (tmp_path / n).write_bytes(b"pem")
    monkeypatch.setenv("DECA_TEMPORAL_TLS_CA_FILE", str(tmp_path / "ca"))
    with pytest.raises(ConfigError, match="all of"):
        TemporalSettings.from_env()
    monkeypatch.setenv("DECA_TEMPORAL_TLS_CERT_FILE", str(tmp_path / "cert"))
    monkeypatch.setenv("DECA_TEMPORAL_TLS_KEY_FILE", str(tmp_path / "key"))
    assert TemporalSettings.from_env().tls is not None
    monkeypatch.delenv("DECA_TEMPORAL_PAYLOAD_KEY")
    with pytest.raises(ConfigError, match="PAYLOAD_KEY"):
        TemporalSettings.from_env()


# --- against a private Temporal dev server ------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def temporal_address(tmp_path_factory):
    binary = os.environ.get("DECA_TEST_TEMPORAL_BIN")
    if not binary:
        pytest.skip("no Temporal dev server (set DECA_TEST_TEMPORAL_BIN)")
    port = _free_port()
    log = (tmp_path_factory.mktemp("temporal") / "dev.log").open("w")
    proc = subprocess.Popen(
        [binary, "server", "start-dev", "--headless", "--ip", "127.0.0.1", "--port", str(port),
         "--http-port", str(_free_port()), "--metrics-port", str(_free_port()), "-n", NS, "--log-level", "warn"],
        stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.time() + 60
        while True:
            try:
                asyncio.run(Client.connect(f"127.0.0.1:{port}", namespace=NS))
                break
            except Exception:
                if time.time() > deadline or proc.poll() is not None:
                    raise
                time.sleep(0.5)
        yield f"127.0.0.1:{port}"
    finally:
        proc.terminate()
        proc.wait(timeout=20)
        log.close()


async def _client(address: str, *, codec: bool = True) -> Client:
    conv = data_converter(KEY) if codec else DataConverter.default
    return await Client.connect(address, namespace=NS, data_converter=conv)


def _fake_broker(outcomes: list):
    """An activity registered under the broker activity's name; pops one outcome per attempt."""
    calls: list[dict] = []

    @activity.defn(name="submit_to_broker")
    async def submit(request: dict) -> dict:
        calls.append(request)
        o = outcomes.pop(0) if outcomes else {"request_id": "r-1", "status": "validated", "reasons": []}
        if isinstance(o, Exception):
            raise o
        return o

    return submit, calls


def _worker(client, queue, broker_activity) -> Worker:
    return Worker(client, task_queue=queue, workflows=[AlertShadowWorkflow], activities=[triage_mock, broker_activity])


def test_workflow_retries_broker_outage_then_submits(temporal_address):
    async def go():
        client = await _client(temporal_address)
        queue = f"q-{uuid.uuid4().hex[:8]}"
        down = ApplicationError("broker http 503", type="BrokerUnavailable")
        fake, calls = _fake_broker([down, down])
        a = _alert()
        async with _worker(client, queue, fake):
            res = await client.execute_workflow(WORKFLOW_NAME, a, id=workflow_id(a["alert_id"]), task_queue=queue)
        return res, calls, a

    res, calls, a = asyncio.run(go())
    assert res["outcome"] == "submitted" and res["status"] == "validated" and res["verdict"] == "malicious"
    assert len(calls) == 3 and all(c == calls[0] for c in calls)
    assert calls[0]["idempotency_key"] == f"wf-{a['alert_id']}"


def test_workflow_stops_on_broker_rejection(temporal_address):
    async def go():
        client = await _client(temporal_address)
        queue = f"q-{uuid.uuid4().hex[:8]}"
        fake, calls = _fake_broker([ApplicationError("broker http 422", type="BrokerRejected", non_retryable=True)])
        a = _alert()
        async with _worker(client, queue, fake):
            with pytest.raises(WorkflowFailureError) as ei:
                await client.execute_workflow(WORKFLOW_NAME, a, id=workflow_id(a["alert_id"]), task_queue=queue)
        raw = await _client(temporal_address, codec=False)
        history = await raw.get_workflow_handle(workflow_id(a["alert_id"])).fetch_history()
        return ei.value, calls, history.to_json()

    err, calls, history = asyncio.run(go())
    assert len(calls) == 1
    assert isinstance(err.cause, ActivityError) and err.cause.cause.type == "BrokerRejected"
    # Failure messages are encrypted too, not only payloads.
    assert "broker http 422" not in history


def test_workflow_no_action_without_target(temporal_address):
    async def go():
        client = await _client(temporal_address)
        queue = f"q-{uuid.uuid4().hex[:8]}"
        fake, calls = _fake_broker([])
        a = _alert(source="sas", entities={"src_ip": None})
        async with _worker(client, queue, fake):
            res = await client.execute_workflow(WORKFLOW_NAME, a, id=workflow_id(a["alert_id"]), task_queue=queue)
        return res, calls

    res, calls = asyncio.run(go())
    assert res["outcome"] == "no_action" and calls == []


def test_alert_started_while_worker_down_is_not_lost(temporal_address):
    queue = f"q-{uuid.uuid4().hex[:8]}"
    starter = TemporalStarter(TemporalSettings(temporal_address, NS, queue, KEY))
    a = _alert()
    try:
        ref = starter(a)
        # Redelivery after a gateway crash attaches to the same run.
        assert starter(a) == ref
    finally:
        starter.close()
    assert ref.startswith(workflow_id(a["alert_id"]) + "/")

    async def go():
        client = await _client(temporal_address)
        handle = client.get_workflow_handle(workflow_id(a["alert_id"]))
        await asyncio.sleep(2)
        before = (await handle.describe()).status
        fake, calls = _fake_broker([])
        async with _worker(client, queue, fake):
            res = await handle.result()
        raw = await _client(temporal_address, codec=False)
        history = await raw.get_workflow_handle(workflow_id(a["alert_id"])).fetch_history()
        return before, res, calls, history

    before, res, calls, history = asyncio.run(go())
    assert before == WorkflowExecutionStatus.RUNNING
    assert res["outcome"] == "submitted" and len(calls) == 1
    started = history.events[0].workflow_execution_started_event_attributes
    assert started.input.payloads[0].metadata["encoding"] == b"binary/encrypted"
    dump = history.to_json()
    assert TOKEN not in dump and "waf.sqli.burst" not in dump and "mock-phase0" not in dump

    # A finished alert is never run twice: a late redelivery is accepted as already delivered.
    again = TemporalStarter(TemporalSettings(temporal_address, NS, queue, KEY))
    try:
        assert again(a) == f"{workflow_id(a['alert_id'])}/existing"
    finally:
        again.close()


def test_starter_reports_unreachable_temporal_without_details():
    from deca_soar.gateway.service import DeliveryError

    starter = TemporalStarter(TemporalSettings(f"127.0.0.1:{_free_port()}", NS, "q", KEY))
    try:
        with pytest.raises(DeliveryError) as ei:
            starter(_alert())
    finally:
        starter.close()
    assert "127.0.0.1" not in str(ei.value)

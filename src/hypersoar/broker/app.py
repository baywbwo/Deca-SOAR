"""Action Broker HTTP API (internal network only). Shadow-only: requests are validated and recorded, never executed."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager, suppress
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from hypersoar import ledger
from hypersoar.broker import catalog as catalog_mod
from hypersoar.broker import roles, service
from hypersoar.broker import triage as triage_mod
from hypersoar.broker.integrations import NAMES, config as int_config, secretbox
from hypersoar.broker.integrations import hub as hub_mod
from hypersoar.broker.integrations import lark as lark_mod
from hypersoar.broker.roles import Principal
from hypersoar.common import entity as entity_mod
from hypersoar.common.config import ConfigError, Settings, assert_no_write_credentials, read_secret
from hypersoar.common.db import make_pool
from hypersoar.common.dbguard import assert_least_privilege_login
from hypersoar.common.http import DEFAULT_MAX_BODY, BodyLimit
from hypersoar.common.pii import Vault

log = logging.getLogger("hypersoar.broker")


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["benign", "suspicious", "malicious", "unknown"]
    confidence: float = Field(ge=0.0, le=1.0)
    source: Literal["rule", "llm"]
    model: str | None = Field(default=None, max_length=128)
    prompt_version: str | None = Field(default=None, max_length=64)
    rationale_summary: str | None = Field(default=None, max_length=2000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    deterministic_signals: dict = Field(default_factory=dict)


class ActionRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: uuid.UUID
    case_id: str | None = Field(default=None, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    params: dict = Field(default_factory=dict)
    decision: DecisionIn
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)


class ApprovalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool


class KillSwitchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: str = Field(min_length=1, max_length=128)
    engaged: bool


class TriageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: uuid.UUID


class Reauth(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=1024)


class IntegrationConfigIn(Reauth):
    target: Literal["mock", "live"]
    enabled: bool = True
    settings: dict
    note: str = Field(default="", max_length=200)


class SecretIn(Reauth):
    value: str = Field(min_length=1, max_length=4096)
    expires_at: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")


class RollbackIn(Reauth):
    version: int = Field(ge=1)


SYNC_INTERVAL_S = float(os.environ.get("HYPERSOAR_SYNC_INTERVAL_S", "5"))


async def _sync_loop(app: FastAPI) -> None:
    """Escalations and the integration outbox. Blocking DB/HTTP work runs in a thread."""
    while True:
        try:
            await asyncio.to_thread(hub_mod.tick, app.state.pool, app.state.broker.hub)
        except Exception:  # keep the loop alive; the next tick retries
            log.exception("integration sync tick failed")
        await asyncio.sleep(SYNC_INTERVAL_S)


def build_hub(pool) -> hub_mod.Hub:
    mode = entity_mod.current_mode()
    ent = entity_mod.load(mode=mode)
    box = secretbox.SecretBox.from_env()
    if mode == "production" and box is None:
        raise ConfigError("production needs HYPERSOAR_INTEGRATION_KEY_FILE for integration secrets")
    with pool.connection() as conn, conn.transaction():
        entity_mod.assert_install(conn, mode, ent.id)
        seeded = int_config.seed(conn, ent)
    if seeded:
        log.info("integration settings seeded from the entity file: %s", ", ".join(seeded))
    return hub_mod.Hub(
        entity=ent, mode=mode, box=box,
        console_url=os.environ.get("HYPERSOAR_CONSOLE_URL") or None,
        jira_inbound=os.environ.get("HYPERSOAR_JIRA_INBOUND") == "1",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    assert_no_write_credentials()
    settings = Settings.for_broker()
    cat, protected = catalog_mod.load(settings.policy_dir)
    production = os.environ.get("HYPERSOAR_ENV") == "production"
    if production and protected.has_placeholders:
        raise ConfigError("protected.yaml still has placeholder entries; refusing to start in production")
    allow_test_nets = os.environ.get("HYPERSOAR_ALLOW_TEST_NETS") == "1"
    if production and allow_test_nets:
        raise ConfigError("HYPERSOAR_ALLOW_TEST_NETS is for tests only; refusing to start in production")
    app.state.broker = service.Broker(
        catalog=cat,
        protected=protected,
        vault=Vault(settings.vault_private_key, settings.vault_key_id),
        internal_cidrs=settings.internal_cidrs,
        allow_test_nets=allow_test_nets,
    )
    pool = make_pool(settings.db_url)
    try:
        with pool.connection() as conn:
            assert_least_privilege_login(conn, "broker")
    except BaseException:
        pool.close()
        raise
    app.state.pool = pool
    try:
        app.state.broker.hub = build_hub(pool)
    except BaseException:
        pool.close()
        raise
    task = None
    if os.environ.get("HYPERSOAR_SYNC", "1") == "1":
        task = asyncio.create_task(_sync_loop(app))
    log.info("broker ready: %d actions, mode=shadow, entity=%s (%s)", len(cat), app.state.broker.entity_id,
             app.state.broker.hub.mode)
    yield
    if task:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    app.state.pool.close()


app = FastAPI(title="HyperSoar Action Broker", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(BodyLimit, max_bytes=int(os.environ.get("HYPERSOAR_MAX_BODY_BYTES", DEFAULT_MAX_BODY)))


def current_principal(request: Request) -> Principal:
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    with request.app.state.pool.connection() as conn:
        p = service.principal_by_token(conn, token.strip())
    if p is None:
        raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
    return p


def require(permission: str):
    def dep(p: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if not roles.allowed(p, permission):
            raise HTTPException(403, f"role {p.role} ({p.kind}) lacks {permission}")
        return p

    return dep


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "mode": "shadow"}


@app.get("/v1/whoami")
def whoami(p: Annotated[Principal, Depends(current_principal)]) -> dict:
    perms = (roles.READ, roles.REQUEST_ACTION, roles.APPROVE, roles.KILL_SWITCH, roles.MANAGE)
    return {"name": p.name, "kind": p.kind, "role": p.role, "permissions": [x for x in perms if roles.allowed(p, x)]}


@app.get("/v1/catalog")
def get_catalog(request: Request, _: Annotated[Principal, Depends(require(roles.READ))]) -> dict:
    return {"mode": "shadow", "actions": [a.public() for a in request.app.state.broker.catalog.values()]}


@app.get("/v1/roles")
def get_roles(_: Annotated[Principal, Depends(require(roles.READ))]) -> dict:
    return roles.matrix()


@app.post("/v1/actions/requests", status_code=201)
def post_request(
    body: ActionRequestIn,
    request: Request,
    response: Response,
    p: Annotated[Principal, Depends(require(roles.REQUEST_ACTION))],
) -> dict:
    data = body.model_dump(mode="json")
    try:
        with request.app.state.pool.connection() as conn, conn.transaction():
            view, replayed = service.submit(conn, request.app.state.broker, p, data)
    except service.NotFound as e:
        raise HTTPException(404, f"{e} not found") from None
    except service.Conflict as e:
        raise HTTPException(409, str(e)) from None
    if replayed:
        response.status_code = 200
    return {**view, "idempotent_replay": replayed}


@app.get("/v1/actions/requests/{request_id}")
def get_request(request_id: uuid.UUID, request: Request, _: Annotated[Principal, Depends(require(roles.READ))]) -> dict:
    try:
        with request.app.state.pool.connection() as conn:
            return service.get_request(conn, str(request_id))
    except service.NotFound:
        raise HTTPException(404, "request not found") from None


@app.post("/v1/actions/requests/{request_id}/approval")
def post_approval(
    request_id: uuid.UUID,
    body: ApprovalIn,
    request: Request,
    p: Annotated[Principal, Depends(require(roles.APPROVE))],
) -> dict:
    try:
        with request.app.state.pool.connection() as conn, conn.transaction():
            return service.decide_approval(conn, p, str(request_id), body.approve, request.app.state.broker)
    except service.Expired as e:
        with request.app.state.pool.connection() as conn, conn.transaction():
            service.mark_expired(conn, str(request_id), f"principal:{p.name}")
        raise HTTPException(409, str(e)) from None
    except service.NotFound:
        raise HTTPException(404, "request not found") from None
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except service.Conflict as e:
        raise HTTPException(409, str(e)) from None


@app.post("/v1/kill-switch")
def post_kill_switch(
    body: KillSwitchIn, request: Request, p: Annotated[Principal, Depends(require(roles.KILL_SWITCH))]
) -> dict:
    if body.scope != "global" and body.scope not in request.app.state.broker.catalog:
        raise HTTPException(422, "scope must be 'global' or a catalog action")
    with request.app.state.pool.connection() as conn, conn.transaction():
        service.set_kill_switch(conn, p.principal_id, f"principal:{p.name}", body.scope, body.engaged,
                                request.app.state.broker.entity_id)
    return {"scope": body.scope, "engaged": body.engaged}


@app.get("/v1/ledger/verify")
def ledger_verify(request: Request, _: Annotated[Principal, Depends(require(roles.READ))]) -> dict:
    with request.app.state.pool.connection() as conn:
        r = ledger.verify(conn)
    return {"ok": r.ok, "entries": r.entries, "head_seq": r.head_seq, "head_hash": r.head_hash, "errors": r.errors}


# -- triage (9router) -----------------------------------------------------------
@app.post("/v1/triage")
def post_triage(body: TriageIn, request: Request, p: Annotated[Principal, Depends(require(roles.REQUEST_ACTION))]) -> dict:
    try:
        return triage_mod.triage(request.app.state.pool, request.app.state.broker, str(body.alert_id),
                                 f"principal:{p.name}")
    except service.NotFound:
        raise HTTPException(404, "alert not found") from None


# -- Lark card callback -----------------------------------------------------------
# Lark cannot send a bearer token: the signature (encrypt key) and verification token are the
# authentication. The console forwards /hooks/lark/card here unchanged; only the broker can open them.
@app.post("/hooks/lark/card")
async def lark_card(request: Request) -> Response:
    raw = await request.body()
    b = request.app.state.broker
    pool = request.app.state.pool

    def handle():
        with pool.connection() as conn:
            secrets = b.hub.lark_secrets(conn)
        try:
            event = lark_mod.verify_callback(request.headers, raw, encrypt_key=secrets.get("encrypt_key", ""),
                                             verification_token=secrets.get("verification_token", ""))
        except lark_mod.CallbackRejected as e:
            log.warning("lark callback rejected: %s", e)
            return JSONResponse({"detail": "rejected"}, status_code=401)
        if event.get("type") == "url_verification":
            return JSONResponse({"challenge": str(event.get("challenge", ""))[:200]})
        click = lark_mod.card_click(event)
        if click is None:
            return JSONResponse({"detail": "ignored"}, status_code=200)
        uid, rid, approve = click
        try:
            with pool.connection() as conn, conn.transaction():
                view = service.decide_from_lark(conn, b, uid, rid, approve)
        except PermissionError as e:
            with pool.connection() as conn, conn.transaction():
                service.record_refusal(conn, b, uid, rid, str(e))
            return JSONResponse({"toast": {"type": "error", "content": "You are not allowed to approve this."}},
                                status_code=403)
        except service.Expired:
            with pool.connection() as conn, conn.transaction():
                service.mark_expired(conn, rid, f"lark:{uid[:80]}")
            return JSONResponse({"toast": {"type": "warning", "content": "Not recorded: approval window expired."}},
                                status_code=409)
        except service.NotFound:
            return JSONResponse({"toast": {"type": "error", "content": "Request not found."}}, status_code=404)
        except service.Conflict as e:
            return JSONResponse({"toast": {"type": "warning", "content": f"Not recorded: {e}."}}, status_code=409)
        verb = "Approved" if approve else "Rejected"
        return JSONResponse({"toast": {"type": "success", "content": f"{verb}. Shadow mode: nothing ran."},
                             "request_id": view["request_id"], "status": view["status"]})

    return await asyncio.to_thread(handle)


# -- Jira inbound: "close the case when the issue is Done" (off until reviewed) ----
@app.post("/hooks/jira")
async def jira_inbound(request: Request, x_hub_signature: Annotated[str | None, Header()] = None) -> Response:
    b = request.app.state.broker
    if not b.hub.jira_inbound:
        raise HTTPException(404, "not found")
    raw = await request.body()
    pool = request.app.state.pool

    def handle():
        with pool.connection() as conn:
            secret = secretbox.get_secrets(conn, b.hub.box, b.entity_id, "jira", b.hub.mode).get("webhook_secret")
            _, s = int_config.settings_of(conn, b.entity_id, "jira", b.hub.mode)
        if not secret or not s or not s.sync.close_case_on_done:
            raise HTTPException(404, "not found")
        want = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        if not x_hub_signature or not hmac.compare_digest(want, x_hub_signature.strip()):
            raise HTTPException(401, "rejected")
        try:
            ev = json.loads(raw)
            issue = ev["issue"]
            key = str(issue["key"])[:40]
            cat = issue["fields"]["status"]["statusCategory"]["key"]
            labels = issue["fields"].get("labels") or []
        except (ValueError, KeyError, TypeError):
            raise HTTPException(422, "unexpected payload") from None
        if cat != "done":
            return {"ignored": "not done"}
        with pool.connection() as conn, conn.transaction():
            row = conn.execute("SELECT case_id, label FROM broker.jira_issue WHERE entity_id = %s AND issue_key = %s",
                               (b.entity_id, key)).fetchone()
            if row is None or row["label"] not in labels:
                return {"ignored": "not a HyperSoar issue"}
            # Case ids are never reused, so one request per case is enough; the broker role has no UPDATE here.
            new = conn.execute(
                "INSERT INTO broker.case_close_request (entity_id, case_id, source, external_ref) VALUES"
                " (%s, %s, 'jira', %s) ON CONFLICT (entity_id, case_id, source) DO NOTHING RETURNING case_id",
                (b.entity_id, row["case_id"], key)).fetchone()
            if new is None:
                return {"case_id": row["case_id"], "close_requested": True}
            ledger.append(conn, "case.close_requested", "service:jira", {"case_id": row["case_id"],
                                                                         "issue_key": key}, b.entity_id)
        return {"case_id": row["case_id"], "close_requested": True}

    return await asyncio.to_thread(handle)


# -- Integration settings (screen 08) ----------------------------------------------
def _integration(name: str) -> str:
    if name not in NAMES:
        raise HTTPException(404, "unknown integration")
    return name


def require_admin_reauth(request: Request, p: Principal, password: str) -> None:
    """Writes need HYPERSOAR_INTEGRATION_WRITES=1 (off until screen 08 is approved and reviewed), a
    human admin, and the admin password again."""
    if os.environ.get("HYPERSOAR_INTEGRATION_WRITES") != "1":
        raise HTTPException(403, "integration writes are disabled on this install")
    if p.kind != "human" or p.role != "admin":
        raise HTTPException(403, "only a human admin may change integrations")
    from hypersoar.console.auth import PasswordHash
    raw = read_secret("HYPERSOAR_INTEGRATION_ADMIN_PASSWORD_HASH", required=False)
    if not raw or not PasswordHash.parse(raw).verify(password):
        raise HTTPException(403, "re-authentication failed")


@app.get("/v1/integrations")
def list_integrations(request: Request, _: Annotated[Principal, Depends(require(roles.READ))]) -> dict:
    b = request.app.state.broker
    with request.app.state.pool.connection() as conn:
        items = [int_config.view(conn, b.entity_id, n, b.hub.mode) for n in NAMES]
    return {"entity_id": b.entity_id, "mode": b.hub.mode,
            "writes_enabled": os.environ.get("HYPERSOAR_INTEGRATION_WRITES") == "1",
            "jira_inbound": b.hub.jira_inbound, "integrations": items}


@app.get("/v1/integrations/{name}/history")
def integration_history(name: str, request: Request, _: Annotated[Principal, Depends(require(roles.READ))]) -> dict:
    b = request.app.state.broker
    with request.app.state.pool.connection() as conn:
        rows = conn.execute(
            "SELECT version, target, enabled, changed_by, changed_at, note FROM broker.integration_config_version"
            " WHERE entity_id = %s AND integration = %s AND mode = %s ORDER BY version DESC LIMIT 20",
            (b.entity_id, _integration(name), b.hub.mode)).fetchall()
    return {"versions": [{**r, "changed_at": r["changed_at"].isoformat()} for r in rows]}


@app.put("/v1/integrations/{name}")
def put_integration(name: str, body: IntegrationConfigIn, request: Request,
                    p: Annotated[Principal, Depends(require(roles.MANAGE))]) -> dict:
    require_admin_reauth(request, p, body.password)
    b = request.app.state.broker
    try:
        with request.app.state.pool.connection() as conn, conn.transaction():
            v = int_config.save(conn, b.entity_id, _integration(name), b.hub.mode, body.target, body.enabled,
                                body.settings, f"principal:{p.name}", body.note)
    except int_config.ConfigInvalid as e:
        raise HTTPException(422, str(e)) from None
    return {"integration": name, "version": v}


@app.post("/v1/integrations/{name}/rollback")
def rollback_integration(name: str, body: RollbackIn, request: Request,
                         p: Annotated[Principal, Depends(require(roles.MANAGE))]) -> dict:
    require_admin_reauth(request, p, body.password)
    b = request.app.state.broker
    try:
        with request.app.state.pool.connection() as conn, conn.transaction():
            v = int_config.rollback(conn, b.entity_id, _integration(name), b.hub.mode, body.version,
                                    f"principal:{p.name}")
    except LookupError:
        raise HTTPException(404, "version not found") from None
    except int_config.ConfigInvalid as e:
        raise HTTPException(422, str(e)) from None
    return {"integration": name, "version": v}


@app.put("/v1/integrations/{name}/secrets/{secret}", status_code=204)
def put_secret(name: str, secret: str, body: SecretIn, request: Request,
               p: Annotated[Principal, Depends(require(roles.MANAGE))]) -> Response:
    require_admin_reauth(request, p, body.password)
    b = request.app.state.broker
    if b.hub.box is None:
        raise HTTPException(409, "integration master key not mounted")
    from datetime import date
    expires = date.fromisoformat(body.expires_at) if body.expires_at else None
    try:
        with request.app.state.pool.connection() as conn, conn.transaction():
            secretbox.set_secret(conn, b.hub.box, b.entity_id, _integration(name), b.hub.mode, secret, body.value,
                                 f"principal:{p.name}", expires)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return Response(status_code=204)


@app.post("/v1/integrations/{name}/test")
def test_integration(name: str, request: Request, p: Annotated[Principal, Depends(require(roles.MANAGE))]) -> dict:
    if p.kind != "human":
        raise HTTPException(403, "only a human admin may run a connection test")
    b = request.app.state.broker
    return b.hub.test(request.app.state.pool.connection, _integration(name), f"principal:{p.name}")

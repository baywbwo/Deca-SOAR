"""Action Broker HTTP API (internal network only). Requests are validated and recorded; no cloud
executor is connected, so nothing is executed against cloud accounts.

Human writes (approve, kill switch, revoke) need the person's password again; case triage needs a
person. Every write accepts an Idempotency-Key header and leaves a ledger entry."""

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
from hypersoar.broker import roles, service, writes
from hypersoar.broker import triage as triage_mod
from hypersoar.broker.integrations import NAMES, config as int_config, secretbox
from hypersoar.broker.integrations import hub as hub_mod
from hypersoar.broker.integrations import lark as lark_mod
from hypersoar.broker.roles import Principal
from hypersoar.common import entity as entity_mod
from hypersoar.common.config import ConfigError, Settings, assert_no_write_credentials
from hypersoar.common.db import make_pool
from hypersoar.common.dbguard import assert_least_privilege_login
from hypersoar.common.http import DEFAULT_MAX_BODY, BodyLimit
from hypersoar.common.pii import Vault
from hypersoar.console.auth import LoginLimiter

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
    password: str | None = Field(default=None, max_length=1024)
    reason: str | None = Field(default=None, max_length=500)


class KillSwitchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: str = Field(min_length=1, max_length=128)
    engaged: bool
    password: str | None = Field(default=None, max_length=1024)
    reason: str = Field(min_length=3, max_length=500)


class RevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str | None = Field(default=None, max_length=1024)
    reason: str = Field(min_length=3, max_length=500)


class AssignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assignee: str | None = Field(default=None, min_length=1, max_length=80)


class CaseStatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "waiting", "closed"]
    reason: str | None = Field(default=None, max_length=500)


class CommentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=2000)


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
    app.state.reauth_limit = reauth_limiter()
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
def whoami(request: Request, p: Annotated[Principal, Depends(current_principal)]) -> dict:
    """Also the install this broker serves, so a worker can refuse to run against the other mode."""
    perms = (roles.READ, roles.REQUEST_ACTION, roles.TRIAGE, roles.APPROVE, roles.KILL_SWITCH, roles.MANAGE)
    b = request.app.state.broker
    return {"name": p.name, "kind": p.kind, "role": p.role, "channel": p.channel,
            "permissions": [x for x in perms if roles.allowed(p, x)],
            "install": {"mode": b.hub.mode, "entity_id": b.entity_id}}


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


IDEMPOTENCY_KEY = r"^[A-Za-z0-9_-]{8,128}$"


def _idem_key(value: str | None) -> str | None:
    import re
    if value is None:
        return None
    if not re.match(IDEMPOTENCY_KEY, value):
        raise HTTPException(422, "Idempotency-Key must be 8-128 letters, digits, - or _")
    return value


def reauth_limiter() -> LoginLimiter:
    """Failed re-authentications per principal (5 per 15 minutes) on top of the console's own limit, so a
    token used outside the console cannot guess a person's password either. One per broker process."""
    return LoginLimiter(per_client=5, window_s=900, global_per_min=60)


def human_write(request: Request, p: Principal, key: str | None, operation: str, body: dict, fn, *,
                reauth: bool, password: str | None = None) -> dict:
    """Run one human write in a transaction: re-auth (if asked), idempotent replay, the change, the
    stored answer. Errors map to 403 (not allowed / re-auth), 404, 409, 422 and 429. `password`
    overrides body["password"] when the body hashed for idempotency must not hold it."""
    key = _idem_key(key)
    sha = writes.body_sha(operation, body)
    pool = request.app.state.pool
    limiter = request.app.state.reauth_limit
    if reauth and not limiter.allow(p.principal_id):
        raise HTTPException(429, "too many failed re-authentications; try again later",
                            headers={"Retry-After": "900"})
    try:
        with pool.connection() as conn, conn.transaction():
            if reauth:
                writes.check_reauth(conn, p, password if password is not None else body.get("password"))
            elif p.kind != "human":
                raise PermissionError("only a person can make this change")
            if key and (prev := writes.replay(conn, p, key, operation, sha)) is not None:
                return prev
            out = fn(conn)
            return writes.remember(conn, p, key, operation, sha, out) if key else {**out, "idempotent_replay": False}
    except writes.ReauthFailed as e:
        limiter.failed(p.principal_id)
        with pool.connection() as conn, conn.transaction():
            ledger.append(conn, "auth.reauth_failed", f"principal:{p.name}", {"operation": operation},
                          request.app.state.broker.entity_id)
        raise HTTPException(403, str(e)) from None
    except service.Expired as e:
        rid = body.get("request_id")
        if rid:
            with pool.connection() as conn, conn.transaction():
                service.mark_expired(conn, rid, f"principal:{p.name}")
        raise HTTPException(409, str(e)) from None
    except (service.NotFound, LookupError) as e:
        raise HTTPException(404, f"{e} not found") from None
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except (service.Conflict, writes.WriteConflict) as e:
        raise HTTPException(409, str(e)) from None
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


@app.post("/v1/actions/requests/{request_id}/approval")
def post_approval(
    request_id: uuid.UUID,
    body: ApprovalIn,
    request: Request,
    p: Annotated[Principal, Depends(require(roles.APPROVE))],
    idempotency_key: Annotated[str | None, Header()] = None,
) -> dict:
    b = request.app.state.broker
    rid = str(request_id)
    return human_write(
        request, p, idempotency_key, "approval", {**body.model_dump(), "request_id": rid},
        lambda conn: service.decide_approval(conn, p, rid, body.approve, b, via=p.channel, reason=body.reason),
        reauth=True)


@app.post("/v1/actions/requests/{request_id}/revoke")
def post_revoke(
    request_id: uuid.UUID,
    body: RevokeIn,
    request: Request,
    p: Annotated[Principal, Depends(require(roles.APPROVE))],
    idempotency_key: Annotated[str | None, Header()] = None,
) -> dict:
    b = request.app.state.broker
    rid = str(request_id)
    return human_write(request, p, idempotency_key, "revoke", {**body.model_dump(), "request_id": rid},
                       lambda conn: writes.revoke(conn, b.entity_id, p, rid, body.reason), reauth=True)


@app.post("/v1/kill-switch")
def post_kill_switch(
    body: KillSwitchIn,
    request: Request,
    p: Annotated[Principal, Depends(require(roles.KILL_SWITCH))],
    idempotency_key: Annotated[str | None, Header()] = None,
) -> dict:
    b = request.app.state.broker
    if body.scope != "global" and body.scope not in b.catalog:
        raise HTTPException(422, "scope must be 'global' or a catalog action")

    def change(conn):
        service.set_kill_switch(conn, p.principal_id, f"principal:{p.name}", body.scope, body.engaged,
                                b.entity_id, body.reason)
        return {"scope": body.scope, "engaged": body.engaged}

    return human_write(request, p, idempotency_key, "kill_switch", body.model_dump(), change, reauth=True)


def _case_id(case_id: str) -> str:
    import re
    if not re.match(r"^CS-[0-9]{1,9}$", case_id):
        raise HTTPException(404, "case not found")
    return case_id


@app.post("/v1/cases/{case_id}/assign")
def post_case_assign(case_id: str, body: AssignIn, request: Request,
                     p: Annotated[Principal, Depends(require(roles.TRIAGE))],
                     idempotency_key: Annotated[str | None, Header()] = None) -> dict:
    cid, e = _case_id(case_id), request.app.state.broker.entity_id
    return human_write(request, p, idempotency_key, "case.assign", {**body.model_dump(), "case_id": cid},
                       lambda conn: writes.assign_case(conn, e, p, cid, body.assignee), reauth=False)


@app.post("/v1/cases/{case_id}/status")
def post_case_status(case_id: str, body: CaseStatusIn, request: Request,
                     p: Annotated[Principal, Depends(require(roles.TRIAGE))],
                     idempotency_key: Annotated[str | None, Header()] = None) -> dict:
    cid, e = _case_id(case_id), request.app.state.broker.entity_id
    return human_write(request, p, idempotency_key, "case.status", {**body.model_dump(), "case_id": cid},
                       lambda conn: writes.set_case_status(conn, e, p, cid, body.status, body.reason), reauth=False)


@app.post("/v1/cases/{case_id}/comments", status_code=201)
def post_case_comment(case_id: str, body: CommentIn, request: Request,
                      p: Annotated[Principal, Depends(require(roles.TRIAGE))],
                      idempotency_key: Annotated[str | None, Header()] = None) -> dict:
    cid, e = _case_id(case_id), request.app.state.broker.entity_id
    return human_write(request, p, idempotency_key, "case.comment", {**body.model_dump(), "case_id": cid},
                       lambda conn: writes.comment_case(conn, e, p, cid, body.body), reauth=False)


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
            try:
                _, s, secrets = b.hub._load(conn, "jira")
            except (hub_mod.NotConfigured, int_config.ConfigInvalid):
                s, secrets = None, {}
            secret = secrets.get("webhook_secret")
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


def _integration_write(request: Request, p: Principal, key: str | None, operation: str, body: dict,
                       password: str, fn) -> dict:
    """Integration writes: HYPERSOAR_INTEGRATION_WRITES=1 (off until screen 08 is approved and reviewed),
    a human admin (MANAGE), that person's password again, and an Idempotency-Key. The console reaches
    these through its own CSRF-checked, same-origin proxy (console /api/integrations/...)."""
    if os.environ.get("HYPERSOAR_INTEGRATION_WRITES") != "1":
        raise HTTPException(403, "integration writes are disabled on this install")
    if not key:
        raise HTTPException(422, "Idempotency-Key header is required")
    try:
        return human_write(request, p, key, operation, body, fn, reauth=True, password=password)
    except int_config.ConfigInvalid as e:
        raise HTTPException(422, str(e)) from None


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
                    p: Annotated[Principal, Depends(require(roles.MANAGE))],
                    idempotency_key: Annotated[str | None, Header()] = None) -> dict:
    b = request.app.state.broker
    name = _integration(name)
    return _integration_write(
        request, p, idempotency_key, f"integration.save:{name}", body.model_dump(), body.password,
        lambda conn: {"integration": name, "version": int_config.save(
            conn, b.entity_id, name, b.hub.mode, body.target, body.enabled, body.settings, f"principal:{p.name}",
            body.note)})


@app.post("/v1/integrations/{name}/rollback")
def rollback_integration(name: str, body: RollbackIn, request: Request,
                         p: Annotated[Principal, Depends(require(roles.MANAGE))],
                         idempotency_key: Annotated[str | None, Header()] = None) -> dict:
    b = request.app.state.broker
    name = _integration(name)
    return _integration_write(
        request, p, idempotency_key, f"integration.rollback:{name}", body.model_dump(), body.password,
        lambda conn: {"integration": name, "version": int_config.rollback(
            conn, b.entity_id, name, b.hub.mode, body.version, f"principal:{p.name}")})


@app.put("/v1/integrations/{name}/secrets/{secret}")
def put_secret(name: str, secret: str, body: SecretIn, request: Request,
               p: Annotated[Principal, Depends(require(roles.MANAGE))],
               idempotency_key: Annotated[str | None, Header()] = None) -> dict:
    b = request.app.state.broker
    name = _integration(name)
    if b.hub.box is None:
        raise HTTPException(409, "integration master key not mounted")
    from datetime import date
    expires = date.fromisoformat(body.expires_at) if body.expires_at else None

    def fn(conn):
        secretbox.set_secret(conn, b.hub.box, b.entity_id, name, b.hub.mode, secret, body.value,
                             f"principal:{p.name}", expires)
        return {"integration": name, "secret": secret[:40], "set": True}
    # The value is never part of the stored request hash: a retry is matched on name and expiry only.
    return _integration_write(request, p, idempotency_key, f"integration.secret:{name}:{secret[:40]}",
                              {"expires_at": body.expires_at}, body.password, fn)


@app.post("/v1/integrations/{name}/test")
def test_integration(name: str, body: Reauth, request: Request,
                     p: Annotated[Principal, Depends(require(roles.MANAGE))],
                     idempotency_key: Annotated[str | None, Header()] = None) -> dict:
    """A passing test also activates the tested version, so it is a write like the others."""
    b = request.app.state.broker
    name = _integration(name)
    pool = request.app.state.pool
    return _integration_write(request, p, idempotency_key, f"integration.test:{name}", {}, body.password,
                              lambda conn: b.hub.test(pool.connection, name, f"principal:{p.name}"))

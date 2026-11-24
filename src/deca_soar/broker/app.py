"""Action Broker HTTP API (internal network only). Shadow-only: requests are validated and recorded, never executed."""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from deca_soar import ledger
from deca_soar.broker import catalog as catalog_mod
from deca_soar.broker import roles, service
from deca_soar.broker.roles import Principal
from deca_soar.common.config import ConfigError, Settings, assert_no_write_credentials
from deca_soar.common.db import make_pool
from deca_soar.common.pii import Vault

log = logging.getLogger("deca_soar.broker")


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    assert_no_write_credentials()
    settings = Settings.from_env()
    cat, protected = catalog_mod.load(settings.policy_dir)
    if os.environ.get("DECA_ENV") == "production" and protected.has_placeholders:
        raise ConfigError("protected.yaml still has placeholder entries; refusing to start in production")
    app.state.broker = service.Broker(
        catalog=cat,
        protected=protected,
        vault=Vault(settings.vault_key, settings.vault_key_id),
        internal_cidrs=settings.internal_cidrs,
    )
    app.state.pool = make_pool(settings.db_url)
    log.info("broker ready: %d actions, mode=shadow", len(cat))
    yield
    app.state.pool.close()


app = FastAPI(title="DECA SOAR Action Broker", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


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
            return service.decide_approval(conn, p, str(request_id), body.approve)
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
        service.set_kill_switch(conn, p.principal_id, f"principal:{p.name}", body.scope, body.engaged)
    return {"scope": body.scope, "engaged": body.engaged}


@app.get("/v1/ledger/verify")
def ledger_verify(request: Request, _: Annotated[Principal, Depends(require(roles.READ))]) -> dict:
    with request.app.state.pool.connection() as conn:
        r = ledger.verify(conn)
    return {"ok": r.ok, "entries": r.entries, "head_seq": r.head_seq, "head_hash": r.head_hash, "errors": r.errors}

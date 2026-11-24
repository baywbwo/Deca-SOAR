"""9router AI DECA: LLM triage over an OpenAI-compatible /chat/completions endpoint.

Guardrails (screen 08):
- only tokenised data leaves: the prompt is built from tokens and catalog fields, then checked for
  raw IPs, emails, phone numbers and AccessKeys before any call;
- the answer must match the triage schema exactly, and may only cite tokens that are in the alert;
  anything else is verdict unknown and the case goes to an analyst;
- if the triage model fails, the fallback model gets one try; if both fail, unknown + escalate;
- past the daily token limit no call is made at all: unknown + escalate;
- the AI never decides an action: the broker's policy does (it only reads the verdict).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from hypersoar.common.pii import TOKEN_RE

SYSTEM_PROMPT = (
    "You are the triage step of a security operations pipeline. You receive one alert as JSON. Every "
    "IP, user, account and key is already replaced by a token like tok_ip_0123456789abcdef. Answer with "
    "one JSON object and nothing else: {\"verdict\": \"benign\"|\"suspicious\"|\"malicious\"|\"unknown\", "
    "\"confidence\": number 0..1, \"rationale_summary\": string (max 500 chars, no advice to act), "
    "\"evidence_refs\": [tokens from the alert that support the verdict]}. Do not propose actions."
)
PROMPT_SHA = hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:16]
_RAW = [
    re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\bLTAI[0-9A-Za-z]{12,30}\b"),
    re.compile(r"(?<![\d+])(?:\+?62|0)8\d{1,3}[\s-]?\d{3,4}[\s-]?\d{3,5}(?!\d)"),
    re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])"),
]


class TriageOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["benign", "suspicious", "malicious", "unknown"]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale_summary: str = Field(max_length=500)
    evidence_refs: list[str] = Field(max_length=20)


@dataclass
class Attempt:
    model: str
    ok: bool
    error: str | None = None
    latency_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    schema_ok: bool = False


@dataclass
class TriageResult:
    verdict: str
    confidence: float
    rationale_summary: str
    evidence_refs: list[str]
    model: str | None
    prompt_version: str
    target: str
    attempts: list[Attempt] = field(default_factory=list)
    fallback_used: bool = False
    escalate: str | None = None  # reason the case goes to an analyst, None if the AI answered

    @property
    def tokens(self) -> int:
        return sum(a.tokens_in + a.tokens_out for a in self.attempts)

    def trace(self) -> dict:
        """G4 work trace for the ledger: what was asked and how it went, never the alert content."""
        return {
            "target": self.target, "prompt_version": self.prompt_version, "prompt_sha": PROMPT_SHA,
            "verdict": self.verdict, "confidence": self.confidence, "model": self.model,
            "fallback_used": self.fallback_used, "escalated": self.escalate,
            "attempts": [asdict(a) for a in self.attempts], "evidence_refs": self.evidence_refs,
        }


def build_input(alert: dict, case: dict | None) -> dict:
    """What the model sees: tokens and catalog fields only. No free text from the raw event."""
    a = alert.get("alert") or {}
    ents = a.get("entities") or {}
    return {
        "rule_id": alert["rule_id"], "source": alert["source"], "severity": alert["severity_hint"],
        "category": a.get("category"), "mitre": a.get("attack"), "outcome": a.get("outcome"),
        "events": alert.get("event_count"),
        "entities": {k: v for k, v in ents.items() if isinstance(v, str) and (TOKEN_RE.fullmatch(v) or k == "dst_asset")},
        "evidence_tokens": list(alert.get("evidence_tokens") or []),
        "origin": {k: (a.get("origin") or {}).get(k) for k in ("country", "asn", "tor")} if a.get("origin") else None,
        "case": {"case_id": case["case_id"], "alerts": case["alert_count"], "tactics": case["tactics"]} if case else None,
    }


def raw_values_in(text: str) -> bool:
    stripped = TOKEN_RE.sub("", text)
    return any(p.search(stripped) for p in _RAW)


def parse_answer(content: str, allowed_refs: set[str]) -> TriageOut:
    data = json.loads(content)
    out = TriageOut.model_validate(data)
    if not set(out.evidence_refs) <= allowed_refs:
        raise ValueError("evidence_refs cites a token that is not in the alert")
    return out


def _mock_answer(inp: dict, fault: str, primary: bool) -> tuple[str, int, int]:
    if fault == "timeout":
        raise httpx.ReadTimeout("mock timeout")
    if fault == "invalid_json" or (fault == "invalid_json_primary" and primary):
        return '{"verdict": "malicious", "confidence": 0.9, "rationale_summary": "cut off', 180, 12
    sev = inp["severity"]
    verdict, conf = {"critical": ("malicious", 0.93), "high": ("malicious", 0.91), "medium": ("suspicious", 0.74),
                     "low": ("benign", 0.81), "info": ("benign", 0.9)}[sev]
    refs = inp["evidence_tokens"][:3]
    rationale = (f"{inp['category'] or inp['rule_id']} ({sev}); "
                 f"{(inp.get('mitre') or {}).get('technique') or 'no technique'}; {inp['events']} events")
    return json.dumps({"verdict": verdict, "confidence": conf, "rationale_summary": rationale[:500],
                       "evidence_refs": refs}), 220, 48


class NineRouter:
    def __init__(self, settings, secrets: dict, target: str, *, transport=None):
        self.s = settings
        self.target = target
        self._key = secrets.get("api_key")
        self._transport = transport

    def _ask(self, model: str, user: str, inp: dict, primary: bool) -> tuple[str, int, int]:
        if self.target == "mock":
            return _mock_answer(inp, self.s.mock_fault, primary)
        if not self._key:
            raise RuntimeError("api key not set")
        with httpx.Client(base_url=self.s.base_url.rstrip("/") + "/", timeout=httpx.Timeout(float(self.s.timeout_s)),
                          follow_redirects=False, transport=self._transport,
                          headers={"Authorization": f"Bearer {self._key}"}) as http:
            r = http.post("chat/completions", json={
                "model": model, "temperature": 0, "max_tokens": self.s.max_tokens,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}],
            })
        if r.status_code >= 400:
            raise RuntimeError(f"http {r.status_code}")
        try:
            body = r.json()
            content = body["choices"][0]["message"]["content"]
            usage = body.get("usage") or {}
        except (ValueError, KeyError, IndexError, TypeError):
            raise RuntimeError("response is not an OpenAI-compatible completion") from None
        if not isinstance(content, str):
            raise RuntimeError("completion has no text")
        return content, int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)

    def triage(self, alert: dict, case: dict | None, tokens_used_today: int) -> TriageResult:
        inp = build_input(alert, case)
        res = TriageResult("unknown", 0.0, "", [], None, self.s.prompt_version, self.target)
        if tokens_used_today >= self.s.daily_token_limit:
            res.escalate = "daily token limit reached; AI stopped"
            res.rationale_summary = res.escalate
            return res
        user = json.dumps(inp, sort_keys=True, separators=(",", ":"))
        if raw_values_in(user):
            res.escalate = "alert is not fully tokenised; nothing sent to the AI"
            res.rationale_summary = res.escalate
            return res
        allowed = set(inp["evidence_tokens"]) | {v for v in inp["entities"].values() if TOKEN_RE.fullmatch(v)}
        models = [self.s.triage_model] + ([self.s.fallback_model] if self.s.fallback_model else [])
        for i, model in enumerate(models):
            att = Attempt(model=model, ok=False)
            res.attempts.append(att)
            t0 = time.monotonic()
            try:
                content, att.tokens_in, att.tokens_out = self._ask(model, user, inp, i == 0)
            except httpx.TimeoutException:
                att.error = "timeout"
            except (httpx.TransportError, RuntimeError) as e:
                att.error = (str(e) if isinstance(e, RuntimeError) else f"unreachable ({type(e).__name__})")[:120]
            else:
                try:
                    out = parse_answer(content, allowed)
                except (ValueError, ValidationError):
                    att.error = "answer does not match the triage schema"
                else:
                    att.ok = att.schema_ok = True
                    res.verdict, res.confidence = out.verdict, out.confidence
                    res.rationale_summary, res.evidence_refs = out.rationale_summary, out.evidence_refs
                    res.model, res.fallback_used = model, i > 0
            finally:
                att.latency_ms = int((time.monotonic() - t0) * 1000)
            if att.ok:
                break
        if not any(a.ok for a in res.attempts):
            res.verdict, res.confidence = "unknown", 0.0
            res.rationale_summary = "AI answer unusable (" + "; ".join(
                f"{a.model}: {a.error}" for a in res.attempts) + ")"
            res.rationale_summary = res.rationale_summary[:500]
            res.escalate = "AI answer unusable"
        elif res.verdict == "unknown":
            res.escalate = "AI verdict unknown"
        return res

    def test(self) -> list[dict]:
        steps = [{"step": "settings valid", "ok": True}]
        if self.target == "live":
            steps.append({"step": "secrets set", "ok": bool(self._key), "detail": None if self._key else "api_key"})
            if not self._key:
                return steps
        probe = {"alert_id": "00000000-0000-0000-0000-000000000000", "rule_id": "waf.test.probe", "source": "waf",
                 "severity_hint": "medium", "event_count": 1, "evidence_tokens": ["tok_ip_0000000000000000"],
                 "alert": {"category": "Connection test", "entities": {"src_ip": "tok_ip_0000000000000000"}}}
        r = self.triage(probe, None, 0)
        for a in r.attempts:
            steps.append({"step": f"model {a.model} answers in schema", "ok": a.ok, "detail": a.error,
                          "latency_ms": a.latency_ms})
        if self.target == "mock":
            steps.append({"step": "mock target (sandbox): no call made", "ok": True})
        return steps

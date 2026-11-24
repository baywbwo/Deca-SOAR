from datetime import UTC, datetime

import pytest

from deca_soar.common.config import DEFAULT_INTERNAL_CIDRS, _cidrs
from deca_soar.common.pii import TOKEN_RE, Tokenizer, Vault, tokens_in
from deca_soar.gateway.normalize import NormalizeError, normalize

KEY = b"\x01" * 32


def tok() -> Tokenizer:
    return Tokenizer(KEY, _cidrs(DEFAULT_INTERNAL_CIDRS))


def test_tokens_are_deterministic_and_keyed():
    a, b = tok().token("ip", "203.0.113.7"), tok().token("ip", "203.0.113.7")
    assert a == b and TOKEN_RE.fullmatch(a)
    assert Tokenizer(b"\x09" * 32).token("ip", "203.0.113.7") != a
    assert tok().token("user", "203.0.113.7") != a  # kind is part of the MAC


def test_internal_ip_stays_raw_external_is_tokenised():
    t = tok()
    assert t.token_ip("10.1.2.3") == "10.1.2.3"
    assert t.token_ip("203.0.113.7").startswith("tok_ip_")


def test_scrub_removes_pii_and_secrets():
    t = tok()
    text = (
        "/login?user=a&token=s3cr3tvalue&x=1 from 203.0.113.9 mail Budi.S@Example.co.id "
        "hp 0812-3456-7890 card 4111111111111111 nik 3171234567890123 ak LTAI5tAbCdEfGhIjKlMn "
        "Authorization: Bearer abcdefghijklmnop"
    )
    out = t.scrub(text)
    for raw in ("s3cr3tvalue", "203.0.113.9", "Budi.S@Example.co.id", "0812-3456-7890", "4111111111111111",
                "3171234567890123", "LTAI5tAbCdEfGhIjKlMn", "abcdefghijklmnop"):
        assert raw not in out
    kinds = {v[0] for v in t.found.values()}
    assert {"secret", "ip", "email", "phone", "card", "nik", "ak"} <= kinds
    # Existing tokens survive a second pass untouched (no re-tokenising of their hex digests).
    assert t.scrub(out) == out


def test_ipv6_tokenised():
    t = tok()
    out = t.scrub("src 2001:db8::1 and ::1")
    assert "2001:db8::1" not in out
    assert "::1" in out  # loopback is internal


def _raw(**kw):
    base = {"source": "waf", "rule_id": "waf.sqli", "severity_hint": "high",
            "detected_at": "2026-11-24T03:00:10Z", "src_ip": "203.0.113.7",
            "uri": "/api/v1/user?id=1%27%20OR%201=1&email=a@b.co", "ua": "sqlmap/1.7"}
    base.update(kw)
    return base


def test_normalize_tokenises_and_collects_evidence():
    na = normalize(_raw(), tok(), source_name="replay")
    assert na.alert["entities"]["src_ip"].startswith("tok_ip_")
    assert "203.0.113.7" not in str(na.alert) and "a@b.co" not in str(na.alert)
    assert na.alert["entities"]["src_ip"] in na.evidence_tokens
    assert all(TOKEN_RE.fullmatch(x) for x in na.evidence_tokens)


def test_fingerprint_dedups_within_window_only():
    a = normalize(_raw(), tok(), source_name="r")
    b = normalize(_raw(detected_at="2026-11-24T03:04:00Z"), tok(), source_name="r")
    c = normalize(_raw(detected_at="2026-11-24T03:06:00Z"), tok(), source_name="r")
    assert a.fingerprint == b.fingerprint != c.fingerprint
    assert a.alert_id != b.alert_id


def test_access_key_masked_and_tokenised():
    na = normalize(_raw(source="actiontrail", src_ip=None, principal="ops-bot",
                        access_key_id="LTAI5tAbCdEfGhIjKlMn"), tok(), source_name="r")
    ent = na.alert["entities"]
    assert ent["access_key_id"] == "****KlMn"
    assert ent["access_key_token"] in na.evidence_tokens and ent["principal"] in na.evidence_tokens


@pytest.mark.parametrize("bad", [{"source": "x"}, {"rule_id": ""}, {"severity_hint": "urgent"},
                                 {"detected_at": None}, {"src_ip": "not-an-ip"}])
def test_normalize_rejects_bad_input(bad):
    with pytest.raises((NormalizeError, ValueError)):
        normalize(_raw(**bad), tok(), source_name="r")


def test_vault_roundtrip_and_aad_binding(conn):
    t = tok()
    token = t.token("ip", "203.0.113.7")
    v = Vault(b"\x02" * 32)
    with conn.transaction():
        v.store(conn, t.found)
    assert v.reveal(conn, token) == "203.0.113.7"
    row = conn.execute("SELECT ciphertext FROM vault.token_map WHERE token = %s", (token,)).fetchone()
    assert b"203.0.113.7" not in bytes(row["ciphertext"])
    # A ciphertext moved under another token fails authentication.
    other = t.token("ip", "203.0.113.8")
    with conn.transaction():
        conn.execute("INSERT INTO vault.token_map SELECT %s, kind, key_id, nonce, ciphertext FROM vault.token_map"
                     " WHERE token = %s", (other, token))
    with pytest.raises(Exception):
        v.reveal(conn, other)


def test_tokens_in():
    assert tokens_in(["x tok_ip_0123456789abcdef y", None or "", "tok_ip_0123456789abcdef"]) == [
        "tok_ip_0123456789abcdef"]
    assert datetime.now(UTC)

import copy
from pathlib import Path

import pytest
import yaml

from hypersoar.broker import catalog, roles
from hypersoar.broker.roles import Principal

POLICY = Path(__file__).resolve().parents[1] / "policy"


def test_real_catalog_loads():
    cat, prot = catalog.load(POLICY)
    assert {"waf.ip_blacklist.add", "ram.access_key.disable", "case.close_benign"} <= set(cat)
    assert all(a.level in ("L0", "L1") or a.mode == "approval" for a in cat.values())
    assert prot.has_placeholders


def _doc():
    return yaml.safe_load((POLICY / "actions.yaml").read_text())


@pytest.mark.parametrize("mutate", [
    lambda d: d["actions"]["ram.access_key.disable"].update(mode="auto"),           # L2 must need approval
    lambda d: d["actions"]["waf.ip_blacklist.add"].pop("rate_limit"),               # L1 needs a limit
    lambda d: d["actions"]["waf.ip_blacklist.add"].pop("target"),                   # token param w/o target
    lambda d: d["actions"]["waf.ip_blacklist.add"]["params"]["waf_instance"].pop("pattern"),
    lambda d: d["actions"]["itsm.create_ticket"].update(min_confidence=2),
    lambda d: d["actions"]["itsm.create_ticket"]["params"]["team"].update(evil=1),
])
def test_bad_catalog_rejected(mutate):
    d = copy.deepcopy(_doc())
    mutate(d)
    with pytest.raises(catalog.CatalogError):
        catalog.parse_catalog(d)


def P(role, kind="human", pid="p1"):
    return Principal(pid, "n", kind, role)


def test_role_matrix():
    assert roles.allowed(P("viewer"), roles.READ) and not roles.allowed(P("viewer"), roles.REQUEST_ACTION)
    assert roles.allowed(P("analyst"), roles.REQUEST_ACTION) and not roles.allowed(P("analyst"), roles.APPROVE)
    assert roles.allowed(P("approver"), roles.APPROVE) and not roles.allowed(P("approver"), roles.KILL_SWITCH)
    assert roles.allowed(P("admin"), roles.KILL_SWITCH)
    assert not roles.allowed(P("bogus"), roles.READ)


def test_service_principals_never_approve_or_kill():
    for r in roles.ROLES:
        assert not roles.allowed(P(r, "service"), roles.APPROVE)
        assert not roles.allowed(P(r, "service"), roles.KILL_SWITCH)


def test_no_self_approval():
    a = P("approver", pid="same")
    assert not roles.can_approve(a, "same") and roles.can_approve(a, "other")

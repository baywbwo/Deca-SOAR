"""Preflight gates added for the second security review (N1, N2, N3)."""

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "python:3.12-slim-bookworm@sha256:" + "ab" * 32


@pytest.fixture
def pf():
    spec = importlib.util.spec_from_file_location("preflight", ROOT / "scripts/preflight.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _status(pf, fragment: str) -> list[str]:
    return [s for s, msg in pf.results if fragment in msg]


def _env(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "deca.env"
    p.write_text(text)
    p.chmod(0o600)
    return p


# N3: base image digest ----------------------------------------------------------------------------

def test_n3_placeholder_digest_fails_in_production(pf):
    pf.base_image(True, None)
    assert _status(pf, "DECA_BASE_IMAGE pinned") == ["FAIL"]


def test_n3_placeholder_digest_only_warns_outside_production(pf):
    pf.base_image(False, None)
    assert _status(pf, "DECA_BASE_IMAGE pinned") == ["WARN"]


@pytest.mark.parametrize("value,expect", [
    (DIGEST, "PASS"),
    ("python:3.12-slim-bookworm@sha256:REPLACE_WITH_PINNED_DIGEST", "FAIL"),
    ("python:3.12-slim-bookworm", "FAIL"),
    ("python:3.12-slim-bookworm@sha256:" + "AB" * 32, "FAIL"),
    ("python:3.12-slim-bookworm@sha256:" + "ab" * 31, "FAIL"),
])
def test_n3_digest_from_production_env(pf, tmp_path, value, expect):
    pf.base_image(True, _env(tmp_path, f"DECA_BASE_IMAGE={value}\n"))
    assert _status(pf, "DECA_BASE_IMAGE pinned") == [expect]


def test_n3_production_flag_is_implied_by_env(pf, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["preflight", "--env", str(_env(tmp_path, "DECA_BIND_IP=10.0.0.9\n"))])
    assert pf.main() == 1
    assert "FAIL  image: DECA_BASE_IMAGE pinned by sha256 digest" in capsys.readouterr().out


# N3: hash locks -----------------------------------------------------------------------------------

def test_n3_repo_locks_pass(pf):
    pf.static_locks()
    assert [s for s, m in pf.results if s != "PASS"] == [], pf.results


def _copy_locks(tmp_path: Path) -> Path:
    d = tmp_path / "req"
    shutil.copytree(ROOT / "deploy/deca/requirements", d)
    return d


def test_n3_range_pin_fails(pf, tmp_path):
    d = _copy_locks(tmp_path)
    (d / "runtime.lock").write_text((d / "runtime.lock").read_text().replace("fastapi==0.", "fastapi>=0.", 1))
    pf.static_locks(d)
    assert _status(pf, "runtime.lock: every package pinned") == ["FAIL"]


def test_n3_missing_hash_fails(pf, tmp_path):
    d = _copy_locks(tmp_path)
    (d / "build.lock").write_text("hatchling==1.33.0\n")
    pf.static_locks(d)
    assert _status(pf, "build.lock: every package pinned") == ["FAIL"]


def test_n3_dependency_missing_from_lock_fails(pf, tmp_path):
    d = _copy_locks(tmp_path)
    py = tmp_path / "pyproject.toml"
    py.write_text((ROOT / "pyproject.toml").read_text().replace('"httpx>=0.27,<1",', '"httpx>=0.27,<1", "requests>=2",'))
    pf.static_locks(d, pyproject=py)
    assert _status(pf, "covers every pyproject dependency") == ["FAIL"]


def test_n3_unlocked_pip_install_in_dockerfile_fails(pf, tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text((ROOT / "deploy/deca/Dockerfile").read_text() + "RUN pip install requests\n")
    pf.static_locks(dockerfile=df)
    assert _status(pf, "only via install-locked.sh") == ["FAIL"]

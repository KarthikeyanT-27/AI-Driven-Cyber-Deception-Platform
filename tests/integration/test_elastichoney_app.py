"""
tests/integration/test_elastichoney_app.py

Exercises the real Elastichoney FastAPI app end-to-end (no mocking needed —
it has no external dependencies besides a writable log directory, which we
point at a tmp_path for the test).
"""

import importlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ELASTICHONEY_DIR = Path(__file__).resolve().parent.parent.parent / "sensor_layer" / "elastichoney"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ELASTICHONEY_LOG_DIR", str(tmp_path))
    sys.path.insert(0, str(ELASTICHONEY_DIR))
    if "app" in sys.modules:
        del sys.modules["app"]
    app_module = importlib.import_module("app")
    importlib.reload(app_module)  # pick up the patched env var
    with TestClient(app_module.app) as c:
        yield c, tmp_path
    sys.path.remove(str(ELASTICHONEY_DIR))


def _read_log_lines(tmp_path) -> list[dict]:
    log_file = tmp_path / "elastichoney.json"
    if not log_file.exists():
        return []
    return [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]


def test_health_endpoint_not_logged(client):
    c, tmp_path = client
    resp = c.get("/health")
    assert resp.status_code == 200
    assert _read_log_lines(tmp_path) == []  # health checks shouldn't show up as "attacks"


def test_root_probe_is_logged(client):
    c, tmp_path = client
    resp = c.get("/")
    assert resp.status_code == 200
    assert "cluster_name" in resp.json()
    lines = _read_log_lines(tmp_path)
    assert len(lines) == 1
    assert lines[0]["event_type"] == "recon_root"


def test_script_injection_attempt_flagged(client):
    c, tmp_path = client
    resp = c.post("/_search", json={"script": "Runtime.getRuntime().exec('id')"})
    assert resp.status_code == 200
    lines = _read_log_lines(tmp_path)
    assert any(l["event_type"] == "rce_script_injection_attempt" for l in lines)


def test_benign_search_not_flagged_as_rce(client):
    c, tmp_path = client
    resp = c.post("/_search", json={"query": {"match_all": {}}})
    assert resp.status_code == 200
    lines = _read_log_lines(tmp_path)
    assert any(l["event_type"] == "query_probe" for l in lines)
    assert not any(l["event_type"] == "rce_script_injection_attempt" for l in lines)


def test_unknown_path_returns_404_and_is_logged(client):
    c, tmp_path = client
    resp = c.get("/some/random/path")
    assert resp.status_code == 404
    lines = _read_log_lines(tmp_path)
    assert any(l["event_type"] == "generic_probe" for l in lines)

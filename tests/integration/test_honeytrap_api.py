"""
tests/integration/test_honeytrap_api.py

Exercises the real HoneyTrap orchestrator FastAPI app with fakeredis
standing in for Redis. Unlike escalation_engine, the lifespan here
performs real I/O at startup (seeding initial honeytokens), so Redis must
be faked *before* the TestClient context manager triggers startup, not
after.
"""

import importlib.util
import sys
import types
from pathlib import Path

import fakeredis.aioredis
import pytest
from fastapi.testclient import TestClient

HONEYTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "honeytrap"


def _load_orchestrator():
    sys.path.insert(0, str(HONEYTRAP_DIR))

    spec = importlib.util.spec_from_file_location("honeytrap_orchestrator", HONEYTRAP_DIR / "orchestrator.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["honeytrap_orchestrator"] = module
    spec.loader.exec_module(module)

    # Same shared-module-mutation hazard as escalation_engine: rebind the
    # name, don't mutate the real redis.asyncio module's Redis attribute.
    # A single FakeRedis server instance is shared across the .Redis(...)
    # "connections" the module creates, matching how a real Redis server
    # would be shared across multiple client connections.
    server = fakeredis.aioredis.FakeServer()
    fake_redis_ns = types.SimpleNamespace(
        Redis=lambda *a, **kw: fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    )
    module.aioredis = fake_redis_ns
    return module


@pytest.fixture
def client():
    module = _load_orchestrator()
    with TestClient(module.app) as c:
        yield c
    sys.path.remove(str(HONEYTRAP_DIR))
    del sys.modules["honeytrap_orchestrator"]


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_seeded_tokens_exist_on_startup(client):
    resp = client.get("/tokens")
    assert resp.status_code == 200
    body = resp.json()
    # 5 kinds x 2 seeded each at startup, per orchestrator.py's lifespan
    assert body["count"] == 10


def test_secrets_are_redacted_in_listing(client):
    resp = client.get("/tokens")
    tokens = resp.json()["tokens"]
    for token in tokens:
        for secret_field in ("secret_access_key", "token", "password", "private_key"):
            if secret_field in token:
                assert "REDACTED" in token[secret_field]


def test_generate_unknown_kind_rejected(client):
    resp = client.post("/tokens/generate", json={"kind": "not_a_kind", "count": 1})
    assert resp.status_code == 400


def test_generate_new_tokens(client):
    resp = client.post("/tokens/generate", json={"kind": "aws_key", "count": 3})
    assert resp.status_code == 200
    assert resp.json()["generated"] == 3


def test_access_unknown_token_404s(client):
    resp = client.post("/tokens/nonexistent-id/access", json={"source_ip": "1.2.3.4"})
    assert resp.status_code == 404


def test_access_report_raises_alert(client):
    tokens = client.get("/tokens").json()["tokens"]
    token_id = tokens[0]["id"]

    resp = client.post(f"/tokens/{token_id}/access", json={
        "source_ip": "203.0.113.9", "honeypot": "cowrie", "detail": "exfiltrated via scp",
    })
    assert resp.status_code == 200
    assert resp.json()["alert_raised"] is True

    alerts = client.get("/alerts").json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["token_id"] == token_id
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["source_ip"] == "203.0.113.9"

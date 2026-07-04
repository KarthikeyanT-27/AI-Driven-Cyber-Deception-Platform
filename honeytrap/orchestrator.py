"""
honeytrap/orchestrator.py

Responsibilities (per spec):
  - Generate fake credentials / AWS keys / API tokens / SSH keys / DB dumps
  - Track access attempts against them
  - Raise alerts when a honeytoken is touched

Honeytokens are generated on a schedule (HONEYTOKEN_REFRESH_HOURS) and
on-demand, stored in Redis (source of truth + TTL-based rotation) and
mirrored to a JSON file under /app/data for any honeypot integration that
wants to drop them into a decoy filesystem (e.g. Cowrie's honeyfs).

"Access tracking" here means: any external caller (telemetry, a honeypot
plugin, or a manual test) reports that a specific honeytoken value was
observed being read/used, via POST /tokens/{id}/access. That's the
trip-wire — a legitimate service never touches these values, so any hit
is by definition an alert-worthy event.

Exposes:
  GET  /health
  POST /tokens/generate         -> create N honeytokens of a given kind
  GET  /tokens                   -> list active honeytokens (redacted)
  POST /tokens/{token_id}/access -> record an access attempt -> alert
  GET  /alerts                   -> recent alerts
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from generators import GENERATORS, generate_token

logging.basicConfig(level=logging.INFO, format="%(asctime)s [honeytrap] %(levelname)s %(message)s")
log = logging.getLogger("honeytrap")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
REFRESH_HOURS = int(os.getenv("HONEYTOKEN_REFRESH_HOURS", "24"))
DATA_DIR = Path("/app/data")
TOKEN_REDIS_PREFIX = "honeytoken:"
ALERT_LIST_KEY = "honeytrap:alerts"
DEFAULT_KINDS = list(GENERATORS.keys())


async def refresh_loop(app: FastAPI):
    # lifespan() already seeds the initial batch synchronously before this
    # task is created — sleep first so we don't immediately duplicate that
    # seeding on startup.
    while True:
        await asyncio.sleep(REFRESH_HOURS * 3600)
        try:
            for kind in DEFAULT_KINDS:
                await _generate_and_store(app, kind, count=2)
            log.info("Honeytoken refresh cycle complete (%s kinds).", len(DEFAULT_KINDS))
        except Exception:
            log.exception("Honeytoken refresh cycle failed")


async def _generate_and_store(app: FastAPI, kind: str, count: int = 1) -> list[dict]:
    tokens = []
    for _ in range(count):
        token = generate_token(kind)
        await app.state.redis.set(f"{TOKEN_REDIS_PREFIX}{token['id']}", json.dumps(token))
        tokens.append(token)
    _mirror_to_disk(app)
    return tokens


def _mirror_to_disk(app: FastAPI) -> None:
    """Best-effort snapshot to disk for honeypot decoy-filesystem integration."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with (DATA_DIR / "active_honeytokens.json").open("w") as f:
            json.dump({"generated_at": datetime.now(timezone.utc).isoformat()}, f)
    except Exception as exc:
        log.warning("Could not mirror honeytokens to disk: %s", exc)


def _redact(token: dict) -> dict:
    redacted = dict(token)
    for secret_field in ("secret_access_key", "token", "password", "private_key"):
        if secret_field in redacted:
            redacted[secret_field] = redacted[secret_field][:6] + "…REDACTED"
    return redacted


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = aioredis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD or None, decode_responses=True
    )
    # Seed an initial batch on cold start so /tokens isn't empty for the demo.
    for kind in DEFAULT_KINDS:
        await _generate_and_store(app, kind, count=2)
    app.state.refresh_task = asyncio.create_task(refresh_loop(app))
    log.info("HoneyTrap orchestrator ready. Seeded %s honeytoken kinds.", len(DEFAULT_KINDS))
    yield
    app.state.refresh_task.cancel()
    await app.state.redis.aclose()


app = FastAPI(title="HoneyTrap Orchestrator", version="1.0.0", lifespan=lifespan)


class GenerateRequest(BaseModel):
    kind: str
    count: int = 1


class AccessReport(BaseModel):
    source_ip: str | None = None
    honeypot: str | None = None
    detail: str | None = None


@app.get("/health")
async def health():
    return {"status": "ok", "service": "honeytrap"}


@app.post("/tokens/generate")
async def generate(req: GenerateRequest):
    if req.kind not in GENERATORS:
        raise HTTPException(status_code=400, detail=f"Unknown kind. Valid: {list(GENERATORS.keys())}")
    tokens = await _generate_and_store(app, req.kind, req.count)
    return {"generated": len(tokens), "tokens": [_redact(t) for t in tokens]}


@app.get("/tokens")
async def list_tokens():
    keys = await app.state.redis.keys(f"{TOKEN_REDIS_PREFIX}*")
    tokens = []
    for key in keys:
        raw = await app.state.redis.get(key)
        if raw:
            tokens.append(_redact(json.loads(raw)))
    return {"count": len(tokens), "tokens": tokens}


@app.post("/tokens/{token_id}/access")
async def report_access(token_id: str, report: AccessReport):
    raw = await app.state.redis.get(f"{TOKEN_REDIS_PREFIX}{token_id}")
    if not raw:
        raise HTTPException(status_code=404, detail="Unknown honeytoken id")

    token = json.loads(raw)
    alert = {
        "alert_type": "honeytoken_access",
        "token_id": token_id,
        "token_kind": token.get("type"),
        "source_ip": report.source_ip,
        "honeypot": report.honeypot,
        "detail": report.detail,
        "severity": "critical",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await app.state.redis.lpush(ALERT_LIST_KEY, json.dumps(alert))
    await app.state.redis.ltrim(ALERT_LIST_KEY, 0, 499)
    log.warning("HONEYTOKEN ALERT: %s", alert)
    return {"alert_raised": True, "alert": alert}


@app.get("/alerts")
async def recent_alerts(limit: int = 50):
    raw = await app.state.redis.lrange(ALERT_LIST_KEY, 0, limit - 1)
    return {"count": len(raw), "alerts": [json.loads(a) for a in raw]}

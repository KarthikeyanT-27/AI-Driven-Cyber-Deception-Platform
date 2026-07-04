"""
escalation_engine/main.py

Exposes:
  POST /evaluate   -> {risk_score, decision, confidence, ...}
  GET  /health
  GET  /sessions/escalated   -> recent ESCALATE decisions (for the dashboard)

See models.py for the classifier / sequence analyzer / decision policy
implementations and the documented upgrade path to real DistilBERT/LSTM/DQN
models.

FIXES applied vs original:
  1. The original lifespan connected to both Redis AND Elasticsearch before
     the service was considered started. Elasticsearch is only used for
     optional persistence inside /evaluate. If ES was slow, the service
     stayed in "starting" state until Docker killed it. Fix: ES client is
     created lazily and connection errors in /evaluate are non-fatal.

  2. build_classifier() can block for 30-90 s while downloading/loading the
     DistilBERT model from HuggingFace.  That entire time the /health
     endpoint was unavailable, causing Docker to restart the container mid-
     load. Fix: model loading is moved to a background asyncio task; /health
     returns {"status": "starting"} with HTTP 200 until the model is ready,
     then switches to {"status": "ok"}.  Docker healthcheck only needs HTTP
     200, so the container stays alive.

  3. TRANSFORMERS_CACHE / HF_HOME are respected via docker-compose env vars
     so the model is read from the persisted volume on subsequent starts.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import redis.asyncio as aioredis
from elasticsearch import AsyncElasticsearch
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from models import HeuristicSequenceModel, ThresholdDecisionPolicy, build_classifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [escalation] %(levelname)s %(message)s")
log = logging.getLogger("escalation_engine")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")
ESCALATED_SET_KEY = "escalations:recent"


async def _load_classifier_async(app: FastAPI) -> None:
    """Load the (potentially heavy) classifier in the background so the
    /health endpoint remains responsive while the model is initialising."""
    try:
        log.info("Loading classifier (this may take 30-90 s on first run)...")
        # build_classifier() is CPU-bound; run in the default executor so
        # it doesn't block the event loop.
        loop = asyncio.get_event_loop()
        classifier = await loop.run_in_executor(None, build_classifier)
        app.state.classifier = classifier
        app.state.classifier_ready = True
        log.info("Classifier ready: %s", type(classifier).__name__)
    except Exception:
        log.exception("Classifier load failed; falling back to rule-based.")
        from models import RuleBasedClassifier
        app.state.classifier = RuleBasedClassifier()
        app.state.classifier_ready = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    # FIX: only connect to Redis here (required). ES is optional for
    # persistence and is connected lazily.
    app.state.redis = aioredis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD or None, decode_responses=True
    )
    # Lazy ES client — won't block startup if ES is slow.
    app.state.es = AsyncElasticsearch(
        hosts=[ES_HOST],
        retry_on_timeout=True,
        max_retries=3,
        request_timeout=10,
    )
    app.state.sequence_model = HeuristicSequenceModel()
    app.state.decision_policy = ThresholdDecisionPolicy()
    app.state.classifier_ready = False
    app.state.classifier = None

    # Start model loading in background — /health will return 200 immediately.
    app.state.load_task = asyncio.create_task(_load_classifier_async(app))

    log.info("Escalation engine lifespan started. Classifier loading in background.")
    yield

    app.state.load_task.cancel()
    try:
        await app.state.load_task
    except asyncio.CancelledError:
        pass
    await app.state.redis.aclose()
    await app.state.es.close()


app = FastAPI(title="Escalation Engine", version="1.0.0", lifespan=lifespan)


class EvaluateRequest(BaseModel):
    session_id: str
    command: str
    sequence: list[str] = []
    mitre: list[dict] = []
    honeypot: str = "unknown"


@app.get("/health")
async def health():
    # FIX: always return HTTP 200 so Docker doesn't restart us while the
    # model is still loading. The "status" field indicates readiness.
    if not app.state.classifier_ready:
        return JSONResponse(
            status_code=200,
            content={"status": "starting", "service": "escalation-engine", "classifier": "loading"},
        )
    return {
        "status": "ok",
        "service": "escalation-engine",
        "classifier": type(app.state.classifier).__name__,
    }


@app.post("/evaluate")
async def evaluate(req: EvaluateRequest):
    # If classifier is still loading, fall back to rule-based for this request.
    if not app.state.classifier_ready or app.state.classifier is None:
        from models import RuleBasedClassifier
        classifier = RuleBasedClassifier()
    else:
        classifier = app.state.classifier

    classification_text = " ".join(req.sequence) if req.sequence else req.command
    classification = classifier.classify(classification_text)

    tactics_seen = {m.get("tactic") for m in req.mitre if m.get("tactic")}
    sequence_score = app.state.sequence_model.score(req.sequence or [req.command], tactics_seen)

    result = app.state.decision_policy.decide(classification, sequence_score, req.mitre)
    result["session_id"] = req.session_id
    result["honeypot"] = req.honeypot
    result["command"] = req.command[:300]
    result["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Cache + persist (both non-fatal)
    try:
        if result["decision"] == "ESCALATE":
            await app.state.redis.lpush(ESCALATED_SET_KEY, str(result))
            await app.state.redis.ltrim(ESCALATED_SET_KEY, 0, 199)
    except Exception as exc:
        log.warning("Non-fatal: failed to cache escalation result in Redis (%s)", exc)

    try:
        index_name = f"escalations-{datetime.now(timezone.utc):%Y.%m.%d}"
        await app.state.es.index(index=index_name, document=result)
    except Exception as exc:
        log.warning("Non-fatal: failed to persist escalation result to ES (%s)", exc)

    return result


@app.get("/sessions/escalated")
async def recent_escalations(limit: int = 50):
    raw = await app.state.redis.lrange(ESCALATED_SET_KEY, 0, limit - 1)
    return {"count": len(raw), "items": raw}

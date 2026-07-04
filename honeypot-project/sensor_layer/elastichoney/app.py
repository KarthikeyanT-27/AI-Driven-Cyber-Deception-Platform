"""
Elastichoney (custom lightweight reimplementation)
---------------------------------------------------
The original jordan-wright/elastichoney project is unmaintained and predates
modern Elasticsearch APIs. This is a small FastAPI service that mimics an
exposed, outdated Elasticsearch node closely enough to attract and log:

  - reconnaissance probes (GET /, GET /_cluster/health, GET /_cat/indices)
  - scripted RCE attempts against the old Groovy scripting engine
    (POST /_search with a "script" field — CVE-2014-3120 / CVE-2015-1427 style)
  - generic CRUD / index enumeration probing

Every request is captured and written as one JSON line to
/var/log/elastichoney/elastichoney.json, which Filebeat tails into the
pipeline exactly like Cowrie/Dionaea output.
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

APP_PORT = int(os.getenv("PORT", "9201"))
LOG_DIR = Path(os.getenv("ELASTICHONEY_LOG_DIR", "/var/log/elastichoney"))
LOG_FILE = LOG_DIR / "elastichoney.json"

app = FastAPI(title="elastichoney", version="1.0.0")

FAKE_CLUSTER_NAME = "prod-logging-cluster"
FAKE_ES_VERSION = "1.4.2"  # deliberately old/vulnerable-looking, bait for CVE scanners
FAKE_INDICES = ["logs-2026.06", "logs-2026.05", "users", "internal-audit"]


def _ensure_log_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if not LOG_FILE.exists():
        LOG_FILE.touch()


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def log_event(request: Request, event_type: str, extra: dict | None = None) -> None:
    """Append one structured JSON record for this interaction."""
    try:
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="replace")[:4000]
    except Exception:
        body_text = ""

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "honeypot": "elastichoney",
        "event_type": event_type,
        "src_ip": _client_ip(request),
        "method": request.method,
        "path": request.url.path,
        "query": str(request.url.query),
        "headers": dict(request.headers),
        "body": body_text,
    }
    if extra:
        record.update(extra)

    _ensure_log_dir()
    with LOG_FILE.open("a") as f:
        f.write(json.dumps(record) + "\n")


@app.get("/health")
async def health():
    # Internal compose healthcheck — not logged as attacker activity.
    return {"status": "ok", "service": "elastichoney"}


@app.get("/")
async def root(request: Request):
    await log_event(request, "recon_root")
    return JSONResponse({
        "name": "es-node-01",
        "cluster_name": FAKE_CLUSTER_NAME,
        "version": {"number": FAKE_ES_VERSION, "lucene_version": "4.10.2"},
        "tagline": "You Know, for Search",
    })


@app.get("/_cluster/health")
async def cluster_health(request: Request):
    await log_event(request, "recon_cluster_health")
    return JSONResponse({
        "cluster_name": FAKE_CLUSTER_NAME,
        "status": "yellow",
        "number_of_nodes": 1,
        "number_of_data_nodes": 1,
    })


@app.get("/_cat/indices")
async def cat_indices(request: Request):
    await log_event(request, "recon_indices")
    body = "\n".join(f"yellow open {idx} 5 1" for idx in FAKE_INDICES)
    return JSONResponse({"indices": FAKE_INDICES, "raw": body})


@app.post("/_search")
@app.get("/_search")
async def search(request: Request):
    """
    This is the classic exploitation surface: old ES versions accepted a
    "script" field that executed arbitrary Groovy/MVEL. We don't execute
    anything — we just flag the attempt and return a believable fake result.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    is_script_injection = isinstance(payload, dict) and "script" in json.dumps(payload)
    event_type = "rce_script_injection_attempt" if is_script_injection else "query_probe"

    await log_event(request, event_type, extra={"parsed_payload_keys": list(payload.keys()) if isinstance(payload, dict) else []})

    return JSONResponse({
        "took": 3,
        "timed_out": False,
        "hits": {"total": 0, "max_score": None, "hits": []},
    })


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
async def catch_all(full_path: str, request: Request):
    await log_event(request, "generic_probe", extra={"requested_path": full_path})
    return JSONResponse({"error": "index_not_found_exception", "status": 404}, status_code=404)

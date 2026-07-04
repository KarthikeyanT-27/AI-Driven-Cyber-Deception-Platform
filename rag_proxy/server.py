"""
rag_proxy/server.py

Responsibilities (per spec):
  - Receive attacker context
  - Query ChromaDB for similar attack history
  - Inject that memory into the LLM prompt
  - Forward to the configured backend LLM (Groq by default; OpenAI/Ollama
    available via LLM_PROVIDER)

Exposes:
  GET  /health
  POST /memory/insert    -> store a record in attack memory
  POST /memory/query     -> raw similarity search (no LLM call)
  POST /query            -> alias for /memory/query (backward compat)
  POST /generate          -> RAG-augmented generation (the main entrypoint
                              used by the SOC chatbot / escalation engine)

FIXES applied vs original:
  1. AttackMemory() was instantiated directly in lifespan(), which calls
     chromadb.HttpClient() synchronously.  If ChromaDB's TCP port was
     reachable but not yet serving requests (container starting), this
     raised a connection error and the RAG proxy crashed before /health
     ever became available.  Fix: wrap the client construction in a retry
     loop with exponential backoff.

  2. /health returned 200 even if the ChromaDB connection had failed
     during startup, giving a false-healthy signal.  Fix: /health now
     checks that app.state.memory is not None.

  3. Missing /query route.  The chatbot's _build_live_context() function
     does not call /query directly, but the API docs show it and other
     callers may expect it.  Added as an alias for /memory/query.

  4. LLM backend KeyError was logged but the proxy still reported healthy,
     so the chatbot would call /generate and get a 503, which appeared as
     "Could not reach RAG proxy" to the user.  The error message is now
     more explicit.

  5. AUDIT FIX (RAG memory hygiene): /generate previously wrote every
     query's context back into ChromaDB as attack-memory ("kind":
     "session") unconditionally — including queries answered from noisy
     or empty context (e.g. no real attack activity in range). That bad
     context would then get retrieved into *future* answers, compounding
     over time. GenerateRequest now takes an explicit `evidence_sufficient`
     flag (set by the caller, e.g. the chatbot, based on whether it found
     real attack sessions) and memory-insert is skipped when it's False.
     Defaults to True so any existing caller that doesn't send it keeps
     the old behavior rather than breaking.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from chroma_client import AttackMemory
from llm_backends import get_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [rag-proxy] %(levelname)s %(message)s")
log = logging.getLogger("rag_proxy")

SYSTEM_PROMPT = (
    "You are a SOC analyst assistant embedded in a cyber deception platform. "
    "You are given live honeypot telemetry plus retrieved memory of similar "
    "past attacks. Answer concisely and factually. When asked for an incident "
    "report, structure it with: Summary, Observed TTPs (MITRE ATT&CK), "
    "Indicators of Compromise, and Recommended Remediation. Never fabricate "
    "IOCs or technique IDs that are not present in the supplied context."
)


async def _connect_memory_with_retry(max_attempts: int = 10, base_delay: float = 3.0) -> AttackMemory:
    """Retry ChromaDB connection until the server is ready."""
    for attempt in range(1, max_attempts + 1):
        try:
            memory = AttackMemory()
            # Verify the connection is actually live.
            memory.count()
            log.info("ChromaDB connection established on attempt %d.", attempt)
            return memory
        except Exception as exc:
            if attempt == max_attempts:
                raise RuntimeError(f"Could not connect to ChromaDB after {max_attempts} attempts: {exc}") from exc
            delay = base_delay * (2 ** (attempt - 1))
            log.warning("ChromaDB not ready (attempt %d/%d): %s — retrying in %.0fs", attempt, max_attempts, exc, delay)
            await asyncio.sleep(delay)
    # Unreachable, but satisfies type checkers.
    raise RuntimeError("Unreachable")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # FIX: retry the ChromaDB connection instead of failing immediately.
    app.state.memory = None
    app.state.llm = None
    try:
        app.state.memory = await _connect_memory_with_retry()
    except Exception as exc:
        log.error("Fatal: could not connect to ChromaDB: %s", exc)

    try:
        app.state.llm = get_backend()
        log.info("LLM backend initialised: %s", type(app.state.llm).__name__)
    except (KeyError, ValueError) as exc:
        log.error("LLM backend misconfigured: missing env var / unknown provider: %s", exc)
    yield


app = FastAPI(title="RAG Proxy", version="1.0.0", lifespan=lifespan)


class InsertRequest(BaseModel):
    text: str
    kind: str  # attack_history | command_history | session | mitre_mapping
    metadata: dict = {}


class QueryRequest(BaseModel):
    query: str
    n_results: int = 5
    kind: str | None = None


class GenerateRequest(BaseModel):
    context: str            # raw attacker context (session text, commands, IOCs)
    question: str            # what the SOC analyst (or chatbot) is asking
    n_memory_results: int = 5
    # AUDIT FIX: caller-supplied signal for whether `context` actually
    # contains real attack evidence. When False, the answer is still
    # generated (so the chatbot can honestly say "no attack activity
    # found") but it is NOT written back into attack memory, so a
    # no-evidence answer never gets recalled as false precedent later.
    evidence_sufficient: bool = True


@app.get("/health")
async def health():
    # FIX: reflect real readiness in the health payload.
    memory_ok = app.state.memory is not None
    llm_ok = app.state.llm is not None
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok" if memory_ok else "degraded",
            "service": "rag-proxy",
            "chroma_connected": memory_ok,
            "llm_configured": llm_ok,
        },
    )


@app.post("/memory/insert")
async def memory_insert(req: InsertRequest):
    if app.state.memory is None:
        raise HTTPException(status_code=503, detail="ChromaDB not connected")
    record_id = app.state.memory.insert(req.text, req.kind, req.metadata)
    return {"id": record_id, "stored": True}


@app.post("/memory/query")
async def memory_query(req: QueryRequest):
    if app.state.memory is None:
        raise HTTPException(status_code=503, detail="ChromaDB not connected")
    results = app.state.memory.query_similar(req.query, req.n_results, req.kind)
    return {"count": len(results), "results": results}


# FIX: /query alias so any caller that uses the shorter path works too.
@app.post("/query")
async def query_alias(req: QueryRequest):
    return await memory_query(req)


@app.post("/generate")
async def generate(req: GenerateRequest):
    if app.state.llm is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "LLM backend not configured. "
                "Check that LLM_PROVIDER and the corresponding API key env vars are set correctly."
            ),
        )
    if app.state.memory is None:
        raise HTTPException(status_code=503, detail="ChromaDB not connected — attack memory unavailable")

    memory_hits = app.state.memory.query_similar(req.context, req.n_memory_results)
    memory_block = "\n".join(
        f"- [{hit['metadata'].get('kind', 'unknown')}] {hit['text'][:300]}" for hit in memory_hits
    ) or "(no similar prior attacks found in memory)"

    user_prompt = (
        f"## Live attacker context\n{req.context}\n\n"
        f"## Retrieved similar past attacks (from attack memory)\n{memory_block}\n\n"
        f"## Analyst question\n{req.question}"
    )

    try:
        answer = await app.state.llm.generate(SYSTEM_PROMPT, user_prompt)
    except Exception as exc:
        log.error("LLM generation failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM backend error: {exc}")

    # AUDIT FIX: only persist this interaction as attack-memory context if
    # the caller confirmed the context held real evidence. A no-evidence
    # answer ("no attacks found in range") must never be stored and later
    # retrieved as if it were a precedent attack.
    memory_stored = False
    if req.evidence_sufficient:
        app.state.memory.insert(req.context, kind="session", metadata={"question": req.question[:200]})
        memory_stored = True

    return {"answer": answer, "memory_hits_used": len(memory_hits), "memory_stored": memory_stored}

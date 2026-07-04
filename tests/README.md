# Test Suite

Runs entirely without Docker — no real Elasticsearch/Redis/ChromaDB needed.

```bash
pip install -r tests/requirements-test.txt
python3 -m pytest tests/ -v
```

## Structure

- **`tests/unit/`** — pure logic, no I/O. IOC extraction, MITRE mapping,
  the escalation engine's classifier/sequence-model/decision-policy, and
  honeytoken generation.
- **`tests/integration/`** — real FastAPI apps via `TestClient`, with
  Redis faked via `fakeredis` and Elasticsearch faked via a minimal stub
  class (just enough surface for `.index()`/`.search()`/`.close()`).
  Elastichoney needs no faking at all — it has no external dependencies.

## Why this caught real bugs

Building this suite surfaced two genuine logic bugs in the first draft,
both fixed in the current code:

1. **Escalation Engine classified only the single latest command**, not
   the session. A `wget ... && chmod 777 ...` followed by a plain
   `./payload` execution would score as benign, because the classifier
   never saw the `wget`/`chmod`. Fixed by classifying on the joined recent
   sequence instead of just `req.command`.
2. **HoneyTrap double-seeded honeytokens on startup.** The background
   refresh loop didn't sleep before its first iteration, so it immediately
   duplicated the seed batch that `lifespan()` had just generated
   synchronously. Fixed by sleeping first.

This is the value of writing the suite *before* the first real
`docker compose up` — these would otherwise have surfaced as confusing,
hard-to-reproduce behavior during a live demo.

## What's intentionally not covered yet

- **Telemetry's `main.py`** (the ES-polling service) isn't under an
  integration test yet — its background poll loop and the chain of
  Elasticsearch → Redis → HTTP-to-escalation-engine calls would need a
  more involved fake-ES-with-realistic-query-responses setup than the
  others. Its building blocks (`ioc_extractor`, `mitre_mapper`) are fully
  unit tested; the glue code in `main.py` is the gap.
- **RAG Proxy** isn't tested — it talks to a real LLM API (Groq) by
  design, which isn't something to fake convincingly in a unit test
  without just testing the mock instead of the integration.
- **No tests run against the real Cowrie/Dionaea images or the actual
  Filebeat → Logstash → Elasticsearch shipping path.** Those require a
  live Docker stack; see the manual `curl`-based steps in the root
  `README.md`'s Testing section for that layer.

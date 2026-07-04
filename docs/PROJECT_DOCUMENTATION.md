# Project Documentation: AI-Driven Adaptive Cyber Deception and Threat Intelligence Platform

## 1. Abstract

This project implements a research-grade prototype of an adaptive cyber
deception platform. It combines low- and medium-interaction honeypots
(Cowrie, Dionaea, and a purpose-built Elastichoney) with an AI-assisted
analysis pipeline that extracts Indicators of Compromise (IOCs), maps
observed attacker behavior onto the MITRE ATT&CK framework, scores session
risk, and escalates high-risk sessions for analyst attention. A
Retrieval-Augmented Generation (RAG) layer maintains contextual memory of
past attacks in a vector database (ChromaDB) and grounds a SOC analyst
chatbot's answers and incident reports in that memory plus live telemetry.
A honeytoken subsystem plants synthetic credentials and raises alerts the
instant they are touched. The full system runs as a single Docker Compose
stack on commodity hardware.

## 2. Motivation

Traditional honeypots passively log attacker activity; an analyst still
has to manually correlate sessions, map techniques to ATT&CK, and decide
what's worth escalating. This project explores how far that triage can be
automated with a layered, swappable AI pipeline — and, importantly, how to
build that pipeline so each stage's heuristic implementation can later be
replaced by a trained model without touching the surrounding system. That
separation of concerns (interface vs. implementation) is the project's
central design decision and is documented per-class in
`escalation_engine/models.py`.

## 3. System Design

See `docs/ARCHITECTURE.md` for the full data-flow diagram. At a high
level: **Attacker → Sensor Layer → Log Shipping (Filebeat/Logstash) →
Elasticsearch → Telemetry (IOC + MITRE) → Escalation Engine (risk
scoring) → RAG Memory (ChromaDB) → SOC Dashboard/Chatbot**, with HoneyTrap
operating in parallel as an independent trip-wire subsystem.

### 3.1 Network Isolation as a Design Constraint
Honeypots run on a Docker network (`edge_net`) with no route to any
internal service. This isn't incidental — it's the project's threat model
made concrete: a fully compromised honeypot container must not be able to
pivot into the analysis pipeline. Log data crosses that boundary only via
one-way file volumes that Filebeat (sitting on the internal network) tails.

### 3.2 AI Pipeline Staging
The spec called for DistilBERT (command classification), an LSTM
(sequence analysis), and a DQN (escalate/hold decisioning). For this
prototype, each stage is implemented as a documented interface with a
working rule-based/heuristic implementation behind it, plus — for the
classifier specifically — an optional pretrained DistilBERT sentiment
model blended in as an auxiliary signal. This was a deliberate scope
decision (see Section 5) rather than an oversight: no public,
honeypot-labeled command corpus exists to fine-tune a real classifier on,
and training an LSTM/DQN without labeled session outcomes would produce
an unvalidatable model dressed up as a validated one. The heuristic
implementations are themselves principled (keyword tables curated against
real Cowrie/Dionaea attack logs reported in honeypot research, MITRE
ATT&CK technique mappings cross-referenced against the public ATT&CK
matrix) rather than arbitrary placeholders.

### 3.3 Retrieval-Augmented Generation
Every analyst-facing answer or incident report is grounded in two sources:
(1) live telemetry context (recent escalations, recent honeytoken alerts)
and (2) similarity search over previously stored attack memory in
ChromaDB. The system prompt explicitly instructs the LLM not to fabricate
IOCs or technique IDs absent from the supplied context — a basic
hallucination-mitigation measure appropriate for a security tool where
false IOCs have real operational cost.

## 4. Implementation Summary

| Component | Technology | Key file |
|---|---|---|
| Sensor layer | Cowrie, Dionaea, custom FastAPI (Elastichoney) | `sensor_layer/` |
| Log shipping | Filebeat → Logstash → Elasticsearch | `config/` |
| IOC extraction | Python regex + heuristic scoring | `telemetry/ioc_extractor.py` |
| MITRE mapping | Curated keyword → technique table | `telemetry/mitre_mapper.py` |
| Risk scoring | Rule-based classifier (+ optional DistilBERT) → heuristic sequence model → threshold decision policy | `escalation_engine/models.py` |
| Attack memory | ChromaDB | `rag_proxy/chroma_client.py` |
| LLM backend | Groq (swappable: OpenAI/Ollama) | `rag_proxy/llm_backends.py` |
| Honeytokens | Synthetic AWS keys/API tokens/SSH keys/DB dumps | `honeytrap/generators.py` |
| Dashboard | Streamlit + Plotly | `dashboard/chatbot.py` |
| Visualization | Kibana | service in `docker-compose.yml` |

## 5. Limitations and Threats to Validity

1. **No trained ML models.** The classifier, sequence analyzer, and
   decision policy are rule-based/heuristic by design for this iteration
   (see 3.2). Reported "risk scores" reflect curated heuristics, not a
   model validated against ground-truth attacker intent.
2. **Elastichoney is a reimplementation, not the original project**, since
   the original is unmaintained. It captures the same class of
   reconnaissance/exploitation behavior but is not a drop-in for the
   original codebase.
3. **Not yet build-tested end-to-end on a live Docker host** as of this
   document's writing — see `README.md`'s "Status of this build" section.
   An automated pytest suite (`tests/`, 53 tests) does cover the custom
   services' logic without needing Docker, and already caught two real
   bugs during development (see `tests/README.md`), but it cannot
   substitute for verifying the full Cowrie/Dionaea → Filebeat → Logstash
   → Elasticsearch shipping path, which only a live Docker host can do.
4. **Single-node, single-machine deployment.** No distributed Elasticsearch
   cluster, no production-grade auth in front of internal dashboards/APIs.
5. **Honeytoken realism is structural, not behavioral.** Generated keys
   are well-formatted but there is no integration yet placing them inside
   a honeypot's actual decoy filesystem for an attacker to discover
   organically (see README "Known follow-ups").

## 6. Future Work

- Replace heuristic models with trained DistilBERT/LSTM/DQN once labeled
  session data exists (interfaces already support this — see
  `escalation_engine/models.py` docstrings).
- Integrate HoneyTrap output directly into Cowrie's `honeyfs/`.
- Add automated CI testing (container health, API contract tests).
- Expand the MITRE mapping table's coverage and validate against a larger
  corpus of real captured sessions.

## 7. Ethics and Responsible Use

This system is defensive: it captures and analyzes *inbound* attacker
behavior against intentionally exposed decoy services. It does not scan,
exploit, or act against third-party systems. Honeytokens are synthetic and
never valid against real infrastructure. Deployers are responsible for
ensuring honeypots are run in properly isolated network segments and that
data retention/handling complies with applicable law and institutional
policy (captured attacker IPs and session content are personal/network
data in many jurisdictions).

# 🛡️ AI-Driven Adaptive Cyber Deception and Threat Intelligence Platform

> An intelligent cyber deception platform that combines **honeypots, MITRE ATT&CK mapping, IOC extraction, threat intelligence, machine learning, RAG memory, and an AI-powered SOC Analyst Chatbot** to detect, analyze, and explain attacker behavior in real time.

---

## 📌 Project Overview

Modern cyber attacks evolve rapidly, making traditional signature-based detection insufficient.

This project provides an AI-powered cyber deception environment where attackers interact with realistic honeypots while the platform continuously:

- Detects malicious activity
- Extracts Indicators of Compromise (IOCs)
- Maps attacker actions to the MITRE ATT&CK framework
- Correlates attack sessions
- Performs intelligent risk scoring
- Stores attack memory using RAG (Retrieval-Augmented Generation)
- Assists SOC analysts through an AI-powered chatbot

The platform is fully containerized using Docker Compose and integrates the Elastic Stack for centralized monitoring and visualization.

---

# ✨ Key Features

### 🕵️ Multi-Honeypot Environment

- Cowrie (SSH & Telnet)
- Dionaea (Malware & FTP)
- Elastichoney (Elasticsearch Honeypot)

---

### 📊 Threat Intelligence Pipeline

- IOC Extraction
- MITRE ATT&CK Mapping
- Session Correlation
- Risk Scoring
- Attack Timeline Generation

---

### 🤖 AI-Powered SOC Chatbot

- Attack summaries
- Incident reports
- MITRE ATT&CK explanations
- IOC analysis
- Live telemetry awareness
- RAG-backed historical memory

---

### 🍯 Honeytoken Engine

- Automatic token generation
- Token rotation
- Access alerting
- Alert correlation

---

### 📈 Elastic Stack Integration

- Elasticsearch
- Logstash
- Filebeat
- Kibana

---

## 🏗️ Architecture

```
                ┌──────────────┐
                │   Attacker   │
                └──────┬───────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
     Cowrie        Dionaea      Elastichoney
        │              │              │
        └──────────────┼──────────────┘
                       │
                    Filebeat
                       │
                    Logstash
                       │
                Elasticsearch
                       │
                 Telemetry Layer
                       │
          IOC + MITRE + Session Correlation
                       │
              Escalation Engine
                       │
          ChromaDB + RAG Proxy + LLM
                       │
             SOC Analyst Dashboard
```

---

# 🛠️ Technology Stack

## Backend

- Python
- FastAPI
- Docker
- Docker Compose

## Security

- Cowrie
- Dionaea
- Elastichoney
- MITRE ATT&CK

## AI / ML

- ChromaDB
- Groq LLM
- DistilBERT (optional)
- Rule-based Risk Engine

## Monitoring

- Elasticsearch
- Kibana
- Logstash
- Filebeat

---

# 📂 Project Structure

```
dashboard/
telemetry/
rag_proxy/
escalation_engine/
honeytrap/
sensor_layer/
config/
scripts/
tests/
docs/
docker-compose.yml
```

---

# 🚀 Quick Start

## Clone Repository

```bash
git clone https://github.com/KarthikeyanT-27/AI-Driven-Cyber-Deception-Platform.git

cd AI-Driven-Cyber-Deception-Platform
```

---

## Configure Environment

```bash
cp .env.example .env
```

Update

- GROQ_API_KEY
- Elasticsearch Passwords
- Redis Password
- Any other secrets

---

## Build

```bash
docker compose build
```

---

## Start Platform

```bash
docker compose up -d
```

---

## Verify Services

```bash
docker compose ps
```

---

# 🌐 Access Dashboard

| Service | URL |
|----------|-----|
| SOC Dashboard | http://localhost:8501 |
| Kibana | http://localhost:5601 |
| Telemetry API | http://localhost:8003/docs |
| Escalation API | http://localhost:8001/docs |
| RAG Proxy API | http://localhost:8002/docs |
| HoneyTrap API | http://localhost:8004/docs |

---

# ⚔️ Simulating Attacks

## Automated Simulation

```bash
python scripts/simulate_attack.py
```

---

## Load Sample Dataset

```bash
python scripts/load_sample_dataset.py
```

---

## Manual SSH Attack

```bash
ssh root@<TARGET-IP> -p 2222
```

---

## Telnet Attack

```bash
telnet <TARGET-IP> 2223
```

---

## FTP Attack

```bash
ftp <TARGET-IP> 2121
```

---

## Elasticsearch Honeypot

```bash
curl http://<TARGET-IP>:9201
```

---

# 💬 Example Chatbot Queries

- What attacks happened today?
- Summarize today's brute-force attacks.
- Show high-risk sessions.
- Generate an incident report.
- What MITRE techniques were observed?
- Were any honeytokens accessed?
- Show attacker timeline.
- What IOCs were extracted?

---

# 🧪 Testing

## Unit Tests

```bash
pip install -r tests/requirements-test.txt

pytest tests -v
```

---

## Manual API Test

```bash
curl http://localhost:8003/health

curl http://localhost:8001/health

curl http://localhost:8002/health

curl http://localhost:8004/health
```

---

# 🔒 Security Notes

- API keys are excluded using `.gitignore`
- Honeypots run in isolated Docker networks
- Generated credentials are synthetic
- Suitable for research and educational purposes only

---

# 📚 Documentation

- docs/ARCHITECTURE.md
- docs/API.md
- docs/COMPLETE_GUIDE.md
- docs/PROJECT_DOCUMENTATION.md

---

# 🚀 Future Enhancements

- Deep Learning–based attack classification
- LSTM session prediction
- Reinforcement Learning decision engine
- Threat Intelligence feeds
- Automated malware sandboxing
- SIEM alert integrations
- Grafana dashboards
- Kubernetes deployment

---

# 👨‍💻 Author

**Karthikeyan T**
Cybersecurity Enthusiast

GitHub: https://github.com/KarthikeyanT-27

---

# ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub.

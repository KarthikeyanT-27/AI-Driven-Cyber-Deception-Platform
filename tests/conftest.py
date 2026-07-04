"""
tests/conftest.py

The custom services aren't packaged (each is just a flat directory of
modules meant to run as its own container), so tests import them directly
by adding each service dir to sys.path. We also pin env vars that affect
module-level constants *before* any service module is imported — most
importantly USE_PRETRAINED_NLP=false, so importing escalation_engine.models
never triggers a HuggingFace model download during the unit test run.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

for service_dir in ("telemetry", "escalation_engine", "honeytrap", "rag_proxy"):
    path = str(ROOT / service_dir)
    if path not in sys.path:
        sys.path.insert(0, path)

# Must be set before escalation_engine.models is imported anywhere.
os.environ.setdefault("USE_PRETRAINED_NLP", "false")
os.environ.setdefault("ESCALATE_THRESHOLD", "70")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PASSWORD", "")
os.environ.setdefault("ELASTICSEARCH_HOST", "http://localhost:9200")

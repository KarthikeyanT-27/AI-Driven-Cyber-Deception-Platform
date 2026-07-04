"""
rag_proxy/chroma_client.py

Thin wrapper around ChromaDB for storing and retrieving "attack memory":
attack history, command history, attacker sessions, and MITRE mappings.
Everything is stored in one collection (CHROMA_COLLECTION) with a `kind`
field in metadata distinguishing record types, which keeps similarity
search simple (search once, filter/boost by kind downstream) while still
letting the dashboard/escalation engine query by type.
"""

import logging
import os
import uuid
from datetime import datetime, timezone

import chromadb

log = logging.getLogger("rag_proxy.chroma_client")

CHROMA_HOST = os.getenv("CHROMA_HOST", "chromadb")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
CHROMA_COLLECTION = os.getenv("CHROMA_COLLECTION", "attack_memory")


class AttackMemory:
    def __init__(self):
        self.client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        self.collection = self.client.get_or_create_collection(name=CHROMA_COLLECTION)

    def insert(self, text: str, kind: str, metadata: dict | None = None) -> str:
        """
        kind: one of "attack_history" | "command_history" | "session" | "mitre_mapping"
        """
        record_id = str(uuid.uuid4())
        meta = {
            "kind": kind,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        }
        # Chroma metadata values must be str/int/float/bool — stringify anything else.
        meta = {k: (v if isinstance(v, (str, int, float, bool)) else str(v)) for k, v in meta.items()}

        self.collection.add(documents=[text], metadatas=[meta], ids=[record_id])
        return record_id

    def query_similar(self, query_text: str, n_results: int = 5, kind: str | None = None) -> list[dict]:
        where = {"kind": kind} if kind else None
        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=n_results,
                where=where,
            )
        except Exception as exc:
            log.warning("Chroma query failed (%s); returning empty result set.", exc)
            return []

        out = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0] if results.get("distances") else [None] * len(docs)
        for doc, meta, dist in zip(docs, metas, distances):
            out.append({"text": doc, "metadata": meta, "distance": dist})
        return out

    def count(self) -> int:
        return self.collection.count()

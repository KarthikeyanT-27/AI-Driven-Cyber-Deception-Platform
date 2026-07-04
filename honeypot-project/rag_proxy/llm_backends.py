"""
rag_proxy/llm_backends.py

Interchangeable LLM backends, selected purely via environment variables
(no hardcoded URLs/keys, per the spec). The active backend for this demo
is Groq, but OpenAI and Ollama implementations are included and the proxy
can be repointed at either by changing LLM_PROVIDER — no code changes.
"""

import logging
import os

import httpx

log = logging.getLogger("rag_proxy.llm_backends")


class LLMBackend:
    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        raise NotImplementedError


class GroqBackend(LLMBackend):
    def __init__(self):
        self.api_key = os.environ["GROQ_API_KEY"]
        self.api_url = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
        self.model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 800,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(self.api_url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]


class OpenAIBackend(LLMBackend):
    def __init__(self):
        self.api_key = os.environ["OPENAI_API_KEY"]
        self.api_url = os.getenv("OPENAI_API_URL", "https://api.openai.com/v1/chat/completions")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 800,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(self.api_url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]


class OllamaBackend(LLMBackend):
    def __init__(self):
        self.host = os.getenv("OLLAMA_HOST", "http://ollama:11434")
        self.model = os.getenv("OLLAMA_MODEL", "llama3")

    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(f"{self.host}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]


def get_backend() -> LLMBackend:
    provider = os.getenv("LLM_PROVIDER", "groq").lower()
    if provider == "groq":
        return GroqBackend()
    if provider == "openai":
        return OpenAIBackend()
    if provider == "ollama":
        return OllamaBackend()
    raise ValueError(f"Unknown LLM_PROVIDER: {provider}")

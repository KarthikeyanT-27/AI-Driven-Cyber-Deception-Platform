"""
telemetry/ioc_extractor.py

Pulls Indicators of Compromise (IOCs) out of raw honeypot event text:
IPs, domains, URLs, and file hashes (MD5/SHA1/SHA256). Produces a simple
heuristic risk_score per extracted indicator so downstream consumers
(escalation engine, dashboard) have something to sort/filter on even
before deeper AI analysis runs.

This is intentionally dependency-light (stdlib regex only) so it can run
inside the telemetry container without pulling in a full threat-intel SDK.
For production use, the risk_score heuristic here should be backed by a
real reputation feed (e.g. AbuseIPDB, OTX, VirusTotal) — hooks are left
as TODOs below.

FIX (audit finding D): private/loopback IP matches were previously still
created as IOC documents (scored 0, but indexed and shown in the dashboard
IOC count and the chatbot's evidence). 127.0.0.1 has no intel value — it's
the honeypot's own healthcheck traffic — so these are now skipped entirely
instead of being recorded at zero score.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Common non-public ranges we don't want flagged as "malicious external IP"
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Known infra hostnames that show up constantly and aren't IOCs
DOMAIN_ALLOWLIST = {"localhost", "elasticsearch", "redis", "chromadb", "logstash"}


@dataclass
class IOC:
    ip: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    hash: Optional[str] = None
    hash_type: Optional[str] = None
    risk_score: int = 0
    tags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip or "",
            "domain": self.domain or "",
            "url": self.url or "",
            "hash": self.hash or "",
            "hash_type": self.hash_type or "",
            "risk_score": self.risk_score,
            "tags": self.tags,
        }


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return False


def _score_ip(ip: str) -> int:
    # TODO: replace with a real reputation lookup (AbuseIPDB / OTX / VT).
    # Heuristic for the demo: any *external* IP touching a honeypot is
    # inherently suspicious since these systems have no legitimate traffic.
    return 0 if _is_private_ip(ip) else 60


def _score_hash() -> int:
    # TODO: replace with VirusTotal / MalwareBazaar lookup.
    # Any binary hash captured by a honeypot download is, by definition,
    # something an attacker dropped — treat as high risk by default.
    return 85


def _score_url() -> int:
    return 55


def extract_iocs(text: str) -> list[IOC]:
    """Extract every distinct IOC found in a blob of raw log/event text."""
    if not text:
        return []

    iocs: list[IOC] = []
    seen = set()

    for match in IPV4_RE.findall(text):
        if match in seen:
            continue
        seen.add(match)
        # FIX: don't record private/loopback IPs as IOCs at all — they're
        # infrastructure addresses, not indicators of compromise, and
        # previously bloated the iocs-* index and dashboard IOC count.
        if _is_private_ip(match):
            continue
        iocs.append(IOC(ip=match, risk_score=_score_ip(match), tags=["network"]))

    for match in URL_RE.findall(text):
        if match in seen:
            continue
        seen.add(match)
        iocs.append(IOC(url=match, risk_score=_score_url(), tags=["network", "delivery"]))

    for match in DOMAIN_RE.findall(text):
        domain = match.rstrip(".")
        if domain in seen or domain.lower() in DOMAIN_ALLOWLIST:
            continue
        # Skip domains that are actually just dotted IPs already captured
        if IPV4_RE.fullmatch(domain):
            continue
        seen.add(domain)
        iocs.append(IOC(domain=domain, risk_score=50, tags=["network"]))

    for match in SHA256_RE.findall(text):
        if match in seen:
            continue
        seen.add(match)
        iocs.append(IOC(hash=match, hash_type="sha256", risk_score=_score_hash(), tags=["malware"]))

    for match in SHA1_RE.findall(text):
        if match in seen:
            continue
        seen.add(match)
        iocs.append(IOC(hash=match, hash_type="sha1", risk_score=_score_hash(), tags=["malware"]))

    for match in MD5_RE.findall(text):
        if match in seen:
            continue
        seen.add(match)
        iocs.append(IOC(hash=match, hash_type="md5", risk_score=_score_hash(), tags=["malware"]))

    return iocs


def extract_iocs_as_dicts(text: str) -> list[dict]:
    return [ioc.to_dict() for ioc in extract_iocs(text)]

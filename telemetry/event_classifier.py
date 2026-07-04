"""
telemetry/event_classifier.py  (NEW FILE)

Classifies each raw honeypot event as one of:

  - "attack"  -> real attacker-originated activity. Feeds IOC extraction,
                 MITRE mapping, session correlation, and escalation scoring.
  - "infra"   -> internal plumbing — specifically Docker healthchecks, which
                 connect to Cowrie/Dionaea from the loopback interface
                 (127.0.0.1) on a fixed interval and never send a real
                 payload. Logged for visibility, excluded from every
                 downstream analytics/AI stage.
  - "system"  -> events Logstash could not attribute to a known honeypot
                 (honeypot == "unknown").

Why loopback + no-payload, specifically:
  Docker's healthcheck for Cowrie/Dionaea opens a bare TCP connection from
  inside the same container (127.0.0.1) and closes it immediately without
  authenticating or sending a command. A real attacker reaching the
  honeypot over the network never appears as 127.0.0.1 — they always have
  a real source address (even if it's a private RFC1918 address on a lab
  network), so we deliberately do NOT treat all private IPs as "infra"
  here — only the loopback interface, which nothing but the local
  healthcheck process can use. Anything else defaults to "attack" so we
  never silently hide real activity behind an over-eager classifier.

This mirrors the `event_class` field Logstash computes at ingest time
(see config/logstash/logstash.conf). Telemetry re-derives it independently
so processing stays correct even if a document is missing the field —
e.g. the /ingest manual-test path, or documents indexed before this field
existed.
"""

import ipaddress

LOOPBACK_NET = ipaddress.ip_network("127.0.0.0/8")

# Any of these being non-empty means the event carries real attacker
# content (a typed command, a fetched URL, a dropped file, credentials
# tried, etc.) rather than being a bare connect/close.
PAYLOAD_FIELDS = ("input", "command", "url", "filename")

VALID_CLASSES = ("attack", "infra", "system")


def _extract_src_ip(doc: dict) -> str | None:
    event_data = doc.get("event_data") or {}
    return event_data.get("src_ip") or event_data.get("src") or doc.get("src_ip")


def _is_loopback(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in LOOPBACK_NET
    except ValueError:
        return False


def _has_payload(doc: dict) -> bool:
    event_data = doc.get("event_data") or {}
    return any(event_data.get(f) for f in PAYLOAD_FIELDS)


def classify_event(doc: dict) -> str:
    """Return "attack", "infra", or "system" for a raw honeypot event doc."""
    honeypot = doc.get("honeypot", "unknown")
    if honeypot == "unknown":
        return "system"

    # Trust an existing Logstash-assigned class if it's already valid —
    # avoids redoing work and keeps telemetry and Logstash in agreement.
    existing = doc.get("event_class")
    if existing in VALID_CLASSES:
        return existing

    src_ip = _extract_src_ip(doc)
    if _is_loopback(src_ip) and not _has_payload(doc):
        return "infra"

    return "attack"

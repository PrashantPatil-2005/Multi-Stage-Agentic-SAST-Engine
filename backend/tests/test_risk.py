"""Risk prioritization tests (deterministic scoring, no LLM)."""

from datetime import datetime, timezone

from app.prove.models import ProofResult, SandboxPolicy
from app.risk.scoring import RiskPolicy, RiskScorer, SEVERITY_WEIGHTS
from app.risk.service import RiskService
from app.scan.models import CandidateFinding, Evidence, SinkRef, SourceRef, TaintStep
from app.validate.service import ValidationService
from tests.fake_llm_provider import FakeLLMProvider

FIXED = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_finding(finding_id: str = "f" * 64, severity: str = "high") -> CandidateFinding:
    path = [
        TaintStep(file="repo/x.py", line=1, snippet="s", step_type="source"),
        TaintStep(file="repo/x.py", line=2, snippet="t", step_type="sink"),
    ]
    return CandidateFinding(
        id=finding_id,
        vulnerability_type="sql_injection",
        severity=severity,
        confidence=0.7,
        source=SourceRef(file="repo/x.py", line=1, snippet="s", kind="request_param"),
        sink=SinkRef(file="repo/x.py", line=2, snippet="t", kind="sql_execute"),
        taint_path=path,
        evidence=Evidence(
            source_snippet="s",
            sink_snippet="t",
            taint_path=path,
            relevant_lines=[1, 2],
            sanitizer_observations=[],
        ),
    )


def make_validation(finding_id: str, verdict: str):
    finding = make_finding(finding_id)
    return ValidationService(
        provider=FakeLLMProvider(verdict=verdict, confidence=0.9)
    ).validate(finding)


def make_proof(finding_id: str, status: str = "verified") -> ProofResult:
    return ProofResult(
        finding_id=finding_id,
        vulnerability_type="sql_injection",
        status=status,
        confidence=0.9,
        summary="fake",
        duration_ms=1.0,
        sandbox_policy=SandboxPolicy(),
        error=None,
        created_at=FIXED,
    )


def assess(finding, validation=None, proof=None, scorer=None):
    return RiskService(scorer=scorer).assess(
        finding, validation, proof, assessed_at=FIXED
    )


def test_high_severity_base_score():
    result = assess(make_finding())
    assert result.risk_score == SEVERITY_WEIGHTS["high"] == 75
    assert result.priority == "P1"
    assert result.severity == "high"


def test_critical_mapping():
    result = assess(make_finding(severity="critical"))
    assert result.risk_score == 100
    assert result.priority == "P0"


def test_medium_mapping():
    result = assess(make_finding(severity="medium"))
    assert result.risk_score == 50
    assert result.priority == "P2"


def test_low_mapping():
    result = assess(make_finding(severity="low"))
    assert result.risk_score == 25
    assert result.priority == "P3"


def test_false_positive_zero_risk():
    finding = make_finding()
    result = assess(finding, make_validation(finding.id, "false_positive"))
    assert result.risk_score == 0
    assert result.priority == "P4"


def test_uncertain_not_confirmed():
    finding = make_finding()
    result = assess(finding, make_validation(finding.id, "uncertain"))
    assert result.risk_score == 75
    assert result.priority == "P1"
    names = [f.name for f in result.factors]
    assert "validation" in names
    assert result.factors[[n for n in names].index("validation")].value == "uncertain"


def test_true_positive_normal_risk():
    finding = make_finding()
    result = assess(finding, make_validation(finding.id, "true_positive"))
    assert result.risk_score == 85
    assert result.priority == "P1"


def test_proven_follows_proof_policy():
    finding = make_finding()
    validation = make_validation(finding.id, "true_positive")
    proof = make_proof(finding.id, "verified")
    default = assess(finding, validation, proof)
    assert default.risk_score == 95
    assert default.priority == "P0"
    conservative = RiskPolicy(proof_increases_priority=False)
    result = assess(finding, validation, proof, scorer=RiskScorer(conservative))
    assert result.risk_score == 85
    assert result.priority == "P1"


def test_score_clamped_to_100():
    finding = make_finding(severity="critical")
    validation = make_validation(finding.id, "true_positive")
    proof = make_proof(finding.id, "verified")
    result = assess(finding, validation, proof)
    assert result.risk_score == 100
    assert result.priority == "P0"
    assert 0 <= result.risk_score <= 100


def test_unknown_severity_not_fabricated():
    result = assess(make_finding(severity="exotic"))
    assert result.risk_score == 0
    severity_factor = next(f for f in result.factors if f.name == "severity")
    assert severity_factor.points == 0
    assert "not fabricated" in severity_factor.description


def test_priority_mapping_deterministic():
    policy_74 = RiskPolicy(severity_weights={"medium": 74})
    policy_75 = RiskPolicy(severity_weights={"medium": 75})
    low = make_finding(severity="medium")
    assert assess(low, scorer=RiskScorer(policy_74)).priority == "P2"
    assert assess(low, scorer=RiskScorer(policy_75)).priority == "P1"
    first = assess(low)
    second = assess(low)
    assert first.priority == second.priority == "P2"
    assert first.risk_score == second.risk_score


def test_factors_explainable():
    finding = make_finding()
    result = assess(finding, make_validation(finding.id, "true_positive"))
    assert len(result.factors) == 2
    severity = next(f for f in result.factors if f.name == "severity")
    assert severity.value == "high"
    assert severity.points == 75
    assert severity.description
    validation = next(f for f in result.factors if f.name == "validation")
    assert validation.value == "true_positive"
    assert validation.points == 10


def test_missing_factors_not_fabricated():
    finding = make_finding()
    result = assess(finding)
    names = [f.name for f in result.factors]
    assert names == ["severity"]
    assert "validation" not in names
    assert "proof" not in names


def test_assessed_at_deterministic_and_aware():
    finding = make_finding()
    assert assess(finding).assessed_at == FIXED
    assert assess(finding).assessed_at.tzinfo is not None
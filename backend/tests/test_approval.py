"""Human approval workflow tests (service level)."""

from datetime import datetime, timezone

import pytest

from app.approval.policies import ApprovalPolicy
from app.approval.service import (
    ApprovalGateError,
    ApprovalService,
    InvalidTransitionError,
)
from app.approval.store import get_approval_store
from app.prove.service import ProofService
from app.prove.store import get_proof_store
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import scan_fixture_files

FIXED = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def clean_stores():
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()


@pytest.fixture
def proven_sqli():
    """A sql_injection finding that passed VALIDATE (true_positive) and PROVE (verified)."""
    finding = next(
        f
        for f in scan_fixture_files("app.py").findings
        if f.vulnerability_type == "sql_injection"
    )
    validation = ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.94)
    ).validate(finding)
    proof = ProofService().prove(finding, validation)
    assert proof.status == "verified"
    get_finding_store().add(finding)
    get_validation_store().record(validation)
    get_proof_store().record(proof)
    return finding, validation, proof


@pytest.fixture
def validated_sqli():
    """Validated true_positive but NOT proven."""
    finding = next(
        f
        for f in scan_fixture_files("app.py").findings
        if f.vulnerability_type == "sql_injection"
    )
    validation = ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.94)
    ).validate(finding)
    get_finding_store().add(finding)
    get_validation_store().record(validation)
    return finding, validation


def _validate(finding, verdict: str):
    validation = ValidationService(
        provider=FakeLLMProvider(verdict=verdict, confidence=0.9)
    ).validate(finding)
    get_validation_store().record(validation)
    return validation


# ---------------------------------------------------------------- eligibility


def test_true_positive_verified_proof_can_request(proven_sqli):
    finding, _, _ = proven_sqli
    request = ApprovalService().request_approval(finding.id, requested_at=FIXED)
    assert request.finding_id == finding.id
    assert request.status == "pending"
    assert request.version == 1


def test_false_positive_cannot_request():
    finding = next(
        f
        for f in scan_fixture_files("app.py").findings
        if f.vulnerability_type == "sql_injection"
    )
    get_finding_store().add(finding)
    _validate(finding, "false_positive")
    with pytest.raises(ApprovalGateError) as exc:
        ApprovalService().request_approval(finding.id)
    assert "false_positive" in str(exc.value)


def test_uncertain_cannot_request():
    finding = next(
        f
        for f in scan_fixture_files("app.py").findings
        if f.vulnerability_type == "sql_injection"
    )
    get_finding_store().add(finding)
    _validate(finding, "uncertain")
    with pytest.raises(ApprovalGateError) as exc:
        ApprovalService().request_approval(finding.id)
    assert "uncertain" in str(exc.value)


def test_true_positive_without_proof_rejected_by_default(validated_sqli):
    finding, _ = validated_sqli
    with pytest.raises(ApprovalGateError) as exc:
        ApprovalService().request_approval(finding.id)
    assert "PROVE" in str(exc.value)


def test_unvalidated_finding_rejected_by_default():
    finding = next(
        f
        for f in scan_fixture_files("app.py").findings
        if f.vulnerability_type == "sql_injection"
    )
    get_finding_store().add(finding)
    with pytest.raises(ApprovalGateError) as exc:
        ApprovalService().request_approval(finding.id)
    assert "validated" in str(exc.value)


def test_policy_can_skip_proof_requirement(validated_sqli):
    finding, _ = validated_sqli
    service = ApprovalService(policy=ApprovalPolicy(require_proof=False))
    request = service.request_approval(finding.id, requested_at=FIXED)
    assert request.status == "pending"


def test_policy_can_skip_validation_gate():
    finding = next(
        f
        for f in scan_fixture_files("app.py").findings
        if f.vulnerability_type == "sql_injection"
    )
    get_finding_store().add(finding)
    service = ApprovalService(policy=ApprovalPolicy(require_validation=False, require_proof=False))
    request = service.request_approval(finding.id, requested_at=FIXED)
    assert request.status == "pending"


# ------------------------------------------------------------------ creation


def test_pending_request_created(proven_sqli):
    finding, _, _ = proven_sqli
    request = ApprovalService().request_approval(finding.id, requested_at=FIXED)
    assert request.id
    assert request.status == "pending"
    assert request.requested_by == "system"
    assert request.action == "remediation"
    assert request.requested_at == FIXED
    assert request.version == 1
    assert request.reviewed_by is None


def test_duplicate_pending_returns_existing(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    first = service.request_approval(finding.id, requested_at=FIXED)
    second = service.request_approval(finding.id, requested_at=FIXED)
    assert second.id == first.id
    assert get_approval_store().find_for_finding(finding.id).id == first.id


def test_different_action_creates_separate_request(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    first = service.request_approval(finding.id, action="remediation", requested_at=FIXED)
    second = service.request_approval(finding.id, action="other", requested_at=FIXED)
    assert second.id != first.id
    assert second.action == "other"


def test_re_request_after_terminal_blocked_by_default(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.approve(request.id, reviewed_by="analyst", reason="ok", reviewed_at=FIXED)
    with pytest.raises(ApprovalGateError) as exc:
        service.request_approval(finding.id, requested_at=FIXED)
    assert "terminal" in str(exc.value)


def test_re_request_after_terminal_allowed_by_policy(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService(
        policy=ApprovalPolicy(allow_re_request_after_terminal=True)
    )
    first = service.request_approval(finding.id, requested_at=FIXED)
    service.reject(first.id, reviewed_by="analyst", reason="no", reviewed_at=FIXED)
    second = service.request_approval(finding.id, requested_at=FIXED)
    assert second.id != first.id
    assert second.status == "pending"


# ------------------------------------------------------------ state machine


def test_pending_to_approved(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    approved = service.approve(
        request.id, reviewed_by="security-analyst", reason="Verified.", reviewed_at=FIXED
    )
    assert approved.status == "approved"
    assert approved.reviewed_by == "security-analyst"
    assert approved.reviewed_at == FIXED


def test_pending_to_rejected(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    rejected = service.reject(
        request.id, reviewed_by="security-analyst", reason="Risk accepted.", reviewed_at=FIXED
    )
    assert rejected.status == "rejected"


def test_pending_to_changes_requested(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    changed = service.request_changes(
        request.id, reviewed_by="security-analyst", reason="More evidence.", reviewed_at=FIXED
    )
    assert changed.status == "changes_requested"
    assert changed.version == 1


def test_changes_requested_to_pending_increments_version(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    changed = service.request_changes(
        request.id, reviewed_by="analyst", reason="More evidence.", reviewed_at=FIXED
    )
    pending_again = service.resubmit(
        changed.id, reviewed_by="analyst", reason="evidence added", reviewed_at=FIXED
    )
    assert pending_again.status == "pending"
    assert pending_again.version == 2


def test_approved_to_rejected_blocked(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.approve(request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED)
    with pytest.raises(InvalidTransitionError):
        service.reject(request.id, reviewed_by="a", reason="no", reviewed_at=FIXED)


def test_approved_to_pending_blocked(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.approve(request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED)
    with pytest.raises(InvalidTransitionError):
        service.resubmit(request.id, reviewed_by="a", reason=None, reviewed_at=FIXED)


def test_rejected_to_approved_blocked(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.reject(request.id, reviewed_by="a", reason="no", reviewed_at=FIXED)
    with pytest.raises(InvalidTransitionError):
        service.approve(request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED)


def test_rejected_to_pending_blocked(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.reject(request.id, reviewed_by="a", reason="no", reviewed_at=FIXED)
    with pytest.raises(InvalidTransitionError):
        service.resubmit(request.id, reviewed_by="a", reason=None, reviewed_at=FIXED)


def test_unknown_approval_transition_fails(proven_sqli):
    with pytest.raises(InvalidTransitionError):
        ApprovalService().approve("does-not-exist", reviewed_by="a")


# ------------------------------------------------------------------- audit


def test_approval_creates_audit_event(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.approve(request.id, reviewed_by="analyst", reason="ok", reviewed_at=FIXED)
    history = service.get_history(request.id)
    assert [e.new_status for e in history] == ["pending", "approved"]
    assert history[1].previous_status == "pending"
    assert history[1].actor == "analyst"


def test_rejection_creates_audit_event(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.reject(request.id, reviewed_by="analyst", reason="no", reviewed_at=FIXED)
    history = service.get_history(request.id)
    assert history[-1].new_status == "rejected"
    assert history[-1].previous_status == "pending"


def test_request_changes_creates_audit_event(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.request_changes(
        request.id, reviewed_by="analyst", reason="more", reviewed_at=FIXED
    )
    history = service.get_history(request.id)
    assert history[-1].new_status == "changes_requested"


def test_audit_history_preserved(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    changed = service.request_changes(
        request.id, reviewed_by="a", reason="more", reviewed_at=FIXED
    )
    pending = service.resubmit(
        changed.id, reviewed_by="a", reason="fixed", reviewed_at=FIXED
    )
    approved = service.approve(
        pending.id, reviewed_by="b", reason="ok now", reviewed_at=FIXED
    )
    history = service.get_history(approved.id)
    assert [e.new_status for e in history] == [
        "pending",
        "changes_requested",
        "pending",
        "approved",
    ]
    assert len(history) == 4
    assert history[2].previous_status == "changes_requested"
    assert approved.version == 2


def test_reviewed_by_and_reason_recorded(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    approved = service.approve(
        request.id,
        reviewed_by="security-analyst",
        reason="Verified vulnerability and proof reviewed.",
        reviewed_at=FIXED,
    )
    assert approved.reviewed_by == "security-analyst"
    assert approved.reason == "Verified vulnerability and proof reviewed."
    event = service.get_history(request.id)[-1]
    assert event.actor == "security-analyst"
    assert event.reason == "Verified vulnerability and proof reviewed."


def test_timestamps_timezone_aware(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    with pytest.raises(ValueError):
        service.request_approval(
            finding.id, action="other", requested_at=datetime(2026, 1, 1)
        )
    request = service.request_approval(finding.id, requested_at=FIXED)
    approved = service.approve(
        request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED
    )
    for event in service.get_history(request.id):
        assert event.created_at.tzinfo is not None
    assert approved.requested_at.tzinfo is not None
    assert approved.reviewed_at.tzinfo is not None


# ------------------------------------------------------------------ safety


def test_approve_does_not_execute_subprocess_or_network(proven_sqli, monkeypatch):
    def _forbidden(*args, **kwargs):
        raise AssertionError("approval must not execute subprocess/network")

    monkeypatch.setattr("subprocess.run", _forbidden)
    monkeypatch.setattr("os.system", _forbidden)
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    approved = service.approve(
        request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED
    )
    assert approved.status == "approved"


def test_approve_does_not_modify_repository_files(proven_sqli, tmp_path):
    import shutil

    from tests.scan_test_helpers import VULN_APP

    repo_copy = tmp_path / "repo"
    shutil.copytree(VULN_APP, repo_copy)
    before = {
        p.relative_to(repo_copy): p.read_bytes()
        for p in repo_copy.rglob("*")
        if p.is_file()
    }
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.approve(request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED)
    after = {
        p.relative_to(repo_copy): p.read_bytes()
        for p in repo_copy.rglob("*")
        if p.is_file()
    }
    assert before == after


def test_approve_does_not_call_llm_or_network(proven_sqli, monkeypatch):
    """Approval must never call the LLM, an HTTP client, or a subprocess."""

    def _forbidden(*args, **kwargs):
        raise AssertionError("network/LLM call detected during approval")

    monkeypatch.setattr("httpx.Client", _forbidden)
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    approved = service.approve(
        request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED
    )
    assert approved.status == "approved"


# ------------------------------------------------------------ authorization


def test_action_authorization_approved_remediation_allowed(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    assert service.is_action_allowed(request.id) is False
    service.approve(request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED)
    assert service.is_action_allowed(request.id) is True


def test_action_authorization_rejected_blocked(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, requested_at=FIXED)
    service.reject(request.id, reviewed_by="a", reason="no", reviewed_at=FIXED)
    assert service.is_action_allowed(request.id) is False


def test_action_authorization_other_action_blocked_by_default(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService()
    request = service.request_approval(finding.id, action="other", requested_at=FIXED)
    service.approve(request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED)
    assert service.is_action_allowed(request.id) is False


def test_action_authorization_policy_expands_actions(proven_sqli):
    finding, _, _ = proven_sqli
    service = ApprovalService(
        policy=ApprovalPolicy(allowed_actions=("remediation", "other"))
    )
    request = service.request_approval(finding.id, action="other", requested_at=FIXED)
    service.approve(request.id, reviewed_by="a", reason="ok", reviewed_at=FIXED)
    assert service.is_action_allowed(request.id) is True


def test_action_authorization_unknown_approval_false():
    assert ApprovalService().is_action_allowed("does-not-exist") is False
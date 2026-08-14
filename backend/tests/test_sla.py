"""SLA tracking, escalation, and dedup integration tests (fixed clocks)."""

from datetime import datetime, timedelta, timezone

import pytest

from app.dedup.service import DeduplicationService
from app.risk.models import RiskAssessment, SLARecord
from app.risk.policies import SLAPolicy
from app.risk.service import RiskService, SLAService
from app.validate.service import ValidationService
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import FIXTURES, scan_fixture_files, scan_sources

FIXED = datetime(2026, 1, 1, tzinfo=timezone.utc)
DEDUP_FIXTURES = FIXTURES / "dedup"


def assessment(priority: str = "P1", finding_id: str = "f" * 64, score: int = 85) -> RiskAssessment:
    return RiskAssessment(
        finding_id=finding_id,
        vulnerability_type="sql_injection",
        severity="high",
        risk_score=score,
        priority=priority,
        factors=[],
        assessed_at=FIXED,
    )


def create(priority: str, started: datetime = FIXED) -> SLARecord:
    return SLAService().create_sla(assessment(priority=priority), started_at=started)


def test_p0_gets_four_hour_sla():
    record = create("P0")
    assert record.due_at == FIXED + timedelta(hours=4)
    assert record.status == "active"


def test_p1_gets_twenty_four_hour_sla():
    record = create("P1")
    assert record.due_at == FIXED + timedelta(hours=24)


def test_p2_gets_three_day_sla():
    record = create("P2")
    assert record.due_at == FIXED + timedelta(days=3)


def test_p3_gets_seven_day_sla():
    record = create("P3")
    assert record.due_at == FIXED + timedelta(days=7)


def test_p4_has_no_sla():
    record = create("P4")
    assert record.due_at is None
    assert record.status == "not_applicable"


def test_active_before_deadline():
    record = create("P1")
    updated, event = SLAService().check_sla(record, now=FIXED + timedelta(hours=1))
    assert updated.status == "active"
    assert event is None


def test_breached_at_deadline():
    record = create("P1")
    updated, event = SLAService().check_sla(record, now=FIXED + timedelta(hours=24))
    assert updated.status == "breached"
    assert updated.breached_at == FIXED + timedelta(hours=24)
    assert event is not None


def test_breached_after_deadline():
    record = create("P1")
    updated, _ = SLAService().check_sla(record, now=FIXED + timedelta(hours=48))
    assert updated.status == "breached"


def test_breached_at_set_only_once():
    record = create("P1")
    service = SLAService()
    first, _ = service.check_sla(record, now=FIXED + timedelta(hours=30))
    second, event = service.check_sla(first, now=FIXED + timedelta(hours=99))
    assert second.breached_at == first.breached_at
    assert event is None


def test_resolve_works():
    record = create("P1")
    resolved_at = FIXED + timedelta(hours=2)
    updated = SLAService().resolve_sla(record, resolved_at)
    assert updated.status == "resolved"
    assert updated.resolved_at == resolved_at


def test_resolved_sla_stays_resolved():
    record = create("P1")
    service = SLAService()
    resolved = service.resolve_sla(record, FIXED + timedelta(hours=1))
    checked, event = service.check_sla(resolved, now=FIXED + timedelta(days=10))
    assert checked.status == "resolved"
    assert event is None


def test_timezone_aware_timestamps():
    record = create("P1")
    assert record.started_at.tzinfo is not None
    assert record.due_at.tzinfo is not None
    checked, _ = SLAService().check_sla(record, now=FIXED + timedelta(hours=1))
    assert checked.last_checked_at.tzinfo is not None
    with pytest.raises(ValueError):
        SLAService().create_sla(assessment(priority="P1"), started_at=datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        SLAService().check_sla(record, now=datetime(2026, 1, 1))


def test_custom_policy():
    policy = SLAPolicy(deadlines={"P0": timedelta(hours=2)})
    record = SLAService(policy=policy).create_sla(
        assessment(priority="P0"), started_at=FIXED
    )
    assert record.due_at == FIXED + timedelta(hours=2)
    no_p1 = SLAService(policy=policy).create_sla(
        assessment(priority="P1"), started_at=FIXED
    )
    assert no_p1.due_at is None
    assert no_p1.status == "not_applicable"


def test_p4_never_breaches():
    record = create("P4")
    updated, event = SLAService().check_sla(record, now=FIXED + timedelta(days=365))
    assert updated.status == "not_applicable"
    assert event is None


def test_check_all():
    records = [create("P1"), create("P0")]
    results = SLAService().check_all(records, now=FIXED + timedelta(days=1))
    assert len(results) == 2
    assert results[0][0].status == "breached"
    assert results[1][0].status == "breached"


def test_first_breach_creates_level_one_escalation():
    record = create("P1")
    _, event = SLAService().check_sla(record, now=FIXED + timedelta(hours=25))
    assert event is not None
    assert event.previous_level == 0
    assert event.new_level == 1
    assert event.finding_id == record.finding_id


def test_repeated_checks_do_not_duplicate_escalation():
    record = create("P1")
    service = SLAService()
    updated, first_event = service.check_sla(record, now=FIXED + timedelta(hours=25))
    updated, second_event = service.check_sla(updated, now=FIXED + timedelta(hours=30))
    updated, third_event = service.check_sla(updated, now=FIXED + timedelta(hours=40))
    assert first_event is not None
    assert second_event is None
    assert third_event is None
    assert updated.escalation_level == 1


def test_escalation_event_contains_reason():
    record = create("P1")
    _, event = SLAService().check_sla(record, now=FIXED + timedelta(hours=25))
    assert "P1" in event.reason
    assert record.due_at.isoformat() in event.reason


def test_escalation_deterministic():
    now = FIXED + timedelta(hours=25)
    _, event_a = SLAService().check_sla(create("P1"), now=now)
    _, event_b = SLAService().check_sla(create("P1"), now=now)
    assert event_a.model_dump() == event_b.model_dump()


# --------------------------------------------------------------------------
# Dedup -> Risk integration
# --------------------------------------------------------------------------


def _scan_cross_repo():
    sources = {
        "repository_a/views.py": (
            DEDUP_FIXTURES / "repository_a" / "views.py"
        ).read_text(encoding="utf-8"),
        "repository_b/main.py": (
            DEDUP_FIXTURES / "repository_b" / "main.py"
        ).read_text(encoding="utf-8"),
    }
    return scan_sources(sources).findings


def test_duplicate_findings_one_assessment_for_canonical():
    findings = _scan_cross_repo()
    group = DeduplicationService().deduplicate(findings).groups[0]
    canonical = next(f for f in findings if f.id == group.canonical_finding_id)
    validation = ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.9)
    ).validate(canonical)
    result = RiskService().assess_group(group, validation=validation, assessed_at=FIXED)
    assert result.finding_id == group.canonical_finding_id
    assert result.priority == "P1"
    assert result.risk_score == 85


def test_dedup_members_traceable():
    findings = _scan_cross_repo()
    group = DeduplicationService().deduplicate(findings).groups[0]
    result = RiskService().assess_group(group, assessed_at=FIXED)
    assert sorted(result.related_finding_ids) == sorted(group.member_finding_ids)
    assert len(result.related_finding_ids) == 2


def test_non_duplicates_remain_separate():
    findings = scan_fixture_files("app.py").findings
    sqli = next(f for f in findings if f.vulnerability_type == "sql_injection")
    cmdi = next(f for f in findings if f.vulnerability_type == "command_injection")
    service = RiskService()
    group_sqli = DeduplicationService().deduplicate([sqli]).groups[0]
    group_cmdi = DeduplicationService().deduplicate([cmdi]).groups[0]
    a = service.assess_group(group_sqli, assessed_at=FIXED)
    b = service.assess_group(group_cmdi, assessed_at=FIXED)
    assert a.finding_id != b.finding_id
    assert a.priority == b.priority
    assert a.vulnerability_type != b.vulnerability_type
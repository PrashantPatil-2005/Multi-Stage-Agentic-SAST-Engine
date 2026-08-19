"""Phase 14E: background SLA evaluator tests (fixed clocks, no sleeps).

The evaluator is exercised directly with an injectable clock (TEST 1-6), the
real app lifecycle (TEST 7-8), configuration validation (TEST 9) and the
manual /sla/check convergence guarantee (TEST 10).
"""

from datetime import datetime, timedelta, timezone
import threading

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.main import create_app
from app.risk.models import RiskAssessment, SLARecord
from app.risk.service import (
    SLAService,
    check_and_persist_sla,
    get_escalation_events,
    get_sla_record,
    record_sla_record,
    reset_risk_stores,
)
from app.risk.sla_evaluator import SlaEvaluator
from app.validate.store import get_finding_store
from tests.scan_test_helpers import scan_fixture_files

FIXED = datetime(2026, 1, 1, tzinfo=timezone.utc)
FAR_FUTURE = datetime(2099, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def clean_risk_stores():
    reset_risk_stores()
    yield
    reset_risk_stores()


@pytest.fixture
def registered_sqli():
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    return next(
        f for f in report.findings if f.vulnerability_type == "sql_injection"
    )


def _assessment(finding_id: str, priority: str = "P1") -> RiskAssessment:
    return RiskAssessment(
        finding_id=finding_id,
        vulnerability_type="sql_injection",
        severity="high",
        risk_score=75,
        priority=priority,
        factors=[],
        assessed_at=FIXED,
    )


def _record(finding_id: str, priority: str = "P1") -> SLARecord:
    return SLAService().create_sla(_assessment(finding_id, priority), started_at=FIXED)


def _store(record: SLARecord) -> None:
    record_sla_record(record)


def _evaluator() -> SlaEvaluator:
    return SlaEvaluator(interval_seconds=60)


# TEST 1 ------------------------------------------------------------------
def test_evaluator_active_record_not_due_stays_active():
    _store(_record("f-not-due"))

    stats = _evaluator().evaluate_once(now=FIXED + timedelta(hours=1))

    assert stats.inspected == 1
    assert stats.breached == 0
    assert stats.errors == 0
    stored = get_sla_record("f-not-due")
    assert stored.status == "active"
    assert stored.last_checked_at == FIXED + timedelta(hours=1)
    assert get_escalation_events("f-not-due") == []


# TEST 2 ------------------------------------------------------------------
def test_evaluator_breaches_overdue_record_once():
    _store(_record("f-overdue"))

    stats = _evaluator().evaluate_once(now=FIXED + timedelta(hours=25))

    assert stats.inspected == 1
    assert stats.breached == 1
    stored = get_sla_record("f-overdue")
    assert stored.status == "breached"
    assert stored.breached_at == FIXED + timedelta(hours=25)
    assert stored.escalation_level == 1
    events = get_escalation_events("f-overdue")
    assert len(events) == 1
    assert events[0].previous_level == 0
    assert events[0].new_level == 1


# TEST 3 ------------------------------------------------------------------
def test_evaluator_never_duplicates_escalation():
    _store(_record("f-repeat"))

    evaluator = _evaluator()
    evaluator.evaluate_once(now=FIXED + timedelta(hours=25))
    first = get_sla_record("f-repeat")

    for hours in (26, 30, 48, 24 * 14):
        stats = evaluator.evaluate_once(now=FIXED + timedelta(hours=hours))
        assert stats.breached == 0

    stored = get_sla_record("f-repeat")
    assert stored.status == "breached"
    assert stored.breached_at == first.breached_at
    assert stored.escalation_level == 1
    assert len(get_escalation_events("f-repeat")) == 1


# TEST 3b ----------------------------------------------------------------
def test_concurrent_sla_checks_emit_single_escalation_event():
    """Regression: the read->check->persist sequence must be atomic across
    threads (background evaluator + API check requests). Before the fix two
    concurrent callers could both observe an active record and each emit
    the active->breached escalation event (observed live, 2 events 78ms
    apart for one transition)."""
    _store(_record("f-concurrent"))

    now = FIXED + timedelta(hours=25)
    failures: list[BaseException] = []

    def worker() -> None:
        try:
            check_and_persist_sla("f-concurrent", now=now)
        except Exception as exc:  # pragma: no cover - failure path
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    record = get_sla_record("f-concurrent")
    assert record.status == "breached"
    events = get_escalation_events("f-concurrent")
    assert len(events) == 1
    assert events[0].new_level == 1


# TEST 4 ------------------------------------------------------------------
def test_evaluator_p4_no_deadline_never_breaches():
    _store(_record("f-p4", priority="P4"))

    stats = _evaluator().evaluate_once(now=FAR_FUTURE)

    assert stats.breached == 0
    stored = get_sla_record("f-p4")
    assert stored.status == "not_applicable"
    assert stored.due_at is None
    assert get_escalation_events("f-p4") == []


# TEST 5 ------------------------------------------------------------------
def test_evaluator_resolved_never_reactivates():
    _store(SLAService().resolve_sla(_record("f-resolved")))

    stats = _evaluator().evaluate_once(now=FAR_FUTURE)

    assert stats.breached == 0
    stored = get_sla_record("f-resolved")
    assert stored.status == "resolved"
    assert get_escalation_events("f-resolved") == []


# TEST 6 ------------------------------------------------------------------
def test_evaluator_mixed_batch_with_failure_isolation(monkeypatch):
    _store(_record("f-early", priority="P2"))  # active, not yet due
    _store(_record("f-late"))  # active, overdue
    already = SLAService().check_sla(
        _record("f-already"), now=FIXED + timedelta(hours=25)
    )[0]
    _store(already)  # already breached by a previous cycle
    _store(SLAService().resolve_sla(_record("f-resolved")))
    _store(_record("f-p4", priority="P4"))
    _store(_record("f-poison"))  # store call itself fails below

    def poisoned(finding_id: str, now=None):
        if finding_id == "f-poison":
            raise RuntimeError("simulated store failure")
        from app.risk.service import check_and_persist_sla as real_check

        return real_check(finding_id, now=now)

    monkeypatch.setattr(
        "app.risk.sla_evaluator.check_and_persist_sla", poisoned
    )

    stats = _evaluator().evaluate_once(now=FIXED + timedelta(hours=30))

    assert stats.inspected == 6
    assert stats.breached == 1
    assert stats.skipped == 3  # already-breached + resolved + P4
    assert stats.errors == 1  # poisoned record; cycle still completed
    assert get_sla_record("f-early").status == "active"
    assert get_sla_record("f-late").status == "breached"
    assert get_sla_record("f-already").status == "breached"
    assert get_sla_record("f-resolved").status == "resolved"
    assert get_sla_record("f-p4").status == "not_applicable"
    assert len(get_escalation_events("f-late")) == 1
    assert get_escalation_events("f-already") == []


# TEST 7 ------------------------------------------------------------------
def test_evaluator_breach_persists_across_restart(tmp_path):
    settings = Settings(
        workspace_dir=tmp_path / "workspace",
        database_url=f"sqlite:///{(tmp_path / "sla.db").as_posix()}",
        log_level="WARNING",
    )
    report = scan_fixture_files("app.py")
    finding = next(
        f for f in report.findings if f.vulnerability_type == "sql_injection"
    )

    with TestClient(create_app(settings)) as client:
        from app.auth.seed import DEMO_PASSWORD
        client.post("/api/auth/login", json={"username": "manager", "password": DEMO_PASSWORD})
        get_finding_store().add_report(report)
        client.post(f"/api/findings/{finding.id}/risk")
        client.post(f"/api/findings/{finding.id}/sla")

        stats = client.app.state.sla_evaluator.evaluate_once(now=FAR_FUTURE)
        assert stats.breached == 1
        assert client.get(f"/api/findings/{finding.id}/sla").json()["status"] == "breached"

    with TestClient(create_app(settings)) as client:
        from app.auth.seed import DEMO_PASSWORD
        client.post("/api/auth/login", json={"username": "manager", "password": DEMO_PASSWORD})
        body = client.get(f"/api/findings/{finding.id}/sla").json()
        assert body["status"] == "breached"
        assert body["escalation_level"] == 1
        assert body["breached_at"] is not None
        events = client.get(f"/api/findings/{finding.id}/escalations").json()
        assert len(events) == 1
        assert events[0]["new_level"] == 1


# TEST 8 ------------------------------------------------------------------
def test_evaluator_startup_shutdown_clean(tmp_path):
    settings = Settings(
        workspace_dir=tmp_path / "workspace",
        database_url="sqlite:///:memory:",
        log_level="WARNING",
    )
    app = create_app(settings)
    assert not hasattr(app.state, "sla_evaluator")

    with TestClient(app) as client:
        evaluator = client.app.state.sla_evaluator
        assert evaluator.is_running

    assert not evaluator.is_running


# TEST 9 ------------------------------------------------------------------
def test_config_interval_default_env_override_invalid(monkeypatch):
    assert Settings(_env_file=None).sla_check_interval_seconds == 60

    monkeypatch.setenv("SAST_SLA_CHECK_INTERVAL_SECONDS", "5")
    assert Settings(_env_file=None).sla_check_interval_seconds == 5

    monkeypatch.setenv("SAST_SLA_CHECK_INTERVAL_SECONDS", "abc")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)

    for bad in (0, -1, -60):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, sla_check_interval_seconds=bad)


# TEST 10 -----------------------------------------------------------------
def test_manual_check_and_background_evaluator_agree(client, registered_sqli):
    client.post(f"/api/findings/{registered_sqli.id}/risk")
    sla = client.post(f"/api/findings/{registered_sqli.id}/sla").json()
    started = datetime.fromisoformat(sla["started_at"])
    now = started + timedelta(hours=30)

    stats = client.app.state.sla_evaluator.evaluate_once(now=now)
    assert stats.breached == 1
    body = client.get(f"/api/findings/{registered_sqli.id}/sla").json()
    assert body["status"] == "breached"
    assert body["escalation_level"] == 1

    later = client.post(
        f"/api/findings/{registered_sqli.id}/sla/check",
        json={"now": (now + timedelta(hours=10)).isoformat()},
    ).json()
    assert later["sla"]["status"] == "breached"
    assert later["escalation"] is None  # manual check agrees: no duplicate

    reset_risk_stores()
    client.post(f"/api/findings/{registered_sqli.id}/risk")
    client.post(f"/api/findings/{registered_sqli.id}/sla")
    fresh = client.post(
        f"/api/findings/{registered_sqli.id}/sla/check",
        json={"now": (started + timedelta(hours=40)).isoformat()},
    ).json()
    assert fresh["sla"]["status"] == "breached"
    assert fresh["escalation"]["new_level"] == 1

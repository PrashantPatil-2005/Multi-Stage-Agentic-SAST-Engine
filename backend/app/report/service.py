"""Security report service.

Collects data from all existing stores and generates comprehensive
security assessment reports in PDF and JSON formats.
"""

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from app.approval.store import get_approval_store
from app.benchmark.service import list_reports
from app.db.models import Project
from app.dedup.service import all_groups
from app.prove.store import get_proof_store
from app.remediation.store import get_remediation_store
from app.report.models import (
    ReportApprovalSummary,
    ReportBenchmarkSummary,
    ReportFindingDetail,
    ReportFindingSummary,
    ReportProofSummary,
    ReportProjectInfo,
    ReportRemediationSummary,
    ReportSlaSummary,
    ReportValidationSummary,
    SecurityReport,
)
from app.risk.service import all_risk_assessments, all_sla_records
from app.scan.run_store import get_scan_run_store
from app.validate.store import get_finding_store, get_validation_store

logger = logging.getLogger(__name__)

_MAX_FINDINGS_IN_REPORT = 100


class ReportService:
    """Service for generating security assessment reports."""

    def __init__(self, session_factory=None) -> None:
        self._session_factory = session_factory

    def generate_report(
        self,
        project_id: str | None = None,
    ) -> SecurityReport:
        """Generate a security assessment report.

        Args:
            project_id: If provided, generate report for single project.
                       If None, generate aggregated report for all projects.

        Returns:
            SecurityReport with all collected data.
        """
        report_id = hashlib.sha256(
            f"{project_id}|{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:32]

        # Collect project information
        projects = self._get_projects(project_id)
        
        # Get finding IDs for the scope
        scoped_finding_ids = self._get_scoped_finding_ids(project_id)
        
        # Collect all data
        findings = self._get_findings(scoped_finding_ids)
        validations = self._get_validations(scoped_finding_ids)
        proofs = self._get_proofs(scoped_finding_ids)
        approvals = self._get_approvals(scoped_finding_ids)
        sla_records = self._get_sla_records(scoped_finding_ids)
        remediation_records = self._get_remediations(scoped_finding_ids)
        benchmark_reports = list_reports()

        # Build summaries
        findings_summary = self._build_findings_summary(findings)
        validation_summary = self._build_validation_summary(findings, validations)
        proof_summary = self._build_proof_summary(findings, proofs)
        approval_summary = self._build_approval_summary(findings, approvals)
        remediation_summary = self._build_remediation_summary(findings, remediation_records)
        sla_summary = self._build_sla_summary(sla_records)
        benchmark_summary = self._build_benchmark_summary(benchmark_reports)

        # Build detailed findings (limited for readability)
        detailed_findings = self._build_detailed_findings(
            findings, validations, proofs, approvals, sla_records
        )

        # Build limitations
        limitations = self._build_limitations(
            findings, validations, proofs, approvals, sla_records
        )

        report = SecurityReport(
            report_id=report_id,
            generated_at=datetime.now(timezone.utc),
            report_type="single_project" if project_id else "aggregated",
            projects=projects,
            total_projects=len(projects),
            total_findings=len(findings),
            findings_summary=findings_summary,
            validation_summary=validation_summary,
            proof_summary=proof_summary,
            approval_summary=approval_summary,
            remediation_summary=remediation_summary,
            sla_summary=sla_summary,
            benchmark_summary=benchmark_summary,
            findings=detailed_findings,
            limitations=limitations,
        )

        logger.info(
            "Security report generated: id=%s type=%s projects=%d findings=%d",
            report_id[:12],
            report.report_type,
            report.total_projects,
            report.total_findings,
        )

        return report

    def _get_projects(self, project_id: str | None) -> list[ReportProjectInfo]:
        """Get project information for the report."""
        if self._session_factory is None:
            return []
        
        with self._session_factory() as session:
            if project_id:
                project = session.get(Project, project_id)
                if project is None:
                    return []
                return [self._project_to_info(project)]
            else:
                projects = session.query(Project).order_by(Project.created_at.desc()).all()
                return [self._project_to_info(p) for p in projects]

    def _project_to_info(self, project: Project) -> ReportProjectInfo:
        """Convert a Project ORM model to ReportProjectInfo."""
        return ReportProjectInfo(
            project_id=project.id,
            name=project.name,
            source_type=project.source_type,
            language=project.language,
            status=project.status,
            location=project.location,
            created_at=project.created_at,
        )

    def _get_scoped_finding_ids(self, project_id: str | None) -> set[str] | None:
        """Get finding IDs scoped to a project via scan run lineage."""
        if project_id is None:
            return None  # No scoping

        run_store = get_scan_run_store()
        runs = run_store.runs_for_project(project_id)
        if not runs:
            return set()  # Project exists but has no scans

        ids: set[str] = set()
        for run in runs:
            ids.update(run_store.finding_ids_for_run(run.scan_run_id))
        return ids

    def _get_findings(self, scoped_ids: set[str] | None):
        """Get findings, optionally scoped to specific IDs."""
        all_findings = get_finding_store().all()
        if scoped_ids is None:
            return {f.id: f for f in all_findings}
        return {f.id: f for f in all_findings if f.id in scoped_ids}

    def _get_validations(self, scoped_ids: set[str] | None):
        """Get validations, optionally scoped to specific finding IDs."""
        all_validations = get_validation_store().all()
        if scoped_ids is None:
            return {v.finding_id: v for v in all_validations}
        return {v.finding_id: v for v in all_validations if v.finding_id in scoped_ids}

    def _get_proofs(self, scoped_ids: set[str] | None):
        """Get proofs, optionally scoped to specific finding IDs."""
        all_proofs = get_proof_store().all()
        if scoped_ids is None:
            return {p.finding_id: p for p in all_proofs}
        return {p.finding_id: p for p in all_proofs if p.finding_id in scoped_ids}

    def _get_approvals(self, scoped_ids: set[str] | None):
        """Get approvals, optionally scoped to specific finding IDs."""
        all_approvals = get_approval_store().all()
        if scoped_ids is None:
            return {a.finding_id: a for a in all_approvals}
        return {a.finding_id: a for a in all_approvals if a.finding_id in scoped_ids}

    def _get_sla_records(self, scoped_ids: set[str] | None):
        """Get SLA records, optionally scoped to specific finding IDs."""
        all_sla = all_sla_records()
        if scoped_ids is None:
            return {s.finding_id: s for s in all_sla}
        return {s.finding_id: s for s in all_sla if s.finding_id in scoped_ids}

    def _get_remediations(self, scoped_ids: set[str] | None):
        """Get remediation records, optionally scoped to specific finding IDs."""
        all_remediations = get_remediation_store().all()
        if scoped_ids is None:
            return {r.finding_id: r for r in all_remediations}
        return {r.finding_id: r for r in all_remediations if r.finding_id in scoped_ids}

    def _build_findings_summary(self, findings: dict) -> ReportFindingSummary:
        """Build findings summary with severity, type, and status breakdowns."""
        by_severity: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}

        for finding in findings.values():
            # Severity
            severity = finding.severity
            by_severity[severity] = by_severity.get(severity, 0) + 1

            # Type
            vuln_type = finding.vulnerability_type
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

            # Status
            status = finding.status
            by_status[status] = by_status.get(status, 0) + 1

        return ReportFindingSummary(
            total=len(findings),
            by_severity=by_severity,
            by_type=by_type,
            by_status=by_status,
        )

    def _build_validation_summary(
        self, findings: dict, validations: dict
    ) -> ReportValidationSummary:
        """Build validation summary."""
        total_validated = len(validations)
        true_positive = sum(1 for v in validations.values() if v.verdict == "true_positive")
        false_positive = sum(1 for v in validations.values() if v.verdict == "false_positive")
        uncertain = sum(1 for v in validations.values() if v.verdict == "uncertain")
        pending_validation = max(0, len(findings) - total_validated)

        return ReportValidationSummary(
            total_validated=total_validated,
            true_positive=true_positive,
            false_positive=false_positive,
            uncertain=uncertain,
            pending_validation=pending_validation,
        )

    def _build_proof_summary(
        self, findings: dict, proofs: dict
    ) -> ReportProofSummary:
        """Build proof summary."""
        total_proven = len(proofs)
        verified = sum(1 for p in proofs.values() if p.status == "verified")
        not_verified = sum(1 for p in proofs.values() if p.status == "not_verified")
        blocked = sum(1 for p in proofs.values() if p.status == "blocked")
        error = sum(1 for p in proofs.values() if p.status == "error")

        return ReportProofSummary(
            total_proven=total_proven,
            verified=verified,
            not_verified=not_verified,
            blocked=blocked,
            error=error,
        )

    def _build_approval_summary(
        self, findings: dict, approvals: dict
    ) -> ReportApprovalSummary:
        """Build approval summary."""
        total_requests = len(approvals)
        approved = sum(1 for a in approvals.values() if a.status == "approved")
        rejected = sum(1 for a in approvals.values() if a.status == "rejected")
        pending = sum(1 for a in approvals.values() if a.status == "pending")
        changes_requested = sum(
            1 for a in approvals.values() if a.status == "changes_requested"
        )

        return ReportApprovalSummary(
            total_requests=total_requests,
            approved=approved,
            rejected=rejected,
            pending=pending,
            changes_requested=changes_requested,
        )

    def _build_remediation_summary(
        self, findings: dict, remediations: dict
    ) -> ReportRemediationSummary:
        """Build remediation summary."""
        total_remediations = len(remediations)
        pending = sum(1 for r in remediations.values() if r.status == "pending")
        in_progress = sum(1 for r in remediations.values() if r.status == "in_progress")
        completed = sum(1 for r in remediations.values() if r.status == "completed")

        return ReportRemediationSummary(
            total_remediations=total_remediations,
            pending=pending,
            in_progress=in_progress,
            completed=completed,
        )

    def _build_sla_summary(self, sla_records: dict) -> ReportSlaSummary:
        """Build SLA summary."""
        total_records = len(sla_records)
        active = sum(1 for s in sla_records.values() if s.status == "active")
        breached = sum(1 for s in sla_records.values() if s.status == "breached")
        resolved = sum(1 for s in sla_records.values() if s.status == "resolved")
        not_applicable = sum(
            1 for s in sla_records.values() if s.status == "not_applicable"
        )

        return ReportSlaSummary(
            total_records=total_records,
            active=active,
            breached=breached,
            resolved=resolved,
            not_applicable=not_applicable,
        )

    def _build_benchmark_summary(self, benchmark_reports: list) -> ReportBenchmarkSummary:
        """Build benchmark summary."""
        fixtures_tested = list({r.fixture for r in benchmark_reports})
        return ReportBenchmarkSummary(
            total_benchmarks=len(benchmark_reports),
            fixtures_tested=fixtures_tested,
        )

    def _build_detailed_findings(
        self,
        findings: dict,
        validations: dict,
        proofs: dict,
        approvals: dict,
        sla_records: dict,
    ) -> list[ReportFindingDetail]:
        """Build detailed findings list (limited for readability)."""
        details = []
        risk_assessments = {r.finding_id: r for r in all_risk_assessments()}

        for finding in findings.values():
            # Get related data
            validation = validations.get(finding.id)
            proof = proofs.get(finding.id)
            approval = approvals.get(finding.id)
            sla = sla_records.get(finding.id)
            risk = risk_assessments.get(finding.id)

            # Determine status
            status = "candidate"
            if approval:
                status = approval.status
            elif proof:
                status = proof.status
            elif validation:
                status = validation.verdict

            detail = ReportFindingDetail(
                finding_id=finding.id,
                vulnerability_type=finding.vulnerability_type,
                severity=finding.severity,
                confidence=finding.confidence,
                source_file=finding.source.file,
                source_line=finding.source.line,
                source_snippet=finding.source.snippet or "",
                sink_file=finding.sink.file,
                sink_line=finding.sink.line,
                sink_snippet=finding.sink.snippet or "",
                status=status,
                priority=risk.priority if risk else None,
                risk_score=risk.risk_score if risk else None,
                validation_verdict=validation.verdict if validation else None,
                validation_confidence=validation.confidence if validation else None,
                proof_status=proof.status if proof else None,
                approval_status=approval.status if approval else None,
                sla_status=sla.status if sla else None,
            )
            details.append(detail)

            if len(details) >= _MAX_FINDINGS_IN_REPORT:
                break

        return details

    def _build_limitations(
        self,
        findings: dict,
        validations: dict,
        proofs: dict,
        approvals: dict,
        sla_records: dict,
    ) -> list[str]:
        """Build list of report limitations."""
        limitations = []

        if not findings:
            limitations.append("No findings available for analysis.")
        
        if not validations:
            limitations.append("No validation results available - findings are unvalidated candidates.")
        
        if not proofs:
            limitations.append("No proof results available - vulnerabilities not dynamically confirmed.")
        
        if not approvals:
            limitations.append("No approval records available - findings pending human review.")
        
        if not sla_records:
            limitations.append("No SLA tracking data available.")

        unvalidated = len(findings) - len(validations)
        if unvalidated > 0:
            limitations.append(
                f"{unvalidated} finding(s) have not been validated by LLM triage."
            )

        limitations.append(
            "This report is generated from automated analysis and should be "
            "reviewed by security professionals."
        )

        return limitations

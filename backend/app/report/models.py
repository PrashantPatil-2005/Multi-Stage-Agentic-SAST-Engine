"""Pydantic models for security report generation."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class ReportProjectInfo(BaseModel):
    """Repository/project details for the report."""
    project_id: str
    name: str
    source_type: str
    language: str
    status: str
    location: str
    created_at: datetime


class ReportFindingSummary(BaseModel):
    """Summary of findings for the report."""
    total: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)


class ReportValidationSummary(BaseModel):
    """Validation results summary."""
    total_validated: int = 0
    true_positive: int = 0
    false_positive: int = 0
    uncertain: int = 0
    pending_validation: int = 0


class ReportProofSummary(BaseModel):
    """Proof results summary."""
    total_proven: int = 0
    verified: int = 0
    not_verified: int = 0
    blocked: int = 0
    error: int = 0


class ReportApprovalSummary(BaseModel):
    """Approval status summary."""
    total_requests: int = 0
    approved: int = 0
    rejected: int = 0
    pending: int = 0
    changes_requested: int = 0


class ReportRemediationSummary(BaseModel):
    """Remediation status summary."""
    total_remediations: int = 0
    pending: int = 0
    in_progress: int = 0
    completed: int = 0


class ReportSlaSummary(BaseModel):
    """SLA status summary."""
    total_records: int = 0
    active: int = 0
    breached: int = 0
    resolved: int = 0
    not_applicable: int = 0


class ReportBenchmarkSummary(BaseModel):
    """Benchmark results summary."""
    total_benchmarks: int = 0
    fixtures_tested: list[str] = Field(default_factory=list)


class ReportFindingDetail(BaseModel):
    """Detailed finding for the report."""
    finding_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    source_file: str
    source_line: int
    source_snippet: str
    sink_file: str
    sink_line: int
    sink_snippet: str
    status: str
    priority: str | None = None
    risk_score: float | None = None
    validation_verdict: str | None = None
    validation_confidence: float | None = None
    proof_status: str | None = None
    approval_status: str | None = None
    sla_status: str | None = None


class SecurityReport(BaseModel):
    """Complete security assessment report."""
    report_id: str
    generated_at: datetime
    report_type: Literal["single_project", "aggregated"]
    
    # Project information
    projects: list[ReportProjectInfo] = Field(default_factory=list)
    
    # Executive summary
    total_projects: int = 0
    total_findings: int = 0
    
    # Findings summary
    findings_summary: ReportFindingSummary = Field(default_factory=ReportFindingSummary)
    
    # Validation results
    validation_summary: ReportValidationSummary = Field(default_factory=ReportValidationSummary)
    
    # Proof results
    proof_summary: ReportProofSummary = Field(default_factory=ReportProofSummary)
    
    # Approval status
    approval_summary: ReportApprovalSummary = Field(default_factory=ReportApprovalSummary)
    
    # Remediation status
    remediation_summary: ReportRemediationSummary = Field(default_factory=ReportRemediationSummary)
    
    # SLA status
    sla_summary: ReportSlaSummary = Field(default_factory=ReportSlaSummary)
    
    # Benchmark results
    benchmark_summary: ReportBenchmarkSummary = Field(default_factory=ReportBenchmarkSummary)
    
    # Detailed findings (limited for readability)
    findings: list[ReportFindingDetail] = Field(default_factory=list)
    
    # Limitations
    limitations: list[str] = Field(default_factory=list)


class ReportRequest(BaseModel):
    """Request model for report generation."""
    project_id: str | None = None  # None = aggregated report
    format: Literal["pdf", "json"] = "pdf"

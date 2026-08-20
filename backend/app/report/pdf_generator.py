"""PDF generator for security reports.

Generates professional PDF reports using reportlab.
"""

import io
import logging
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.report.models import SecurityReport

logger = logging.getLogger(__name__)

# Color palette
PRIMARY_COLOR = colors.HexColor("#2563EB")  # Blue
SECONDARY_COLOR = colors.HexColor("#64748B")  # Slate
SUCCESS_COLOR = colors.HexColor("#16A34A")  # Green
WARNING_COLOR = colors.HexColor("#D97706")  # Amber
DANGER_COLOR = colors.HexColor("#DC2626")  # Red
LIGHT_BG = colors.HexColor("#F8FAFC")  # Light slate


def _create_styles():
    """Create custom paragraph styles."""
    styles = getSampleStyleSheet()
    
    styles.add(ParagraphStyle(
        name='ReportTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=PRIMARY_COLOR,
        spaceAfter=6,
        alignment=TA_CENTER,
    ))
    
    styles.add(ParagraphStyle(
        name='ReportSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=SECONDARY_COLOR,
        spaceAfter=20,
        alignment=TA_CENTER,
    ))
    
    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=PRIMARY_COLOR,
        spaceBefore=20,
        spaceAfter=10,
        borderWidth=1,
        borderColor=PRIMARY_COLOR,
        borderPadding=5,
    ))
    
    styles.add(ParagraphStyle(
        name='SubSectionHeader',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=SECONDARY_COLOR,
        spaceBefore=10,
        spaceAfter=6,
    ))
    
    styles.add(ParagraphStyle(
        name='KPIValue',
        parent=styles['Normal'],
        fontSize=20,
        textColor=PRIMARY_COLOR,
        alignment=TA_CENTER,
        spaceAfter=4,
    ))
    
    styles.add(ParagraphStyle(
        name='KPILabel',
        parent=styles['Normal'],
        fontSize=9,
        textColor=SECONDARY_COLOR,
        alignment=TA_CENTER,
        spaceAfter=8,
    ))
    
    styles.add(ParagraphStyle(
        name='TableHeader',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.white,
        alignment=TA_CENTER,
    ))
    
    styles.add(ParagraphStyle(
        name='TableCell',
        parent=styles['Normal'],
        fontSize=8,
        alignment=TA_LEFT,
    ))
    
    styles.add(ParagraphStyle(
        name='Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=SECONDARY_COLOR,
        alignment=TA_CENTER,
    ))
    
    return styles


def _add_page_number(canvas, doc):
    """Add page number and footer to each page."""
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(SECONDARY_COLOR)
    canvas.drawCentredString(
        letter[0] / 2,
        0.5 * inch,
        f"Page {doc.page} | Security Assessment Report | Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    canvas.restoreState()


def _create_title_page(story, styles, report: SecurityReport):
    """Create the title page."""
    story.append(Spacer(1, 2 * inch))
    story.append(Paragraph("Security Assessment Report", styles['ReportTitle']))
    story.append(Spacer(1, 0.3 * inch))
    
    if report.report_type == "single_project" and report.projects:
        project_name = report.projects[0].name
        story.append(Paragraph(f"Repository: {project_name}", styles['ReportSubtitle']))
    else:
        story.append(Paragraph("Aggregated Report - All Repositories", styles['ReportSubtitle']))
    
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        f"Generated: {report.generated_at.strftime('%B %d, %Y at %H:%M UTC')}",
        styles['ReportSubtitle']
    ))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        f"Report ID: {report.report_id}",
        styles['ReportSubtitle']
    ))
    
    story.append(PageBreak())


def _create_executive_summary(story, styles, report: SecurityReport):
    """Create executive summary section."""
    story.append(Paragraph("Executive Summary", styles['SectionHeader']))
    story.append(Spacer(1, 0.2 * inch))
    
    # KPI Table
    kpi_data = [
        [
            Paragraph(str(report.total_projects), styles['KPIValue']),
            Paragraph(str(report.total_findings), styles['KPIValue']),
            Paragraph(
                str(report.sla_summary.breached),
                styles['KPIValue']
            ),
            Paragraph(
                str(report.validation_summary.true_positive),
                styles['KPIValue']
            ),
        ],
        [
            Paragraph("Projects", styles['KPILabel']),
            Paragraph("Total Findings", styles['KPILabel']),
            Paragraph("SLA Breaches", styles['KPILabel']),
            Paragraph("True Positives", styles['KPILabel']),
        ],
    ]
    
    kpi_table = Table(kpi_data, colWidths=[1.5 * inch] * 4)
    kpi_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, colors.white),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.white),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 10),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 0.3 * inch))
    
    # Risk Assessment
    story.append(Paragraph("Risk Assessment", styles['SubSectionHeader']))
    
    if report.total_findings == 0:
        story.append(Paragraph(
            "No security findings detected. The codebase appears to be clean.",
            styles['Normal']
        ))
    else:
        risk_text = f"The scan identified <b>{report.total_findings}</b> security finding(s) across "
        risk_text += f"<b>{report.total_projects}</b> repository(ies). "
        
        if report.sla_summary.breached > 0:
            risk_text += f"<b>{report.sla_summary.breached}</b> finding(s) have breached SLA deadlines and require immediate attention. "
        
        if report.validation_summary.false_positive > 0:
            risk_text += f"The LLM validation suppressed <b>{report.validation_summary.false_positive}</b> false positive(s). "
        
        story.append(Paragraph(risk_text, styles['Normal']))
    
    story.append(PageBreak())


def _create_findings_section(story, styles, report: SecurityReport):
    """Create security findings section."""
    story.append(Paragraph("Security Findings", styles['SectionHeader']))
    story.append(Spacer(1, 0.2 * inch))
    
    # Findings by Severity
    story.append(Paragraph("Findings by Severity", styles['SubSectionHeader']))
    
    if report.findings_summary.by_severity:
        severity_data = [["Severity", "Count", "Percentage"]]
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = report.findings_summary.by_severity.get(severity, 0)
            if count > 0:
                pct = (count / report.total_findings * 100) if report.total_findings > 0 else 0
                severity_data.append([
                    severity.upper(),
                    str(count),
                    f"{pct:.1f}%"
                ])
        
        severity_table = Table(severity_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
        ]))
        story.append(severity_table)
    else:
        story.append(Paragraph("No findings available.", styles['Normal']))
    
    story.append(Spacer(1, 0.2 * inch))
    
    # Findings by Type
    story.append(Paragraph("Findings by Vulnerability Type", styles['SubSectionHeader']))
    
    if report.findings_summary.by_type:
        type_data = [["Vulnerability Type", "Count"]]
        for vuln_type, count in sorted(
            report.findings_summary.by_type.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            type_data.append([vuln_type.replace("_", " ").title(), str(count)])
        
        type_table = Table(type_data, colWidths=[3 * inch, 2 * inch])
        type_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
        ]))
        story.append(type_table)
    
    story.append(PageBreak())


def _create_detailed_findings(story, styles, report: SecurityReport):
    """Create detailed findings table."""
    story.append(Paragraph("Detailed Findings", styles['SectionHeader']))
    story.append(Spacer(1, 0.2 * inch))
    
    if not report.findings:
        story.append(Paragraph("No detailed findings available.", styles['Normal']))
        return
    
    story.append(Paragraph(
        f"Showing {len(report.findings)} of {report.total_findings} findings",
        styles['Normal']
    ))
    story.append(Spacer(1, 0.1 * inch))
    
    # Findings table
    header = ["ID", "Type", "Severity", "File", "Line", "Status"]
    data = [header]
    
    for finding in report.findings[:20]:  # Limit to 20 for readability
        data.append([
            finding.finding_id[:12],
            finding.vulnerability_type.replace("_", " ").title()[:20],
            finding.severity.upper(),
            finding.source_file[:30],
            str(finding.source_line),
            finding.status.replace("_", " ").title()[:15],
        ])
    
    findings_table = Table(data, colWidths=[1 * inch, 1.3 * inch, 0.8 * inch, 1.5 * inch, 0.5 * inch, 1.2 * inch])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(findings_table)
    
    if report.total_findings > 20:
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(
            f"... and {report.total_findings - 20} more findings. See JSON export for complete data.",
            styles['Normal']
        ))
    
    story.append(PageBreak())


def _create_validation_section(story, styles, report: SecurityReport):
    """Create validation and proof section."""
    story.append(Paragraph("Validation & Proof Results", styles['SectionHeader']))
    story.append(Spacer(1, 0.2 * inch))
    
    # Validation Summary
    story.append(Paragraph("LLM Validation Summary", styles['SubSectionHeader']))
    
    val_data = [
        ["Metric", "Count"],
        ["Total Validated", str(report.validation_summary.total_validated)],
        ["True Positives", str(report.validation_summary.true_positive)],
        ["False Positives", str(report.validation_summary.false_positive)],
        ["Uncertain", str(report.validation_summary.uncertain)],
        ["Pending Validation", str(report.validation_summary.pending_validation)],
    ]
    
    val_table = Table(val_data, colWidths=[3 * inch, 2 * inch])
    val_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
    ]))
    story.append(val_table)
    story.append(Spacer(1, 0.3 * inch))
    
    # Proof Summary
    story.append(Paragraph("Proof Verification Summary", styles['SubSectionHeader']))
    
    proof_data = [
        ["Metric", "Count"],
        ["Total Proven", str(report.proof_summary.total_proven)],
        ["Verified", str(report.proof_summary.verified)],
        ["Not Verified", str(report.proof_summary.not_verified)],
        ["Blocked", str(report.proof_summary.blocked)],
        ["Errors", str(report.proof_summary.error)],
    ]
    
    proof_table = Table(proof_data, colWidths=[3 * inch, 2 * inch])
    proof_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
    ]))
    story.append(proof_table)
    
    story.append(PageBreak())


def _create_sla_section(story, styles, report: SecurityReport):
    """Create SLA and approval section."""
    story.append(Paragraph("SLA & Approval Status", styles['SectionHeader']))
    story.append(Spacer(1, 0.2 * inch))
    
    # SLA Summary
    story.append(Paragraph("SLA Tracking", styles['SubSectionHeader']))
    
    sla_data = [
        ["Metric", "Count"],
        ["Total SLA Records", str(report.sla_summary.total_records)],
        ["Active", str(report.sla_summary.active)],
        ["Breached", str(report.sla_summary.breached)],
        ["Resolved", str(report.sla_summary.resolved)],
        ["Not Applicable", str(report.sla_summary.not_applicable)],
    ]
    
    sla_table = Table(sla_data, colWidths=[3 * inch, 2 * inch])
    sla_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
    ]))
    story.append(sla_table)
    story.append(Spacer(1, 0.3 * inch))
    
    # Approval Summary
    story.append(Paragraph("Approval Workflow", styles['SubSectionHeader']))
    
    approval_data = [
        ["Metric", "Count"],
        ["Total Requests", str(report.approval_summary.total_requests)],
        ["Approved", str(report.approval_summary.approved)],
        ["Rejected", str(report.approval_summary.rejected)],
        ["Pending", str(report.approval_summary.pending)],
        ["Changes Requested", str(report.approval_summary.changes_requested)],
    ]
    
    approval_table = Table(approval_data, colWidths=[3 * inch, 2 * inch])
    approval_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
    ]))
    story.append(approval_table)
    
    # Remediation Summary
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("Remediation Status", styles['SubSectionHeader']))
    
    remediation_data = [
        ["Metric", "Count"],
        ["Total Remediations", str(report.remediation_summary.total_remediations)],
        ["Pending", str(report.remediation_summary.pending)],
        ["In Progress", str(report.remediation_summary.in_progress)],
        ["Completed", str(report.remediation_summary.completed)],
    ]
    
    remediation_table = Table(remediation_data, colWidths=[3 * inch, 2 * inch])
    remediation_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
    ]))
    story.append(remediation_table)
    
    story.append(PageBreak())


def _create_benchmark_section(story, styles, report: SecurityReport):
    """Create benchmark results section."""
    story.append(Paragraph("Benchmark Results", styles['SectionHeader']))
    story.append(Spacer(1, 0.2 * inch))
    
    if report.benchmark_summary.total_benchmarks > 0:
        story.append(Paragraph(
            f"Total benchmark runs: {report.benchmark_summary.total_benchmarks}",
            styles['Normal']
        ))
        story.append(Spacer(1, 0.1 * inch))
        
        if report.benchmark_summary.fixtures_tested:
            story.append(Paragraph("Fixtures Tested:", styles['SubSectionHeader']))
            for fixture in report.benchmark_summary.fixtures_tested:
                story.append(Paragraph(f"  - {fixture}", styles['Normal']))
    else:
        story.append(Paragraph(
            "No benchmark results available. Run benchmarks to compare with other tools.",
            styles['Normal']
        ))
    
    story.append(PageBreak())


def _create_limitations_section(story, styles, report: SecurityReport):
    """Create limitations section."""
    story.append(Paragraph("Limitations", styles['SectionHeader']))
    story.append(Spacer(1, 0.2 * inch))
    
    if report.limitations:
        for i, limitation in enumerate(report.limitations, 1):
            story.append(Paragraph(f"{i}. {limitation}", styles['Normal']))
            story.append(Spacer(1, 0.1 * inch))
    else:
        story.append(Paragraph("No specific limitations identified.", styles['Normal']))
    
    story.append(PageBreak())


def _create_final_summary(story, styles, report: SecurityReport):
    """Create final security summary."""
    story.append(Paragraph("Final Security Summary", styles['SectionHeader']))
    story.append(Spacer(1, 0.3 * inch))
    
    # Overall assessment
    if report.total_findings == 0:
        assessment = "SECURE"
        assessment_color = SUCCESS_COLOR
        assessment_text = (
            "The security assessment found no vulnerabilities in the codebase. "
            "The code appears to follow secure coding practices."
        )
    elif report.sla_summary.breached > 0:
        assessment = "AT RISK"
        assessment_color = DANGER_COLOR
        assessment_text = (
            f"The codebase has {report.total_findings} findings with "
            f"{report.sla_summary.breached} SLA breaches requiring immediate attention."
        )
    elif report.validation_summary.true_positive > 0:
        assessment = "NEEDS ATTENTION"
        assessment_color = WARNING_COLOR
        assessment_text = (
            f"The security assessment identified {report.total_findings} findings, "
            f"with {report.validation_summary.true_positive} confirmed true positives."
        )
    else:
        assessment = "UNDER REVIEW"
        assessment_color = WARNING_COLOR
        assessment_text = (
            f"The security assessment identified {report.total_findings} findings "
            f"that require validation and review."
        )
    
    story.append(Paragraph(f"Overall Assessment: {assessment}", styles['SubSectionHeader']))
    story.append(Paragraph(assessment_text, styles['Normal']))
    story.append(Spacer(1, 0.3 * inch))
    
    # Key metrics summary
    story.append(Paragraph("Key Metrics:", styles['SubSectionHeader']))
    metrics = [
        f"Total Findings: {report.total_findings}",
        f"True Positives: {report.validation_summary.true_positive}",
        f"False Positives (Suppressed): {report.validation_summary.false_positive}",
        f"SLA Breaches: {report.sla_summary.breached}",
        f"Approved Findings: {report.approval_summary.approved}",
        f"Remediations Completed: {report.remediation_summary.completed}",
    ]
    for metric in metrics:
        story.append(Paragraph(f"  - {metric}", styles['Normal']))
    
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        "This report was generated by the Multi-Stage Agentic SAST Engine. "
        "For questions or concerns, please contact the security team.",
        styles['Footer']
    ))


def generate_pdf(report: SecurityReport) -> bytes:
    """Generate a PDF report from a SecurityReport model.
    
    Args:
        report: The SecurityReport model to generate PDF from.
        
    Returns:
        PDF file content as bytes.
    """
    buffer = io.BytesIO()
    
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    
    styles = _create_styles()
    story = []
    
    # Build report sections
    _create_title_page(story, styles, report)
    _create_executive_summary(story, styles, report)
    _create_findings_section(story, styles, report)
    _create_detailed_findings(story, styles, report)
    _create_validation_section(story, styles, report)
    _create_sla_section(story, styles, report)
    _create_benchmark_section(story, styles, report)
    _create_limitations_section(story, styles, report)
    _create_final_summary(story, styles, report)
    
    # Build PDF
    doc.build(story, onFirstPage=_add_page_number, onLaterPages=_add_page_number)
    
    buffer.seek(0)
    return buffer.read()

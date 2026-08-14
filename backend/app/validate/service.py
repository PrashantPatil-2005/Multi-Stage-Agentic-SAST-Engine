"""ValidationService: the VALIDATE stage entry point.

Flow::

    CandidateFinding
          | EvidenceBuilder (redacted, deterministic)
          v
    ValidationRequest
          | LLMProvider.validate (Pydantic-validated, repair-once, UNCERTAIN fallback)
          v
    ValidationResult

The original CandidateFinding is never modified; validation information is
attached/stored separately. Scanner confidence and LLM confidence remain
distinct values.
"""

import logging
import time
from datetime import datetime, timezone

from app.scan.models import CandidateFinding, ScanReport
from app.validate.evidence import EvidenceBuilder
from app.validate.models import ValidationRequest, ValidationResult
from app.validate.providers import get_provider
from app.validate.providers.base import ConfigurationError, LLMProvider

logger = logging.getLogger(__name__)


class ValidationService:
    def __init__(self, provider: LLMProvider | None = None) -> None:
        self._provider = provider

    # ------------------------------------------------------------------ validate

    def validate(
        self,
        finding: CandidateFinding,
        *,
        sources: dict[str, str] | None = None,
        provider: LLMProvider | None = None,
        provider_name: str | None = None,
    ) -> ValidationResult:
        """Validate one candidate finding against an LLM provider."""
        llm = provider or self._provider or get_provider(provider_name)
        evidence = EvidenceBuilder(sources).build(finding)
        request = ValidationRequest(
            finding_id=finding.id,
            evidence=evidence,
            provider=llm.provider_name,
            model=llm.model,
        )
        started = time.perf_counter()
        result = llm.validate(request)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.info(
            "VALIDATE finding_id=%s vuln=%s provider=%s model=%s verdict=%s duration_ms=%.1f",
            finding.id,
            finding.vulnerability_type,
            llm.provider_name,
            llm.model,
            result.verdict,
            duration_ms,
        )
        return result

    def validate_report(
        self,
        scan_report: ScanReport,
        *,
        sources: dict[str, str] | None = None,
        provider: LLMProvider | None = None,
        provider_name: str | None = None,
    ) -> list[ValidationResult]:
        """Validate every candidate independently, in deterministic order.

        Findings are validated one at a time (no concurrency yet) and each
        result keeps its finding id. Evidence never mixes between findings.
        """
        results: list[ValidationResult] = []
        for finding in scan_report.findings:  # already sorted by sink.file/line
            results.append(
                self.validate(
                    finding,
                    sources=sources,
                    provider=provider,
                    provider_name=provider_name,
                )
            )
        return results

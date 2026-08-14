"""Deterministic evidence package builder for VALIDATE.

Turns one CandidateFinding into a :class:`ValidationEvidence` containing
only the code relevant to the finding (source, sink, taint path, and a small
surrounding context window when the file sources are available). Every
snippet is passed through the secret redactor before it can leave the
process.
"""

from app.scan.models import CandidateFinding
from app.validate.models import ValidationEvidence
from app.validate.redaction import redact_secrets

_CONTEXT_WINDOW = 3  # lines of surrounding context on each side


class EvidenceBuilder:
    """Builds the exact evidence package used for one validation."""

    def __init__(self, sources: dict[str, str] | None = None) -> None:
        #: relative file path -> full source text (from the CodeModel);
        #: used only to extract small surrounding context windows.
        self._sources = sources or {}

    def build(self, finding: CandidateFinding) -> ValidationEvidence:
        return ValidationEvidence(
            finding_id=finding.id,
            vulnerability_type=finding.vulnerability_type,
            severity=finding.severity,
            scanner_confidence=finding.confidence,
            source_file=finding.source.file,
            source_line=finding.source.line,
            source_snippet=redact_secrets(finding.source.snippet),
            sink_file=finding.sink.file,
            sink_line=finding.sink.line,
            sink_snippet=redact_secrets(finding.sink.snippet),
            taint_path=[
                step.model_copy(
                    update={"snippet": redact_secrets(step.snippet)}
                )
                for step in finding.taint_path
            ],
            relevant_lines=list(finding.evidence.relevant_lines),
            sanitizer_observations=[
                redact_secrets(obs) for obs in finding.evidence.sanitizer_observations
            ],
            surrounding_context=self._surrounding_context(finding),
        )

    # ---------------------------------------------------------------- context

    def _surrounding_context(self, finding: CandidateFinding) -> dict[str, list[str]]:
        context: dict[str, list[str]] = {}
        for file in {finding.source.file, finding.sink.file}:
            source = self._sources.get(file)
            if source is None:
                continue
            lines = source.splitlines()
            wanted: set[int] = set()
            for center in (finding.source.line, finding.sink.line):
                for offset in range(-_CONTEXT_WINDOW, _CONTEXT_WINDOW + 1):
                    wanted.add(center + offset)
            context[file] = [
                redact_secrets(line)
                for index, line in enumerate(lines, start=1)
                if index in wanted
            ]
        return context

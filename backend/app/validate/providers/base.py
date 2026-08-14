"""LLM provider abstraction for VALIDATE.

A provider talks to one model backend and returns structured verdicts. The
shared parsing/repair/fallback logic lives in :class:`LLMProvider.validate`
so every backend behaves identically: parse with Pydantic, retry once with a
repair prompt, and fall back to UNCERTAIN when the model output stays
malformed. Malformed output is never silently trusted.
"""

import hashlib
import json
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from app.validate.models import (
    ValidationMetadata,
    ValidationRequest,
    ValidationResult,
)
from app.validate.prompts import build_repair_prompt, build_validation_prompt


class ConfigurationError(RuntimeError):
    """Raised when no usable LLM configuration is available."""


class LLMResponse(BaseModel):
    """Strict contract for the model's structured output."""

    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    evidence_used: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_next_step: Literal["prove", "discard", "manual_review"]


def parse_llm_response(raw: str) -> LLMResponse | None:
    """Parse + validate the model's raw output; None when unusable."""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    try:
        return LLMResponse.model_validate(data)
    except ValidationError:
        return None


def _evidence_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


class LLMProvider(ABC):
    provider_name: str = "base"

    @abstractmethod
    def _complete(self, prompt: str) -> str:
        """Return the raw model text for a single completion."""

    @property
    def model(self) -> str | None:
        return None

    # -------------------------------------------------------------- validate

    def validate(self, request: ValidationRequest) -> ValidationResult:
        """Template method: prompt -> complete -> parse -> repair once -> fallback."""
        started = time.perf_counter()
        prompt = build_validation_prompt(request)
        raw = self._complete(prompt)
        retries = 0
        parsed = parse_llm_response(raw)
        while parsed is None and retries < 1:
            retries += 1
            raw = self._complete(build_repair_prompt(request, prompt))
            parsed = parse_llm_response(raw)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        if parsed is None:
            return self._result(
                request,
                verdict="uncertain",
                confidence=0.0,
                reasoning=(
                    "The model returned malformed output even after a repair "
                    "retry; the response was not trusted. Manual review is required."
                ),
                evidence_used=[],
                missing_evidence=["structured model output (JSON)"],
                next_step="manual_review",
                duration_ms=duration_ms,
                retry_count=retries,
            )
        return self._result(
            request,
            verdict=parsed.verdict,
            confidence=parsed.confidence,
            reasoning=parsed.reasoning,
            evidence_used=parsed.evidence_used,
            missing_evidence=parsed.missing_evidence,
            next_step=parsed.recommended_next_step,
            duration_ms=duration_ms,
            retry_count=retries,
        )

    # ---------------------------------------------------------------- helpers

    def _result(
        self,
        request: ValidationRequest,
        *,
        verdict: str,
        confidence: float,
        reasoning: str,
        evidence_used: list[str],
        missing_evidence: list[str],
        next_step: str,
        duration_ms: float,
        retry_count: int,
    ) -> ValidationResult:
        return ValidationResult(
            finding_id=request.finding_id,
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            evidence_used=evidence_used,
            missing_evidence=missing_evidence,
            recommended_next_step=next_step,
            model=self.model,
            validated_at=datetime.now(timezone.utc),
            evidence=request.evidence,
            metadata=ValidationMetadata(
                provider=self.provider_name,
                model=self.model,
                duration_ms=duration_ms,
                retry_count=retry_count,
                evidence_hash=_evidence_hash(build_validation_prompt(request)),
            ),
        )

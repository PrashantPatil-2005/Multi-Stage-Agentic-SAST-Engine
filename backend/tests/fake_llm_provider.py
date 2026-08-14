"""Deterministic fake LLM provider for VALIDATE tests.

Never calls a real model. Two usage modes:

* canned response: constructor verdict/confidence/reasoning/... are returned
  for every completion;
* scripted responses: ``script=["...", "..."]`` is consumed one raw string
  per completion (used to exercise the repair/fallback logic in
  ``LLMProvider.validate``).
"""

import json

from app.validate.models import ValidationEvidence
from app.validate.providers.base import LLMProvider

_REPAIR_MARKER = "EVIDENCE PACKAGE (unchanged):"


class FakeLLMProvider(LLMProvider):
    provider_name = "fake"

    def __init__(
        self,
        *,
        verdict: str = "true_positive",
        confidence: float = 0.94,
        reasoning: str = "tainted value reaches the sink through the supplied path",
        evidence_used: list[str] | None = None,
        missing_evidence: list[str] | None = None,
        next_step: str | None = None,
        script: list[str] | None = None,
        model: str = "fake-model",
    ) -> None:
        self._verdict = verdict
        self._confidence = confidence
        self._reasoning = reasoning
        self._evidence_used = evidence_used or ["taint_path", "sink_snippet"]
        self._missing_evidence = missing_evidence or []
        self._next_step = next_step or {
            "true_positive": "prove",
            "false_positive": "discard",
            "uncertain": "manual_review",
        }[verdict]
        self._script = list(script or [])
        self._model = model
        #: recording for leak/grounding assertions
        self.prompts: list[str] = []
        self.evidence_packages: list[ValidationEvidence] = []

    @property
    def model(self) -> str | None:
        return self._model

    def _complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        package = self._extract_evidence(prompt)
        if package is not None:
            self.evidence_packages.append(package)
        if self._script:
            return self._script.pop(0)
        return json.dumps(
            {
                "verdict": self._verdict,
                "confidence": self._confidence,
                "reasoning": self._reasoning,
                "evidence_used": self._evidence_used,
                "missing_evidence": self._missing_evidence,
                "recommended_next_step": self._next_step,
            }
        )

    @staticmethod
    def _extract_evidence(prompt: str) -> ValidationEvidence | None:
        text = prompt
        if _REPAIR_MARKER in text:
            text = text.split(_REPAIR_MARKER, 1)[1].strip()
        try:
            return ValidationEvidence.model_validate(json.loads(text))
        except (json.JSONDecodeError, ValueError):
            return None
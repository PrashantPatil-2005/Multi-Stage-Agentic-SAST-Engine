"""Prompt construction for LLM-assisted validation.

The validator is grounded strictly in the supplied evidence package. Every
claim the model makes must be traceable to that package; everything else is
out of scope. The model is never asked to execute code, make requests, or
produce exploit code.
"""

import json

from app.validate.models import ValidationRequest

SYSTEM_PROMPT = """You are a senior application-security analyst validating a static taint-analysis finding.

You are given a JSON evidence package produced by a deterministic scanner. It contains ONLY:
- the vulnerability type, severity, and the scanner's own confidence
- the tainted source (user-controlled input or function parameter)
- the dangerous sink call
- the taint path (source -> propagation -> sink)
- relevant source lines, sanitizer observations, and a small surrounding context

TASK
1. Analyze the candidate finding.
2. Trace the supplied source -> propagation -> sink path.
3. Determine whether attacker-controlled data can actually reach the dangerous sink.
4. Check whether a sanitizer or safe construction exists anywhere in the supplied evidence.
5. Identify what information is missing (e.g. no sanitizer observed, control flow unknown).
6. Decide: TRUE_POSITIVE, FALSE_POSITIVE, or UNCERTAIN.

GROUNDING RULES (MANDATORY)
- Every claim you make must be traceable to the supplied evidence package.
- NEVER invent source code, execution results, network responses, or evidence.
- If the evidence is insufficient to conclude, return "uncertain".
- NEVER assume a sanitizer exists if it is not shown in the evidence.
- NEVER claim runtime behavior that was not demonstrated by static evidence.
- NEVER claim a request was actually executed or a command was actually run.
- Prefer "uncertain" over an unsupported "true_positive".
- Scanner confidence is SEPARATE from your confidence; do not inherit it.
- Do not mention scanning tools by name.

YOU ARE NOT ALLOWED TO
- execute code
- make network requests
- produce or suggest exploit payloads/PoCs

OUTPUT
Return ONLY a single JSON object (no markdown, no commentary) with exactly this shape:
{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "concise justification, every claim traceable to evidence",
  "evidence_used": ["short labels of the evidence items you relied on"],
  "missing_evidence": ["what you would have needed to be certain"],
  "recommended_next_step": "prove" | "discard" | "manual_review"
}
Map verdict to next step: true_positive -> "prove", false_positive -> "discard",
uncertain -> "manual_review".
"""

REPAIR_PROMPT = """Your previous response was not valid JSON and could not be parsed.

Resend ONLY a single valid JSON object (no markdown, no commentary) with exactly this shape:
{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "string",
  "evidence_used": ["string"],
  "missing_evidence": ["string"],
  "recommended_next_step": "prove" | "discard" | "manual_review"
}
"""


def build_validation_prompt(request: ValidationRequest) -> str:
    """Serialize the exact evidence package for the model."""
    return json.dumps(request.evidence.model_dump(mode="json"), indent=2)


def build_repair_prompt(request: ValidationRequest, original_prompt: str) -> str:
    """Repair prompt: original evidence plus the strict format instruction."""
    return f"{REPAIR_PROMPT}\n\nEVIDENCE PACKAGE (unchanged):\n{original_prompt}"

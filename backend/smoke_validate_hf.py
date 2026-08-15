"""Controlled real Hugging Face validation smoke test (Phase 10).

One VALIDATE call against the configured Hugging Face router using a
developer-provided token from the environment / backend/.env.

Never prints the token. Requires:
  LLM_API_KEY   (or SAST_LLM_API_KEY) - Hugging Face token
  LLM_MODEL     - model id

Usage:
    .\\.venv\\Scripts\\python.exe smoke_validate_hf.py
"""

import logging
import os

from dotenv import load_dotenv

load_dotenv(".env")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s - %(message)s")
    key = os.getenv("LLM_API_KEY", "") or os.getenv("SAST_LLM_API_KEY", "")
    model = os.getenv("LLM_MODEL", "")
    base_url = os.getenv("LLM_BASE_URL", "https://router.huggingface.co/v1")
    if not key:
        print("LLM_API_KEY is not set; cannot run the real smoke test.")
        return 1
    if not model:
        print("LLM_MODEL is not set; cannot run the real smoke test.")
        return 1

    from app.validate.service import ValidationService
    from tests.scan_test_helpers import VULN_APP, scan_fixture_files

    report = scan_fixture_files("app.py", "db.py")
    finding = next(
        (f for f in report.findings if f.vulnerability_type == "sql_injection"),
        report.findings[0],
    )
    sources = {name: (VULN_APP / name).read_text(encoding="utf-8") for name in ("app.py", "db.py")}

    result = ValidationService().validate(
        finding,
        sources=sources,
        provider_name="huggingface",
    )
    print(f"endpoint: {base_url}")
    print(f"model: {result.model}")
    print(f"verdict: {result.verdict}")
    print(f"confidence: {result.confidence}")
    print(f"reasoning: {result.reasoning}")
    print(f"evidence_used: {result.evidence_used}")
    print(f"missing_evidence: {result.missing_evidence}")
    print(f"validated_at: {result.validated_at.isoformat()}")
    print(f"duration_ms: {result.metadata.duration_ms if result.metadata else None}")
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

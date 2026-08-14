"""ProofService: the PROVE stage entry point.

Flow::

    CandidateFinding + ValidationResult
              | gate: ONLY verdict == "true_positive" may proceed
              v
    ProofPlanner (deterministic plan, trusted harness)
              | SandboxRunner (temp workspace, timeout, output caps, cleanup)
              v
    ProofResult

The service never mutates the CandidateFinding or ValidationResult. Finding
snippets are data - they are never executed, never interpolated into the
harness, and never used to build payloads.
"""

import logging
import re
import time
from datetime import datetime, timezone

from app.prove.models import ProofArtifact, ProofRequest, ProofResult, SandboxPolicy
from app.prove.planner import ProofPlan, ProofPlanner
from app.prove.sandbox import ExecutionResult, SandboxRunner
from app.scan.models import CandidateFinding
from app.validate.models import ValidationResult

logger = logging.getLogger(__name__)


class ProofGateError(RuntimeError):
    """Raised when a finding is not eligible for proof (verdict gate)."""


class ProofService:
    def __init__(
        self,
        planner: ProofPlanner | None = None,
        runner: SandboxRunner | None = None,
    ) -> None:
        self._planner = planner or ProofPlanner()
        self._runner = runner or SandboxRunner()

    # ------------------------------------------------------------------- prove

    def prove(
        self,
        finding: CandidateFinding,
        validation_result: ValidationResult | None,
    ) -> ProofResult:
        """Attempt a sandboxed proof; only true_positive findings may proceed."""
        started = time.perf_counter()

        if validation_result is None:
            raise ProofGateError("no validation result recorded for this finding")
        if validation_result.finding_id != finding.id:
            raise ProofGateError("validation result does not match the finding")
        if validation_result.verdict != "true_positive":
            raise ProofGateError(
                f"finding is not eligible for proof: verdict={validation_result.verdict}"
            )

        plan = self._planner.plan(finding)
        if plan is None:
            return self._result(
                finding,
                validation_result,
                plan=None,
                status="not_verified",
                summary=(
                    f"no proof plan exists for vulnerability type "
                    f"{finding.vulnerability_type!r}"
                ),
                duration_ms=(time.perf_counter() - started) * 1000,
                policy=SandboxPolicy(),
            )

        request = ProofRequest(
            finding_id=finding.id,
            vulnerability_type=finding.vulnerability_type,
            objective=plan.objective,
            input_value=plan.input_value,
            harness=plan.harness,
            policy=plan.policy,
        )
        logger.info(
            "PROVE finding_id=%s vuln=%s harness=%s policy_timeout=%.1f",
            finding.id,
            finding.vulnerability_type,
            plan.harness,
            plan.policy.timeout_seconds,
        )

        try:
            execution = self._runner.run(
                plan.harness,
                plan.harness_script,
                plan.input_value,
                policy=plan.policy,
            )
        except Exception as exc:  # noqa: BLE001 - structured error boundary
            logger.exception("PROVE harness run failed for finding %s", finding.id)
            return self._result(
                finding,
                validation_result,
                plan=plan,
                status="error",
                summary="proof harness could not be executed",
                duration_ms=(time.perf_counter() - started) * 1000,
                policy=self._runner.policy,
                error=str(exc),
            )

        status, summary, artifacts = self._interpret(plan, execution)
        duration_ms = (time.perf_counter() - started) * 1000
        return self._result(
            finding,
            validation_result,
            plan=plan,
            status=status,
            summary=summary,
            duration_ms=duration_ms,
            policy=self._runner.policy,
            artifacts=artifacts,
        )

    # -------------------------------------------------------------- interpret

    def _interpret(
        self, plan: ProofPlan, execution: ExecutionResult
    ) -> tuple[str, str, list[ProofArtifact]]:
        """Map controlled harness observations to a proof status."""
        if execution.timed_out:
            return (
                "error",
                "proof harness exceeded the sandbox timeout",
                [ProofArtifact(name="observation", kind="observation", content="timed_out")],
            )
        if execution.returncode != 0:
            return (
                "error",
                f"proof harness failed (rc={execution.returncode}): {execution.stderr[:200]}",
                [
                    ProofArtifact(
                        name="observation",
                        kind="observation",
                        content=f"rc={execution.returncode}",
                    )
                ],
            )

        out = execution.stdout
        if plan.harness == "sql_injection_proof":
            artifacts = self._line_artifacts(out, ("UNSAFE_QUERY", "SAFE_QUERY"))
            match = re.search(r"PROVED:unsafe_rows=(\d+):safe_rows=(\d+)", out)
            if match and int(match.group(1)) != int(match.group(2)):
                return (
                    "verified",
                    (
                        "unsafe string construction returned %s rows while the "
                        "parameterized construction returned %s rows for the same "
                        "benign marker in the local fixture"
                    )
                    % (match.group(1), match.group(2)),
                    artifacts,
                )
            return "not_verified", "unsafe and safe constructions behaved identically", artifacts

        if plan.harness == "command_injection_proof":
            match = re.search(r"PROVED:control_hit=(\d+):injected_hit=(\d+)", out)
            if match and match.group(1) == "0" and match.group(2) == "1":
                return (
                    "verified",
                    (
                        "the benign marker produced the known marker file inside the "
                        "sandbox while the control value did not - the command sink "
                        "interpolates untrusted input into a shell command"
                    ),
                    [
                        ProofArtifact(
                            name="marker_file",
                            kind="marker",
                            content="prove_marker.txt (inside sandbox workspace)",
                        )
                    ],
                )
            return "not_verified", "marker observation did not match expectations", []

        if plan.harness == "ssrf_proof":
            artifacts = self._line_artifacts(out, ("URL",))
            match = re.search(r"PROVED:status=(\d+):body=(\w+)", out)
            if match and match.group(1) == "200" and match.group(2) == "proved":
                return (
                    "verified",
                    (
                        "the request reached the harness-created loopback endpoint "
                        "(127.0.0.1, ephemeral port) and got the expected controlled "
                        "response - input flows into an HTTP request sink"
                    ),
                    artifacts,
                )
            return "not_verified", "loopback endpoint did not answer as expected", artifacts

        return "not_verified", f"no interpretation for harness {plan.harness!r}", []

    @staticmethod
    def _line_artifacts(out: str, prefixes: tuple[str, ...]) -> list[ProofArtifact]:
        artifacts: list[ProofArtifact] = []
        for line in out.splitlines():
            for prefix in prefixes:
                if line.startswith(prefix + ":"):
                    artifacts.append(
                        ProofArtifact(
                            name=prefix.lower(),
                            kind="observation",
                            content=line[len(prefix) + 1 :],
                        )
                    )
        return artifacts

    # ---------------------------------------------------------------- result

    def _result(
        self,
        finding: CandidateFinding,
        validation_result: ValidationResult,
        *,
        plan: ProofPlan | None,
        status: str,
        summary: str,
        duration_ms: float,
        policy: SandboxPolicy,
        artifacts: list[ProofArtifact] | None = None,
        error: str | None = None,
    ) -> ProofResult:
        evidence = []
        if plan is not None:
            evidence.append(
                ProofArtifact(
                    name="plan",
                    kind="plan",
                    content=plan.objective,
                )
            )
            evidence.append(
                ProofArtifact(
                    name="input_value",
                    kind="observation",
                    content=plan.input_value,
                )
            )
        return ProofResult(
            finding_id=finding.id,
            vulnerability_type=finding.vulnerability_type,
            status=status,
            confidence=validation_result.confidence,
            summary=summary,
            evidence=evidence,
            artifacts=artifacts or [],
            duration_ms=round(duration_ms, 2),
            sandbox_policy=policy,
            error=error,
            created_at=datetime.now(timezone.utc),
        )
"""Deterministic, transparent risk scoring (no LLM, no invented facts).

Formula (documented in README.md)::

    base   = severity_weight[severity]
            + validated_bonus    when verdict == true_positive
            + proof_bonus        when proof.status == verified AND policy says so
    false_positive -> score 0, priority P4
    uncertain      -> base only (unconfirmed, no bonus)
    final          = clamp(base, 0, 100)

Factors that are *not* known are never scored: an unvalidated finding gets
no validation factor, an unproven finding gets no proof factor, and an
unknown severity is weighted 0 with an explanatory factor.
"""

from dataclasses import dataclass, field

from app.risk.models import Priority, RiskFactor
from app.scan.models import CandidateFinding

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 5,
}

VALIDATED_BONUS = 10
PROOF_BONUS = 10

PRIORITY_THRESHOLDS: tuple[tuple[int, Priority], ...] = (
    (90, "P0"),
    (75, "P1"),
    (50, "P2"),
    (25, "P3"),
    (0, "P4"),
)


@dataclass(frozen=True)
class RiskPolicy:
    """Configurable weights/thresholds; defaults match the documented model."""

    severity_weights: dict[str, int] = field(
        default_factory=lambda: dict(SEVERITY_WEIGHTS)
    )
    validated_bonus: int = VALIDATED_BONUS
    proof_bonus: int = PROOF_BONUS
    proof_increases_priority: bool = True
    priority_thresholds: tuple[tuple[int, Priority], ...] = PRIORITY_THRESHOLDS


class RiskScorer:
    """Pure function: finding + optional validation/proof -> (score, priority, factors)."""

    def __init__(self, policy: RiskPolicy | None = None) -> None:
        self._policy = policy or RiskPolicy()

    def score(
        self,
        finding: CandidateFinding,
        validation=None,
        proof=None,
    ) -> tuple[int, Priority, list[RiskFactor]]:
        factors: list[RiskFactor] = []
        policy = self._policy

        if validation is not None and validation.verdict == "false_positive":
            factors.append(
                RiskFactor(
                    name="validation",
                    value="false_positive",
                    points=0,
                    description="LLM validation concluded the finding is a false positive; no risk assigned",
                )
            )
            return 0, "P4", factors

        severity = finding.severity
        weight = policy.severity_weights.get(severity.lower())
        if weight is None:
            weight = 0
            factors.append(
                RiskFactor(
                    name="severity",
                    value=severity,
                    points=0,
                    description="severity not in the known weight table; weighted 0 (not fabricated)",
                )
            )
        else:
            factors.append(
                RiskFactor(
                    name="severity",
                    value=severity,
                    points=weight,
                    description=f"base severity weight ({severity.upper()} = {weight})",
                )
            )

        score = weight

        if validation is not None and validation.verdict == "true_positive":
            score += policy.validated_bonus
            factors.append(
                RiskFactor(
                    name="validation",
                    value="true_positive",
                    points=policy.validated_bonus,
                    description="validated as a true positive (exploitable candidate)",
                )
            )
        elif validation is not None and validation.verdict == "uncertain":
            factors.append(
                RiskFactor(
                    name="validation",
                    value="uncertain",
                    points=0,
                    description="validation uncertain - not confirmed, no bonus",
                )
            )

        if proof is not None and proof.status == "verified":
            if policy.proof_increases_priority:
                score += policy.proof_bonus
                factors.append(
                    RiskFactor(
                        name="proof",
                        value="verified",
                        points=policy.proof_bonus,
                        description="sandboxed proof verified exploitability",
                    )
                )
            else:
                factors.append(
                    RiskFactor(
                        name="proof",
                        value="verified",
                        points=0,
                        description="proof verified but policy does not increase priority",
                    )
                )

        score = max(0, min(100, score))
        priority = self._priority_for(score)
        return score, priority, factors

    def _priority_for(self, score: int) -> Priority:
        for threshold, priority in self._policy.priority_thresholds:
            if score >= threshold:
                return priority
        return "P4"
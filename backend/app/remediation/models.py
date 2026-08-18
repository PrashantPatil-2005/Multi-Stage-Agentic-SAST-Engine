"""Remediation workflow contracts (post-approval, human-confirmed fixes).

Remediation is the *final* step of the pipeline and the only place source
code is ever modified - and only under three conditions, all enforced here:

1. an approved approval request (``status == approved``, action
   ``remediation``) exists for the finding;
2. a remediation proposal was generated and the human explicitly confirmed
   it (``POST .../remediation/apply`` with ``confirm=true``);
3. the change is applied to the private workspace copy of the repository
   (``workspace/projects/<id>/repo/``) - never to the user's original
   source, and never through any other endpoint.

A :class:`RemediationProposal` is a deterministic, line-anchored diff
(before/after) computed by the patch generator for a specific finding; when
no safe deterministic fix exists the proposal reports
``strategy="no_automatic_fix"`` and nothing is ever patched.

A :class:`RemediationRecord` tracks the lifecycle of one remediation:
``proposed`` -> ``applied`` -> ``verified`` | ``still_present`` (or
``no_fix_available`` / ``error``). ``verify`` re-runs the scanner against
the current snapshot and checks whether the same finding is still produced;
it never fabricates a result.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

RemediationStatus = Literal[
    "proposed",
    "no_fix_available",
    "applied",
    "verified",
    "still_present",
    "error",
]


class RemediationProposal(BaseModel):
    """One deterministic line-anchored patch proposal for a finding."""

    finding_id: str
    vulnerability_type: str
    file: str
    line: int
    #: "parameterize_query" | "shell_argument_vector" | "shell_quote" |
    #: "no_automatic_fix"
    strategy: str
    before: str
    after: str
    import_to_add: str | None = None
    rationale: str


class RemediationRecord(BaseModel):
    """Persisted lifecycle record of one remediation workflow."""

    finding_id: str
    approval_id: str
    status: RemediationStatus
    proposal: RemediationProposal | None = None
    applied_at: datetime | None = None
    applied_by: str | None = None
    verified_at: datetime | None = None
    verification: str | None = None
    error: str | None = None
    created_at: datetime
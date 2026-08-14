"""Approval policy (configurable).

Default policy gates approval requests behind the full security workflow:

* VALIDATE verdict must be ``true_positive`` (``require_validation``)
* PROVE status must be ``verified`` (``require_proof``)
* only the ``remediation`` action is authorized (``allowed_actions``)

Approval decisions are made by humans; no LLM is involved.
"""

from dataclasses import dataclass, field

DEFAULT_ALLOWED_ACTIONS: tuple[str, ...] = ("remediation",)


@dataclass(frozen=True)
class ApprovalPolicy:
    require_validation: bool = True
    require_proof: bool = True
    allowed_actions: tuple[str, ...] = field(
        default_factory=lambda: DEFAULT_ALLOWED_ACTIONS
    )
    #: Whether a new request may be created after a terminal (approved /
    #: rejected) request for the same finding + action. Default: no.
    allow_re_request_after_terminal: bool = False
"""Centralized role-based access control (RBAC) for the SAST platform.

Defines the four application roles and the permission matrix that maps
roles to capabilities.  All authorization decisions flow through this
module — no raw role-string comparisons in route handlers.

Usage in routes::

    from app.auth.rbac import require_permission

    @router.post("/findings/{id}/validate")
    def validate(..., user: User = Depends(require_permission("validate"))):
        ...

The dependency raises 403 when the authenticated user lacks the required
permission.
"""

from enum import Enum
from typing import FrozenSet

from app.auth.models import Role


# ---------------------------------------------------------------------------
# Permissions — fine-grained capabilities
# ---------------------------------------------------------------------------

class Permission(str, Enum):
    # Read-only
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_REPOSITORIES = "view_repositories"
    VIEW_FINDINGS = "view_findings"
    VIEW_SCAN_RUNS = "view_scan_runs"
    VIEW_VALIDATION = "view_validation"
    VIEW_PROOF = "view_proof"
    VIEW_RISK = "view_risk"
    VIEW_APPROVALS = "view_approvals"
    VIEW_REMEDIATION = "view_remediation"
    VIEW_BENCHMARK = "view_benchmark"

    # Security workflow (analyst)
    SCAN = "scan"
    DEDUPLICATE = "deduplicate"
    VALIDATE = "validate"
    PROVE = "prove"
    ASSESS_RISK = "assess_risk"
    START_SLA = "start_sla"
    CHECK_SLA = "check_sla"
    REQUEST_APPROVAL = "request_approval"

    # Approval workflow (manager)
    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"
    RESUBMIT = "resubmit"
    VIEW_APPROVAL_QUEUE = "view_approval_queue"

    # Remediation (developer)
    PROPOSE_REMEDIATION = "propose_remediation"
    APPLY_REMEDIATION = "apply_remediation"
    VERIFY_REMEDIATION = "verify_remediation"
    REPREPARE = "reprepare"

    # Repository management
    CREATE_REPOSITORY = "create_repository"
    DELETE_REPOSITORY = "delete_repository"

    # Benchmark
    RUN_BENCHMARK = "run_benchmark"


# ---------------------------------------------------------------------------
# Role → Permission mapping
# ---------------------------------------------------------------------------

_ANALYST_PERMISSIONS: FrozenSet[Permission] = frozenset({
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_REPOSITORIES,
    Permission.VIEW_FINDINGS,
    Permission.VIEW_SCAN_RUNS,
    Permission.VIEW_VALIDATION,
    Permission.VIEW_PROOF,
    Permission.VIEW_RISK,
    Permission.VIEW_APPROVALS,
    Permission.VIEW_REMEDIATION,
    Permission.VIEW_BENCHMARK,
    Permission.SCAN,
    Permission.DEDUPLICATE,
    Permission.VALIDATE,
    Permission.PROVE,
    Permission.ASSESS_RISK,
    Permission.START_SLA,
    Permission.CHECK_SLA,
    Permission.REQUEST_APPROVAL,
    Permission.CREATE_REPOSITORY,
    Permission.RUN_BENCHMARK,
})

_MANAGER_PERMISSIONS: FrozenSet[Permission] = frozenset({
    # Manager inherits analyst read + security workflow permissions
    *_ANALYST_PERMISSIONS,
    # Approval workflow
    Permission.APPROVE,
    Permission.REJECT,
    Permission.REQUEST_CHANGES,
    Permission.RESUBMIT,
    Permission.VIEW_APPROVAL_QUEUE,
    # Remediation oversight (manager oversees developer work)
    Permission.PROPOSE_REMEDIATION,
    Permission.APPLY_REMEDIATION,
    Permission.VERIFY_REMEDIATION,
    Permission.REPREPARE,
    # Delete (manager-only destructive action)
    Permission.DELETE_REPOSITORY,
})

_DEVELOPER_PERMISSIONS: FrozenSet[Permission] = frozenset({
    # Developer read access
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_REPOSITORIES,
    Permission.VIEW_FINDINGS,
    Permission.VIEW_SCAN_RUNS,
    Permission.VIEW_VALIDATION,
    Permission.VIEW_PROOF,
    Permission.VIEW_RISK,
    Permission.VIEW_APPROVALS,
    Permission.VIEW_REMEDIATION,
    Permission.VIEW_BENCHMARK,
    # Remediation workflow
    Permission.PROPOSE_REMEDIATION,
    Permission.APPLY_REMEDIATION,
    Permission.VERIFY_REMEDIATION,
    Permission.REPREPARE,
    # Can also scan own repos
    Permission.SCAN,
    Permission.CREATE_REPOSITORY,
})

_AUDITOR_PERMISSIONS: FrozenSet[Permission] = frozenset({
    # Auditor: read-only access to everything
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_REPOSITORIES,
    Permission.VIEW_FINDINGS,
    Permission.VIEW_SCAN_RUNS,
    Permission.VIEW_VALIDATION,
    Permission.VIEW_PROOF,
    Permission.VIEW_RISK,
    Permission.VIEW_APPROVALS,
    Permission.VIEW_REMEDIATION,
    Permission.VIEW_BENCHMARK,
})

ROLE_PERMISSIONS: dict[Role, FrozenSet[Permission]] = {
    "analyst": _ANALYST_PERMISSIONS,
    "manager": _MANAGER_PERMISSIONS,
    "developer": _DEVELOPER_PERMISSIONS,
    "auditor": _AUDITOR_PERMISSIONS,
}


# ---------------------------------------------------------------------------
# Authorization check helpers
# ---------------------------------------------------------------------------

def has_permission(role: Role, permission: Permission) -> bool:
    """Check whether *role* grants *permission*."""
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def require_permission(permission: Permission):
    """FastAPI dependency factory that enforces a single permission.

    Returns the authenticated ``User`` when the check passes, raises 403
    otherwise.

    Usage::

        @router.post("/something")
        def do_something(user: User = Depends(require_permission(Permission.SCAN))):
            ...
    """
    from fastapi import Depends, HTTPException

    from app.auth.dependencies import get_current_user

    def _check(user=Depends(get_current_user)):
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: {permission.value}",
            )
        return user

    return _check


def require_role(*allowed_roles: Role):
    """FastAPI dependency factory that enforces one of the listed roles.

    Usage::

        @router.post("/approve")
        def approve(user: User = Depends(require_role("manager"))):
            ...
    """
    from fastapi import Depends, HTTPException

    from app.auth.dependencies import get_current_user

    def _check(user=Depends(get_current_user)):
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role not authorized: {user.role}",
            )
        return user

    return _check

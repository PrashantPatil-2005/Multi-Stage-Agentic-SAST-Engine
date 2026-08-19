"""DefectDojo data models.

Pydantic models for the data exchanged with the DefectDojo API.
These models represent what is actually sent to and received from
a real DefectDojo instance — no fabricated fields.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class DefectDojoFindingCreate(BaseModel):
    """Payload for POST /api/v2/findings/ in DefectDojo.

    Maps SAST engine findings to DefectDojo's finding schema.
    """

    title: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    numerical_severity: int  # SAST engine maps: Critical=1, High=2, Medium=3, Low=4, Info=5
    mitigation: str = ""
    impact: str = ""
    steps_to_reproduce: str = ""
    references: str = ""
    active: bool = True
    verified: bool = False
    false_p: bool = False
    out_of_scope: bool = False
    product_id: int | None = None
    engagement_id: int | None = None
    test_type_name: str = "SAST Engine"
    file_path: str = ""
    line: int | None = None
    component_name: str = ""


class DefectDojoFindingResponse(BaseModel):
    """Response from DefectDojo after creating a finding."""

    id: int
    url: str = ""
    title: str
    severity: str
    numerical_severity: int
    active: bool
    verified: bool
    created: str = ""
    updated: str = ""


class DefectDojoTicket(BaseModel):
    """Internal representation of a DefectDojo ticket/link."""

    finding_id: str  # our SAST finding ID
    defectdojo_finding_id: int | None = None
    defectdojo_url: str = ""
    status: Literal["pending", "created", "synced", "error"] = "pending"
    error_message: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class DefectDojoConnectionTest(BaseModel):
    """Result of testing the DefectDojo connection."""

    success: bool
    message: str
    url: str = ""
    version: str | None = None


class DefectDojoSyncResult(BaseModel):
    """Result of syncing findings to DefectDojo."""

    total: int
    created: int
    updated: int
    errors: int
    tickets: list[DefectDojoTicket] = Field(default_factory=list)
    error_messages: list[str] = Field(default_factory=list)

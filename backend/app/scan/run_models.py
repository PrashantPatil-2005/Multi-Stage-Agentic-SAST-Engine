"""Scan run lineage contracts (Phase 14D/14J).

A :class:`ScanRun` is a durable record of one execution of the scan route
against a project. A :class:`ScanStageRun` tracks the current status of one
pipeline stage within that run, and a :class:`ScanStageExecution` records one
explicit execution of a stage (append-only history). Stages that were never
executed stay ``pending`` forever - they are never reported completed unless
their service actually succeeded.

The scan route executes synchronously: SCAN runs, then the run finishes as
``completed`` or ``failed``. ``pending``/``running`` exist so the model can
represent queued/in-flight runs without inventing fake progress.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

ScanRunStatus = Literal["pending", "running", "completed", "failed"]
StageStatus = Literal["pending", "running", "completed", "failed"]

#: Pipeline stages in execution order. SCAN is executed by the scan route;
#: PREPARE is recorded as completed when a run is created (a scan run can
#: only exist for an already-prepared project); DEDUPLICATE/RISK/SLA/
#: VALIDATE/PROVE/APPROVAL are separate user-triggered endpoints, so their
#: stage records remain pending until an explicit execution is recorded
#: (never falsely marked completed).
STAGE_PREPARE = "PREPARE"
STAGE_SCAN = "SCAN"
STAGE_DEDUPLICATE = "DEDUPLICATE"
STAGE_RISK = "RISK"
STAGE_SLA = "SLA"
STAGE_VALIDATE = "VALIDATE"
STAGE_PROVE = "PROVE"
STAGE_APPROVAL = "APPROVAL"
STAGE_NAMES = [
    STAGE_PREPARE,
    STAGE_SCAN,
    STAGE_DEDUPLICATE,
    STAGE_RISK,
    STAGE_SLA,
    STAGE_VALIDATE,
    STAGE_PROVE,
    STAGE_APPROVAL,
]


class ScanRun(BaseModel):
    """One durable execution of the scan route for a project."""

    scan_run_id: str
    project_id: str
    status: ScanRunStatus
    started_at: datetime
    completed_at: datetime | None = None
    #: None until the run finishes; never fabricated (a failed run that never
    #: produced a report keeps these empty).
    scanned_file_count: int | None = None
    total_findings: int | None = None
    error: str | None = None
    created_at: datetime


class ScanStageRun(BaseModel):
    """Current status of one pipeline stage within a scan run.

    The record reflects the most recent explicit execution of the stage:
    ``started_at``/``completed_at``/``error`` belong to that execution, and
    ``execution_count`` counts every recorded execution of the stage within
    this run (SCAN records one per scan; DEDUPLICATE/RISK/SLA record one
    per explicit user-triggered execution that carried a ``scan_run_id``
    context). ``completed`` means the last recorded execution succeeded - it
    does not claim every finding of the run was processed.
    """

    scan_run_id: str
    stage_name: str
    status: StageStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    execution_count: int = 0
    last_execution_at: datetime | None = None


class ScanStageExecution(BaseModel):
    """One explicit execution of a stage within a scan run (append-only).

    History is preserved: retrying a failed stage appends a new execution
    record instead of overwriting the previous one. ``running`` is the
    in-flight state written before the stage body runs; it becomes
    ``completed`` or ``failed`` with a real ``completed_at`` afterwards.
    """

    execution_id: str
    scan_run_id: str
    stage_name: str
    status: StageStatus
    started_at: datetime
    completed_at: datetime | None = None
    error: str | None = None


class ScanRunDetail(BaseModel):
    """Scan run plus the status of every registered stage and the
    append-only execution history of each stage."""

    run: ScanRun
    stages: list[ScanStageRun]
    executions: list[ScanStageExecution] = []
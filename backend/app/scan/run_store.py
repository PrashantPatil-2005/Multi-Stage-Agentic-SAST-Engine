"""Scan run store: durable scan runs, stage records, execution history and
finding lineage.

Follows the same convention as the other pipeline stores (in-memory cache +
optional SQLite backing via ``app/db/persistence.py``). ``set_factory`` is
called from the FastAPI lifespan and rehydrates runs, stages, executions
and lineage from the database, so a backend restart keeps serving the same
scan history.

Stages, executions and lineage rows use composite/independent primary keys;
the store performs its own idempotent writes for them (the shared
``db_upsert`` is single-key). Execution history is append-only: retrying a
failed stage appends a new :class:`ScanStageExecution` instead of
overwriting the previous one.
"""

import json
import logging

from app.db.models import (
    ScanFindingRow,
    ScanRunRow,
    ScanStageExecutionRow,
    ScanStageRunRow,
)
from app.db.persistence import db_delete_all, db_load_all, db_upsert
from app.scan.run_models import (
    STAGE_NAMES,
    ScanRun,
    ScanStageExecution,
    ScanStageRun,
)

logger = logging.getLogger(__name__)


class ScanRunStore:
    def __init__(self) -> None:
        self._runs: dict[str, ScanRun] = {}
        self._stages: dict[str, dict[str, ScanStageRun]] = {}
        self._executions: dict[str, list[ScanStageExecution]] = {}
        self._lineage: dict[str, list[str]] = {}
        self._factory = None

    def set_factory(self, factory) -> None:
        self._factory = factory
        self._runs.clear()
        self._stages.clear()
        self._executions.clear()
        self._lineage.clear()
        if factory is None:
            return
        for key, run in db_load_all(factory, ScanRunRow, ScanRun, "scan_run_id"):
            self._runs[key] = run
        with factory() as session:
            stage_rows = session.query(ScanStageRunRow).all()
            execution_rows = session.query(ScanStageExecutionRow).all()
            lineage_rows = session.query(ScanFindingRow).all()
        for row in stage_rows:
            stage = ScanStageRun.model_validate_json(json.dumps(row.payload))
            self._stages.setdefault(stage.scan_run_id, {})[stage.stage_name] = stage
        for row in execution_rows:
            execution = ScanStageExecution.model_validate_json(
                json.dumps(row.payload)
            )
            self._executions.setdefault(execution.scan_run_id, []).append(execution)
        for run_id, executions in self._executions.items():
            executions.sort(key=lambda e: e.started_at)
        for row in lineage_rows:
            self._lineage.setdefault(row.scan_run_id, []).append(row.finding_id)

    # -- writes -------------------------------------------------------------

    def create_run(self, run: ScanRun) -> None:
        self._runs[run.scan_run_id] = run
        db_upsert(
            self._factory,
            ScanRunRow,
            "scan_run_id",
            run.scan_run_id,
            run,
            project_id=run.project_id,
        )

    def update_run(self, run: ScanRun) -> None:
        self.create_run(run)

    def upsert_stage(self, stage: ScanStageRun) -> None:
        self._stages.setdefault(stage.scan_run_id, {})[stage.stage_name] = stage
        if self._factory is None:
            return
        payload = stage.model_dump(mode="json")
        with self._factory() as session:
            row = session.get(
                ScanStageRunRow, (stage.scan_run_id, stage.stage_name)
            )
            if row is None:
                session.add(
                    ScanStageRunRow(
                        scan_run_id=stage.scan_run_id,
                        stage_name=stage.stage_name,
                        payload=payload,
                    )
                )
            else:
                row.payload = payload
            session.commit()

    def add_finding_lineage(self, scan_run_id: str, finding_id: str) -> None:
        ids = self._lineage.setdefault(scan_run_id, [])
        if finding_id not in ids:
            ids.append(finding_id)
        if self._factory is None:
            return
        with self._factory() as session:
            existing = session.get(ScanFindingRow, (scan_run_id, finding_id))
            if existing is None:
                session.add(
                    ScanFindingRow(scan_run_id=scan_run_id, finding_id=finding_id)
                )
                session.commit()

    # -- stage execution lifecycle ------------------------------------------

    def _stage(self, scan_run_id: str, stage_name: str) -> ScanStageRun | None:
        return self._stages.get(scan_run_id, {}).get(stage_name)

    def begin_stage_execution(
        self,
        scan_run_id: str,
        stage_name: str,
        execution_id: str,
        started_at,
    ) -> None:
        """Record that one execution of a stage has started.

        The stage record moves to ``running`` with real timestamps; the
        execution count increments and an append-only execution record is
        persisted. Existing ``started_at`` is replaced by this execution's
        start (the previous attempt's timestamps survive in the history).
        """
        execution = ScanStageExecution(
            execution_id=execution_id,
            scan_run_id=scan_run_id,
            stage_name=stage_name,
            status="running",
            started_at=started_at,
        )
        self._executions.setdefault(scan_run_id, []).append(execution)
        self._upsert_execution_row(execution)

        previous = self._stage(scan_run_id, stage_name)
        stage = ScanStageRun(
            scan_run_id=scan_run_id,
            stage_name=stage_name,
            status="running",
            started_at=started_at,
            completed_at=None,
            error=None,
            execution_count=(previous.execution_count if previous else 0) + 1,
            last_execution_at=started_at,
        )
        self.upsert_stage(stage)

    def complete_stage_execution(
        self, scan_run_id: str, stage_name: str, execution_id: str, completed_at
    ) -> None:
        """Mark an in-flight execution completed and the stage completed."""
        self._update_execution(
            execution_id, status="completed", completed_at=completed_at, error=None
        )
        previous = self._stage(scan_run_id, stage_name)
        self.upsert_stage(
            ScanStageRun(
                scan_run_id=scan_run_id,
                stage_name=stage_name,
                status="completed",
                started_at=(previous.started_at if previous else None),
                completed_at=completed_at,
                error=None,
                execution_count=(previous.execution_count if previous else 0),
                last_execution_at=(previous.last_execution_at if previous else None),
            )
        )

    def fail_stage_execution(
        self,
        scan_run_id: str,
        stage_name: str,
        execution_id: str,
        completed_at,
        error: str,
    ) -> None:
        """Mark an in-flight execution failed and the stage failed."""
        self._update_execution(
            execution_id, status="failed", completed_at=completed_at, error=error
        )
        previous = self._stage(scan_run_id, stage_name)
        self.upsert_stage(
            ScanStageRun(
                scan_run_id=scan_run_id,
                stage_name=stage_name,
                status="failed",
                started_at=(previous.started_at if previous else None),
                completed_at=completed_at,
                error=error,
                execution_count=(previous.execution_count if previous else 0),
                last_execution_at=(previous.last_execution_at if previous else None),
            )
        )

    def _update_execution(
        self, execution_id: str, *, status: str, completed_at, error: str | None
    ) -> None:
        for scan_run_id, executions in self._executions.items():
            for execution in executions:
                if execution.execution_id != execution_id:
                    continue
                updated = execution.model_copy(
                    update={
                        "status": status,
                        "completed_at": completed_at,
                        "error": error,
                    }
                )
                executions[executions.index(execution)] = updated
                self._upsert_execution_row(updated)
                return
        logger.warning("stage execution %s not found in memory", execution_id)

    def _upsert_execution_row(self, execution: ScanStageExecution) -> None:
        if self._factory is None:
            return
        payload = execution.model_dump(mode="json")
        with self._factory() as session:
            row = session.get(ScanStageExecutionRow, execution.execution_id)
            if row is None:
                session.add(
                    ScanStageExecutionRow(
                        execution_id=execution.execution_id,
                        scan_run_id=execution.scan_run_id,
                        stage_name=execution.stage_name,
                        payload=payload,
                    )
                )
            else:
                row.payload = payload
            session.commit()

    # -- reads --------------------------------------------------------------

    def get_run(self, scan_run_id: str) -> ScanRun | None:
        return self._runs.get(scan_run_id)

    def runs_for_project(self, project_id: str) -> list[ScanRun]:
        runs = [r for r in self._runs.values() if r.project_id == project_id]
        return sorted(runs, key=lambda r: r.started_at, reverse=True)

    def runs_for_finding(self, finding_id: str) -> list[ScanRun]:
        """Every scan run whose explicit lineage includes this finding.

        Finding ids are deterministic and project-scoped, so rescanning the
        same project re-observes the same finding id: this returns all of
        those runs (newest first). Callers show the full lineage instead of
        guessing a single "originating" run.
        """
        runs = [
            self._runs[scan_run_id]
            for scan_run_id, ids in self._lineage.items()
            if finding_id in ids
        ]
        return sorted(runs, key=lambda r: r.started_at, reverse=True)

    def stages_for_run(self, scan_run_id: str) -> list[ScanStageRun]:
        stages = self._stages.get(scan_run_id, {})
        return [stages[name] for name in STAGE_NAMES if name in stages]

    def executions_for_run(
        self, scan_run_id: str
    ) -> list[ScanStageExecution]:
        """Append-only execution history for a run, oldest first."""
        executions = list(self._executions.get(scan_run_id, []))
        executions.sort(key=lambda e: e.started_at)
        return executions

    def finding_ids_for_run(self, scan_run_id: str) -> list[str]:
        return list(self._lineage.get(scan_run_id, []))

    def all_runs(self) -> list[ScanRun]:
        """Read-only enumeration (used by read endpoints)."""
        return list(self._runs.values())

    def delete_project_runs(self, project_id: str) -> None:
        """Remove every scan run (with stages, executions and lineage) of a
        project. Used by repository deletion; idempotent for projects with
        no runs.
        """
        run_ids = [
            run.scan_run_id
            for run in self._runs.values()
            if run.project_id == project_id
        ]
        for run_id in run_ids:
            self._runs.pop(run_id, None)
            self._stages.pop(run_id, None)
            self._executions.pop(run_id, None)
            self._lineage.pop(run_id, None)
        if self._factory is None or not run_ids:
            return
        with self._factory() as session:
            session.query(ScanRunRow).filter(
                ScanRunRow.scan_run_id.in_(run_ids)
            ).delete(synchronize_session=False)
            session.query(ScanStageRunRow).filter(
                ScanStageRunRow.scan_run_id.in_(run_ids)
            ).delete(synchronize_session=False)
            session.query(ScanStageExecutionRow).filter(
                ScanStageExecutionRow.scan_run_id.in_(run_ids)
            ).delete(synchronize_session=False)
            session.query(ScanFindingRow).filter(
                ScanFindingRow.scan_run_id.in_(run_ids)
            ).delete(synchronize_session=False)
            session.commit()

    def clear(self) -> None:
        self._runs.clear()
        self._stages.clear()
        self._executions.clear()
        self._lineage.clear()
        db_delete_all(self._factory, ScanFindingRow)
        db_delete_all(self._factory, ScanStageExecutionRow)
        db_delete_all(self._factory, ScanStageRunRow)
        db_delete_all(self._factory, ScanRunRow)


_runs = ScanRunStore()


def get_scan_run_store() -> ScanRunStore:
    return _runs


def set_scan_run_store_factory(factory) -> None:
    _runs.set_factory(factory)
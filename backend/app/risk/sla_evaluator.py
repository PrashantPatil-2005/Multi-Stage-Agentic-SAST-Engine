"""Background SLA evaluator (automatic breach detection & escalation).

SLA records are normally only checked on demand (POST /api/findings/{id}/sla/check).
This module adds a small, reliable background cycle that periodically inspects
all records and applies the existing :class:`~app.risk.service.SLAService`
policy, so overdue SLAs breach and escalate without any user action.

Design notes
------------
* ``evaluate_once(now=...)`` is fully synchronous and directly testable with an
  injectable clock; the background loop merely calls it on a timer.
* The evaluator reuses ``SLAService.check_sla`` unchanged and persists through
  the existing store functions (``record_sla_record`` /
  ``record_escalation_event``), which write through to SQLite when stores are
  configured.
* Idempotency is guaranteed by ``SLAService.check_sla``: an active record
  breaches exactly once (one escalation event), and breached/resolved/P4
  records are never re-evaluated (``skipped``).
* A failing record is logged and skipped; it never aborts the cycle.
* Single-process assumption: one evaluator instance per application process;
  no distributed locking (documented for the current SQLite architecture).
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from app.risk.service import (
    SLAService,
    all_sla_records,
    check_and_persist_sla,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EvaluationStats:
    """Result of one evaluation cycle."""

    inspected: int  # total SLA records considered
    breached: int  # records that transitioned active -> breached (event created)
    skipped: int  # records not needing evaluation (non-active)
    errors: int  # records whose evaluation raised (logged, skipped)
    at: datetime  # clock used for this cycle


class SlaEvaluator:
    """Periodically applies the SLA policy to every recorded SLA.

    The object itself is inert until :meth:`start` is called from the FastAPI
    lifespan; :meth:`evaluate_once` can be used standalone (e.g. in tests).
    """

    def __init__(
        self,
        interval_seconds: int,
        *,
        service: SLAService | None = None,
    ) -> None:
        self._interval = interval_seconds
        self._service = service or SLAService()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started and self._task is not None and not self._task.done()

    def evaluate_once(self, now: datetime | None = None) -> EvaluationStats:
        """Run one evaluation cycle over all SLA records.

        ``now`` is injectable for deterministic tests; defaults to the current
        UTC time. Returns the cycle stats; never raises (per-record failures
        are logged and skipped).
        """
        now = now or datetime.now(timezone.utc)
        records = sorted(all_sla_records(), key=lambda r: r.finding_id)

        inspected = len(records)
        breached = 0
        skipped = 0
        errors = 0

        for record in records:
            if record.status != "active":
                skipped += 1
                continue
            try:
                updated, event = check_and_persist_sla(record.finding_id, now=now)
                if event is not None:
                    breached += 1
            except Exception as exc:  # failure isolation per record
                errors += 1
                logger.warning(
                    "SLA evaluation failed for finding %s: %s",
                    record.finding_id,
                    exc,
                )

        logger.info(
            "SLA evaluation cycle: inspected=%d breached=%d skipped=%d errors=%d",
            inspected,
            breached,
            skipped,
            errors,
        )
        return EvaluationStats(
            inspected=inspected,
            breached=breached,
            skipped=skipped,
            errors=errors,
            at=now,
        )

    # -- lifecycle (FastAPI lifespan) ---------------------------------------

    def start(self) -> asyncio.Task:
        """Start the background cycle on the running event loop (idempotent)."""
        if self._task is not None and not self._task.done():
            return self._task
        self._stop = asyncio.Event()
        self._task = asyncio.create_task(self._run())
        self._started = True
        logger.info("SLA evaluator started (interval=%ds)", self._interval)
        return self._task

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass
            if self._stop.is_set():
                break
            try:
                await asyncio.to_thread(self.evaluate_once)
            except Exception:
                logger.exception("SLA evaluation cycle failed")

    async def stop(self) -> None:
        """Stop the background cycle and wait for it to finish (idempotent)."""
        if self._task is None:
            return
        self._stop.set()
        await self._task
        logger.info("SLA evaluator stopped")
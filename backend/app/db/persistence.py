"""SQLite-backed persistence helpers shared by the pipeline stores.

Each store keeps its in-memory dict cache (public behavior unchanged) and
optionally mirrors every write into SQLite rows when a session factory is
configured. Without a factory the stores behave exactly as before: purely
in-memory (used by direct-service tests and library usage).

Factories are wired by :func:`configure_stores` from the FastAPI lifespan
(see app/main.py). Configuration resets every store cache to the rows
currently in the database (rehydration), so a backend restart immediately
serves the previously recorded pipeline state without re-running any stage.

Rows are JSON payloads of the Pydantic models (see app/db/models.py): the
Pydantic models stay the single source of truth and no field is dropped.
Datetimes are serialized as ISO-8601 with timezone, preserving UTC-aware
semantics through store and load.
"""

import json
import logging

logger = logging.getLogger(__name__)


def db_upsert(factory, row_cls, key_name: str, key: str, model, **extra) -> None:
    """Insert or update one row from a Pydantic model (idempotent by key).

    ``extra`` supplies additional non-payload columns (e.g. FK columns).
    """
    if factory is None:
        return
    payload = model.model_dump(mode="json")
    fields = {key_name: key, "payload": payload, **extra}
    with factory() as session:
        row = session.get(row_cls, key)
        if row is None:
            session.add(row_cls(**fields))
        else:
            row.payload = payload
        session.commit()


def db_insert(factory, row) -> None:
    """Append one already-constructed row (append-only event records)."""
    if factory is None:
        return
    with factory() as session:
        session.add(row)
        session.commit()


def db_delete_all(factory, row_cls) -> None:
    if factory is None:
        return
    with factory() as session:
        session.query(row_cls).delete()
        session.commit()


def db_delete(factory, row_cls, key_name: str, key) -> None:
    """Delete one row by its primary key (idempotent; missing key is fine)."""
    if factory is None:
        return
    with factory() as session:
        row = session.get(row_cls, key)
        if row is not None:
            session.delete(row)
            session.commit()


def db_load_all(factory, row_cls, model_cls, key_name: str) -> list[tuple[str, object]]:
    """Load every row and validate it back into the Pydantic model.

    Returns ``(key, model)`` pairs in database order. Never fabricates
    values: an unparseable payload raises, which surfaces as an explicit
    startup failure instead of silently dropping state.
    """
    if factory is None:
        return []
    with factory() as session:
        rows = session.query(row_cls).all()
    return [
        (
            str(getattr(row, key_name)),
            model_cls.model_validate_json(json.dumps(row.payload)),
        )
        for row in rows
    ]


def configure_stores(session_factory) -> None:
    """Point every pipeline store at the application database.

    Resets each store's cache to the persisted rows (rehydration), so a
    backend restart immediately serves the previously recorded state.
    """
    from app.approval.store import set_approval_store_factory
    from app.benchmark.service import set_benchmark_store_factory
    from app.dedup.service import set_dedup_store_factory
    from app.prove.store import set_proof_store_factory
    from app.remediation.store import set_remediation_store_factory
    from app.risk.service import set_risk_store_factory
    from app.scan.run_store import set_scan_run_store_factory
    from app.validate.store import set_validate_store_factory

    set_validate_store_factory(session_factory)
    set_proof_store_factory(session_factory)
    set_approval_store_factory(session_factory)
    set_risk_store_factory(session_factory)
    set_dedup_store_factory(session_factory)
    set_scan_run_store_factory(session_factory)
    set_benchmark_store_factory(session_factory)
    set_remediation_store_factory(session_factory)

    from app.defectdojo.service import set_defectdojo_store_factory
    set_defectdojo_store_factory(session_factory)

    logger.info("pipeline stores configured with database session factory")
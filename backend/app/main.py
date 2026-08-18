"""FastAPI application entrypoint (PREPARE + SCAN + DEDUP + RISK/SLA + VALIDATE + PROVE + APPROVAL)."""

import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    approval,
    benchmark,
    dashboard,
    dedup,
    findings,
    proofs,
    projects,
    proof_summary,
    remediation,
    repositories,
    risk,
    risk_summary,
    scans,
    validations,
    validation_summary,
)
from app.config import Settings, get_settings
from app.db.persistence import configure_stores
from app.db.session import init_db, make_engine, make_session_factory
from app.prepare.parser import PythonASTParser
from app.prepare.service import PrepareService
from app.risk.sla_evaluator import SlaEvaluator


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s - %(message)s",
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    # Load .env into the process environment so LLM_* provider settings in
    # backend/.env are visible to os.getenv (existing variables win).
    load_dotenv(".env")
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    engine = make_engine(settings.database_url)
    init_db(engine)
    session_factory = make_session_factory(engine)
    prepare_service = PrepareService(settings, fetcher=None, parser=PythonASTParser())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.session_factory = session_factory
        app.state.prepare_service = prepare_service
        configure_stores(session_factory)
        evaluator = SlaEvaluator(
            interval_seconds=settings.sla_check_interval_seconds
        )
        app.state.sla_evaluator = evaluator
        evaluator.start()
        try:
            yield
        finally:
            await evaluator.stop()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(projects.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(findings.router, prefix="/api")
    app.include_router(validations.router, prefix="/api")
    app.include_router(proofs.router, prefix="/api")
    app.include_router(dedup.router, prefix="/api")
    app.include_router(risk.router, prefix="/api")
    app.include_router(approval.router, prefix="/api")
    app.include_router(benchmark.router, prefix="/api")
    app.include_router(dashboard.router, prefix="/api")
    app.include_router(risk_summary.router, prefix="/api")
    app.include_router(validation_summary.router, prefix="/api")
    app.include_router(proof_summary.router, prefix="/api")
    app.include_router(remediation.router, prefix="/api")
    app.include_router(repositories.router, prefix="/api")

    @app.get("/api/health")
    def health() -> dict:
        from app.scan.run_models import STAGE_NAMES

        return {"status": "ok", "stage": STAGE_NAMES[0]}

    return app


app = create_app()

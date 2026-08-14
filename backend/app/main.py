"""FastAPI application entrypoint (PREPARE + SCAN + DEDUP + RISK/SLA + VALIDATE + PROVE + APPROVAL)."""

import logging
from contextlib import asynccontextmanager

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
    risk,
    validations,
)
from app.config import Settings, get_settings
from app.db.session import init_db, make_engine, make_session_factory
from app.prepare.parser import PythonASTParser
from app.prepare.service import PrepareService


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s - %(message)s",
    )


def create_app(settings: Settings | None = None) -> FastAPI:
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
        yield

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
    app.include_router(findings.router, prefix="/api")
    app.include_router(validations.router, prefix="/api")
    app.include_router(proofs.router, prefix="/api")
    app.include_router(dedup.router, prefix="/api")
    app.include_router(risk.router, prefix="/api")
    app.include_router(approval.router, prefix="/api")
    app.include_router(benchmark.router, prefix="/api")
    app.include_router(dashboard.router, prefix="/api")

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "stage": "prepare"}

    return app


app = create_app()

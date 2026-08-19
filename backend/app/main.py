"""FastAPI application entrypoint (PREPARE + SCAN + DEDUP + RISK/SLA + VALIDATE + PROVE + APPROVAL)."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import (
    approval,
    benchmark,
    dashboard,
    dedup,
    findings,
    notifications,
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
from app.auth import routes as auth_routes
from app.auth.seed import seed_demo_users
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
        # Seed demo users (idempotent)
        db = session_factory()
        try:
            seed_demo_users(db)
        finally:
            db.close()
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
    app.include_router(notifications.router, prefix="/api")
    app.include_router(auth_routes.router, prefix="/api")

    @app.get("/api/health")
    def health() -> dict:
        from app.scan.run_models import STAGE_NAMES

        return {"status": "ok", "stage": STAGE_NAMES[0]}

    # ── Serve frontend static files (production) ────────────────────────
    # In production the frontend is built into ../frontend/dist relative to
    # this file.  Mount the assets directory first so /api/* routes are not
    # shadowed, then add a catch-all that returns index.html for SPA routing.
    frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    if frontend_dist.is_dir():
        assets_dir = frontend_dist / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="static-assets")

        from fastapi.responses import FileResponse

        index_html = frontend_dist / "index.html"

        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str) -> FileResponse:
            # Serve the file if it exists under dist, otherwise fall back to index.html
            file_candidate = frontend_dist / full_path
            if full_path and file_candidate.is_file():
                return FileResponse(str(file_candidate))
            return FileResponse(str(index_html))

    return app


app = create_app()

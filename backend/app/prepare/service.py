"""PrepareService: orchestrates the PREPARE stage.

Flow: fetch (directory / zip / git) -> parse Python files -> ProjectSnapshot
-> CodeModel. The snapshot and code model are persisted as JSON in the
per-project workspace so later stages can consume them without re-parsing.

Nothing from the target repository is imported, executed or compiled here.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from app.config import Settings
from app.core.contracts import (
    CodeModel,
    ProjectSnapshot,
    RepoSpec,
    SnapshotSummary,
    SourceFile,
)
from app.prepare.base import get_builder
from app.prepare.fetcher import FetchResult, FetcherError, RepoFetcher, SecurityError
from app.prepare.parser import PythonASTParser
import app.prepare.python_builder  # noqa: F401  (registers the Python code model builder)

logger = logging.getLogger(__name__)

SNAPSHOT_FILE = "snapshot.json"
CODE_MODEL_FILE = "codemodel.json"


class PrepareError(Exception):
    """Raised when the PREPARE stage cannot complete."""


class PrepareService:
    def __init__(
        self,
        settings: Settings,
        fetcher: RepoFetcher | None = None,
        parser: PythonASTParser | None = None,
    ) -> None:
        self._settings = settings
        self._fetcher = fetcher or RepoFetcher(settings)
        self._parser = parser or PythonASTParser()

    # ------------------------------------------------------------------ API

    def prepare(self, spec: RepoSpec, project_id: str) -> tuple[ProjectSnapshot, CodeModel, Path]:
        """Run the full PREPARE stage; returns (snapshot, code_model, project_dir)."""
        project_dir = self._settings.workspace_dir / "projects" / project_id
        repo_dir = project_dir / "repo"
        try:
            result = self._fetcher.fetch(spec, repo_dir)
        except SecurityError as exc:
            raise SecurityError(str(exc)) from exc
        except FetcherError as exc:
            raise PrepareError(str(exc)) from exc

        parsed_files = []
        for rel_path in sorted(result.copied_files):
            if not rel_path.endswith(".py"):
                continue
            file_path = repo_dir / rel_path
            try:
                raw = file_path.read_bytes()
            except OSError as exc:
                logger.warning("cannot read %s: %s", rel_path, exc)
                continue
            if b"\x00" in raw[:8192]:
                logger.debug("skipping binary-looking file %s", rel_path)
                parsed_files.append(self._parser.parse(rel_path, "<binary content>\n"))
                continue
            source = raw.decode("utf-8", errors="replace")
            parsed_files.append(self._parser.parse(rel_path, source))

        snapshot = self._build_snapshot(spec, project_id, result, parsed_files)
        project_dir.mkdir(parents=True, exist_ok=True)
        (project_dir / SNAPSHOT_FILE).write_text(
            snapshot.model_dump_json(indent=2), encoding="utf-8"
        )
        code_model = get_builder(spec.language).build(snapshot)
        (project_dir / CODE_MODEL_FILE).write_text(
            code_model.model_dump_json(indent=2), encoding="utf-8"
        )
        logger.info(
            "PREPARE complete: project=%s files=%d python=%d failures=%d",
            project_id,
            snapshot.summary.fetched_files,
            snapshot.summary.python_files,
            snapshot.summary.parse_failures,
        )
        return snapshot, code_model, project_dir

    @staticmethod
    def load_snapshot(project_dir: Path) -> ProjectSnapshot:
        return ProjectSnapshot.model_validate_json(
            (project_dir / SNAPSHOT_FILE).read_text(encoding="utf-8")
        )

    @staticmethod
    def load_code_model(project_dir: Path) -> CodeModel:
        return CodeModel.model_validate_json(
            (project_dir / CODE_MODEL_FILE).read_text(encoding="utf-8")
        )

    # ------------------------------------------------------------- internal

    def _build_snapshot(
        self,
        spec: RepoSpec,
        project_id: str,
        result: FetchResult,
        parsed_files: list[SourceFile],
    ) -> ProjectSnapshot:
        summary = self._summarize(result, parsed_files)
        return ProjectSnapshot(
            project_id=project_id,
            repo_name=spec.name,
            language=spec.language,
            created_at=datetime.now(timezone.utc),
            files=parsed_files,
            ignored_paths=result.ignored_paths,
            skipped_files=result.skipped,
            summary=summary,
        )

    @staticmethod
    def _summarize(result: FetchResult, parsed_files: list[SourceFile]) -> SnapshotSummary:
        return SnapshotSummary(
            fetched_files=len(result.copied_files),
            fetched_bytes=result.total_bytes,
            python_files=len(parsed_files),
            parse_failures=sum(1 for f in parsed_files if f.error is not None),
            total_lines=sum(f.line_count for f in parsed_files),
            function_count=sum(len(f.functions) for f in parsed_files),
            class_count=sum(len(f.classes) for f in parsed_files),
            call_count=sum(len(f.calls) for f in parsed_files),
            import_count=sum(len(f.imports) for f in parsed_files),
            assignment_count=sum(len(f.assignments) for f in parsed_files),
        )

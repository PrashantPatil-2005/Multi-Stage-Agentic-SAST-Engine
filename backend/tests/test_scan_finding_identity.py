"""Finding identity regression tests (project-scoped deterministic ids).

GAP-02 regression: finding ids are scoped to the project, so scanning two
repositories with identical vulnerable file/line structures no longer
collides in the shared finding store, while rescans of the same project
remain deterministic and the cross-repository dedup fingerprint is
unchanged.
"""

from datetime import datetime, timezone

from app.core.contracts import CodeModel
from app.dedup.service import DeduplicationService
from app.prepare.parser import PythonASTParser
from app.scan.service import ScanService

SOURCES = {
    "views.py": (
        "from flask import request\n"
        "import sqlite3\n"
        "def show_user():\n"
        "    user_id = request.args.get(\"id\")\n"
        "    conn = sqlite3.connect(\"app.db\")\n"
        "    cursor = conn.cursor()\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
}


def _model() -> CodeModel:
    parser = PythonASTParser()
    return CodeModel(
        language="python",
        files=[parser.parse(path, src) for path, src in SOURCES.items()],
        module_map={},
        function_index=[],
        built_at=datetime.now(timezone.utc),
    )


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


def test_same_code_in_different_projects_gets_distinct_ids() -> None:
    first = ScanService().scan(_model(), project_id="proj-a")
    second = ScanService().scan(_model(), project_id="proj-b")
    assert _ids(first)
    assert _ids(first).isdisjoint(_ids(second))


def test_rescan_same_project_is_idempotent() -> None:
    first = ScanService().scan(_model(), project_id="proj-a")
    second = ScanService().scan(_model(), project_id="proj-a")
    assert _ids(first) == _ids(second)


def test_ids_deterministic_without_project_id() -> None:
    first = ScanService().scan(_model())
    second = ScanService().scan(_model())
    assert _ids(first) == _ids(second)


def test_cross_project_dedup_fingerprint_unchanged() -> None:
    a = ScanService().scan(_model(), project_id="proj-a")
    b = ScanService().scan(_model(), project_id="proj-b")
    result = DeduplicationService().deduplicate(a.findings + b.findings)
    assert len(result.groups) == 1
    group = result.groups[0]
    assert group.occurrence_count == 2
    assert sorted(group.member_finding_ids) == sorted(_ids(a) | _ids(b))
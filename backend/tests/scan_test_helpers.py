"""Shared helpers for SCAN stage tests."""

from datetime import datetime, timezone
from pathlib import Path

from app.core.contracts import CodeModel
from app.prepare.parser import PythonASTParser
from app.scan.models import ScanReport
from app.scan.service import ScanService

FIXTURES = Path(__file__).parent / "fixtures"
VULN_APP = FIXTURES / "vulnerable_python_app"

parser = PythonASTParser()


def scan_sources(sources: dict[str, str]) -> ScanReport:
    files = [parser.parse(path, src) for path, src in sources.items()]
    model = CodeModel(
        language="python",
        files=files,
        module_map={},
        function_index=[],
        built_at=datetime.now(timezone.utc),
    )
    return ScanService().scan(model)


def scan_fixture_files(*names: str) -> ScanReport:
    return scan_sources(
        {name: (VULN_APP / name).read_text(encoding="utf-8") for name in names}
    )

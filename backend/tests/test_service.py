"""PrepareService tests: end-to-end PREPARE for dir and zip sources."""

import zipfile
from pathlib import Path

import pytest

from app.core.contracts import RepoSpec
from app.prepare.service import PrepareError


def _spec(source_type: str, location) -> RepoSpec:
    return RepoSpec(name="vuln-app", source_type=source_type, location=str(location))


def _zip_of(fixture_repo, target):
    with zipfile.ZipFile(target, "w") as zf:
        for py in fixture_repo.rglob("*.py"):
            if "__pycache__" in py.parts or ".venv" in py.parts:
                continue
            zf.write(py, py.relative_to(fixture_repo).as_posix())


def test_prepare_directory_source(service, fixture_repo):
    snapshot, code_model, project_dir = service.prepare(_spec("directory", fixture_repo), "p1")
    assert snapshot.project_id == "p1"
    assert snapshot.repo_name == "vuln-app"
    paths = {f.path for f in snapshot.files}
    assert {"app.py", "db.py", "utils.py", "config.py", "models.py", "poison.py", "bad_syntax.py"} <= paths
    assert snapshot.summary.python_files == 7
    assert snapshot.summary.parse_failures == 1
    assert snapshot.summary.function_count >= 10
    assert snapshot.summary.class_count >= 2
    assert (project_dir / "snapshot.json").exists()
    assert (project_dir / "codemodel.json").exists()
    assert code_model.language == "python"
    assert "app" in code_model.module_map
    assert any(f.qualified_name == "Database.query_users" for f in code_model.function_index)


def test_prepare_zip_source(service, fixture_repo, tmp_path):
    zip_path = tmp_path / "app.zip"
    _zip_of(fixture_repo, zip_path)
    snapshot, _, _ = service.prepare(_spec("zip", zip_path), "p2")
    assert snapshot.summary.python_files == 7
    paths = {f.path for f in snapshot.files}
    assert "app.py" in paths


def test_prepare_missing_directory_fails(service, tmp_path):
    with pytest.raises(PrepareError):
        service.prepare(_spec("directory", tmp_path / "nope"), "p3")


def test_prepare_load_snapshot_roundtrip(service, fixture_repo, tmp_path):
    _, _, project_dir = service.prepare(_spec("directory", fixture_repo), "p4")
    loaded = service.load_snapshot(project_dir)
    assert loaded.summary == service.load_snapshot(project_dir).summary
    assert loaded.files[0].path.endswith(".py")


def test_no_target_code_execution(service, fixture_repo):
    marker = Path.cwd() / "sast_should_never_run.txt"
    if marker.exists():
        marker.unlink()
    snapshot, _, _ = service.prepare(_spec("directory", fixture_repo), "p5")
    poison = next(f for f in snapshot.files if f.path == "poison.py")
    assert "sys.exit" in poison.source
    assert marker.exists() is False


def test_import_builder_registry():
    from app.prepare.base import get_builder
    from app.prepare.python_builder import PythonASTCodeModelBuilder

    assert get_builder("python").__class__ is PythonASTCodeModelBuilder


def test_code_model_indexes(service, fixture_repo):
    _, code_model, _ = service.prepare(_spec("directory", fixture_repo), "p6")
    assert "app" in code_model.module_map
    assert code_model.module_map["app"] == "app.py"
    assert len(code_model.function_index) > 0
    assert all(f.file.endswith(".py") for f in code_model.function_index)

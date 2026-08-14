"""Fetcher tests: ingestion sources, ignore rules, security guards."""

import stat
import zipfile

import pytest

from app.core.contracts import RepoSpec
from app.prepare.fetcher import FetcherError, SecurityError


def _spec(source_type: str, location: str) -> RepoSpec:
    return RepoSpec(name="test", source_type=source_type, location=str(location))


def _make_zip(path, entries):
    """entries: list of (name, data) or (name, data, is_symlink)."""
    with zipfile.ZipFile(path, "w") as zf:
        for entry in entries:
            name, data = entry[0], entry[1]
            is_symlink = entry[2] if len(entry) > 2 else False
            info = zipfile.ZipInfo(name)
            if is_symlink:
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, data)


def test_directory_source_ingested(fetcher, fixture_repo, tmp_path):
    spec = _spec("directory", fixture_repo)
    result = fetcher.fetch(spec, tmp_path / "out")
    paths = set(result.copied_files)
    assert "app.py" in paths
    assert "db.py" in paths
    assert "bad_syntax.py" in paths
    assert (tmp_path / "out" / "app.py").exists()


def test_ignored_directories_pruned(fetcher, fixture_repo, tmp_path):
    spec = _spec("directory", fixture_repo)
    result = fetcher.fetch(spec, tmp_path / "out")
    paths = set(result.copied_files)
    assert not any("__pycache__" in p for p in paths)
    assert not any(".venv" in p for p in paths)
    assert not any("node_modules" in p for p in paths)
    assert "__pycache__" in result.ignored_paths
    assert (tmp_path / "out" / "__pycache__").exists() is False


def test_directory_source_missing_raises(fetcher, tmp_path):
    spec = _spec("directory", tmp_path / "does_not_exist")
    with pytest.raises(FetcherError):
        fetcher.fetch(spec, tmp_path / "out")


def test_zip_source_extracted(fetcher, fixture_repo, tmp_path):
    zip_path = tmp_path / "repo.zip"
    _make_zip(
        zip_path,
        [("pkg/__init__.py", "VALUE = 1\n"), ("pkg/main.py", "def run():\n    pass\n")],
    )
    result = fetcher.fetch(_spec("zip", zip_path), tmp_path / "out")
    assert set(result.copied_files) == {"pkg/__init__.py", "pkg/main.py"}
    assert (tmp_path / "out" / "pkg" / "main.py").exists()


def test_zip_path_traversal_relative_rejected(fetcher, tmp_path):
    zip_path = tmp_path / "evil.zip"
    _make_zip(zip_path, [("../escape.py", "print('pwn')\n")])
    with pytest.raises(SecurityError):
        fetcher.fetch(_spec("zip", zip_path), tmp_path / "out")
    assert not (tmp_path / "escape.py").exists()


def test_zip_path_traversal_absolute_rejected(fetcher, tmp_path):
    zip_path = tmp_path / "evil2.zip"
    _make_zip(zip_path, [("/etc/pwned.py", "print('pwn')\n")])
    with pytest.raises(SecurityError):
        fetcher.fetch(_spec("zip", zip_path), tmp_path / "out")


def test_zip_symlink_entry_rejected(fetcher, tmp_path):
    zip_path = tmp_path / "evil3.zip"
    _make_zip(zip_path, [("link.py", "", True)])
    with pytest.raises(SecurityError):
        fetcher.fetch(_spec("zip", zip_path), tmp_path / "out")


def test_zip_missing_file_raises(fetcher, tmp_path):
    spec = _spec("zip", tmp_path / "missing.zip")
    with pytest.raises(FetcherError):
        fetcher.fetch(spec, tmp_path / "out")


def test_oversized_file_skipped(fetcher, tmp_path):
    settings = fetcher._settings
    big = tmp_path / "big" / "huge.py"
    big.parent.mkdir()
    big.write_bytes(b"x = 1\n" * 200_000)
    assert big.stat().st_size > settings.max_file_size_bytes
    result = fetcher.fetch(_spec("directory", big.parent), tmp_path / "out")
    assert result.copied_files == []
    assert any(s.reason == "too_large" for s in result.skipped)

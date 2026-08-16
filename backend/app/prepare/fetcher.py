"""Repository ingestion (PREPARE stage input handling).

Supported sources:
  * local directory
  * ZIP archive
  * git repository URL (requires ``git`` on PATH)

Security guarantees:
  * nothing from the repository is ever imported, executed or compiled
  * ZIP extraction is hardened against path traversal and symlink entries
  * extraction is restricted to a per-project workspace directory
  * files larger than a configured limit are skipped; aggregate limits abort
  * irrelevant directories (.git, node_modules, __pycache__, venvs, ...) are ignored
"""

import fnmatch
import logging
import os
import re
import shutil
import stat
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.config import Settings
from app.core.contracts import RepoSpec, SkipInfo

logger = logging.getLogger(__name__)

# Redacts embedded credentials (https://user:token@host/...) so git stderr
# echoed to clients or logs never leaks a token.
_URL_CREDENTIALS = re.compile(r"://([^/@:\s]+):([^/@\s]+)@")


def _redact_credentials(text: str) -> str:
    return _URL_CREDENTIALS.sub(r"://<redacted>:<redacted>@", text)

# Directories that are never ingested, matched by name at any depth.
IGNORED_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".env",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".eggs",
        "dist",
        "build",
        "target",
        ".idea",
        ".vscode",
        ".coverage",
        "htmlcov",
    }
)

# File patterns that are never ingested.
IGNORED_FILE_PATTERNS = ("*.pyc", "*.pyo")

MAX_SNIPPET_CHARS = 200


class FetcherError(Exception):
    """Raised when repository ingestion fails."""


class SecurityError(FetcherError):
    """Raised when repository input violates security constraints."""


@dataclass
class FetchResult:
    repo_root: Path
    copied_files: list[str] = field(default_factory=list)  # repo-relative posix paths
    ignored_paths: list[str] = field(default_factory=list)
    skipped: list[SkipInfo] = field(default_factory=list)
    total_bytes: int = 0


def _is_ignored_dir(name: str) -> bool:
    return name in IGNORED_DIR_NAMES


def _is_ignored_file(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in IGNORED_FILE_PATTERNS)


class RepoFetcher:
    """Fetches a repository into an isolated workspace directory."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch(self, spec: RepoSpec, dest_dir: Path) -> FetchResult:
        """Bring the repository described by ``spec`` into ``dest_dir``."""
        if spec.source_type == "directory":
            return self._fetch_directory(spec, dest_dir)
        if spec.source_type == "zip":
            return self._fetch_zip(spec, dest_dir)
        if spec.source_type == "git":
            return self._fetch_git(spec, dest_dir)
        raise FetcherError(f"unsupported source_type: {spec.source_type}")

    # ------------------------------------------------------------------ dir

    def _fetch_directory(self, spec: RepoSpec, dest_dir: Path) -> FetchResult:
        src = Path(spec.location).expanduser().resolve()
        if not src.is_dir():
            raise FetcherError(f"directory not found: {spec.location}")
        dest_dir.mkdir(parents=True, exist_ok=True)
        result = FetchResult(repo_root=dest_dir)
        file_count = 0
        for dirpath, dirnames, filenames in os.walk(src):
            pruned = [d for d in dirnames if _is_ignored_dir(d)]
            dirnames[:] = [d for d in dirnames if not _is_ignored_dir(d)]
            rel_dir = Path(dirpath).relative_to(src)
            for d in pruned:
                result.ignored_paths.append((rel_dir / d).as_posix())
            for name in sorted(filenames):
                if _is_ignored_file(name):
                    rel = Path(dirpath).relative_to(src).as_posix()
                    result.ignored_paths.append(f"{rel}/{name}" if rel != "." else name)
                    continue
                abs_src = Path(dirpath) / name
                rel = abs_src.relative_to(src)
                if abs_src.is_symlink():
                    result.skipped.append(SkipInfo(path=rel.as_posix(), reason="symlink"))
                    continue
                try:
                    size = abs_src.stat().st_size
                except OSError as exc:
                    logger.warning("cannot stat %s: %s", abs_src, exc)
                    result.skipped.append(SkipInfo(path=rel.as_posix(), reason=f"stat_error: {exc}"))
                    continue
                if size > self._settings.max_file_size_bytes:
                    result.skipped.append(SkipInfo(path=rel.as_posix(), reason="too_large"))
                    continue
                file_count += 1
                if file_count > self._settings.max_files:
                    raise FetcherError(
                        f"repository exceeds max_files limit ({self._settings.max_files})"
                    )
                result.total_bytes += size
                if result.total_bytes > self._settings.max_total_size_bytes:
                    raise FetcherError(
                        f"repository exceeds max_total_size limit "
                        f"({self._settings.max_total_size_bytes} bytes)"
                    )
                dest_file = dest_dir / rel
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(abs_src, dest_file, follow_symlinks=False)
                result.copied_files.append(rel.as_posix())
        logger.info(
            "ingested directory %s -> %s (%d files, %d bytes)",
            src,
            dest_dir,
            len(result.copied_files),
            result.total_bytes,
        )
        return result

    # ------------------------------------------------------------------ zip

    def _fetch_zip(self, spec: RepoSpec, dest_dir: Path) -> FetchResult:
        zip_path = Path(spec.location).expanduser().resolve()
        if not zip_path.is_file():
            raise FetcherError(f"zip file not found: {spec.location}")
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_resolved = dest_dir.resolve()
        result = FetchResult(repo_root=dest_dir)
        file_count = 0
        with zipfile.ZipFile(zip_path) as archive:
            for info in archive.infolist():
                name = info.filename.replace("\\", "/")
                if not name or name.endswith("/"):
                    continue
                parts = [p for p in name.split("/") if p not in ("", ".")]
                if not parts or ".." in parts:
                    raise SecurityError(f"zip entry escapes destination: {info.filename!r}")
                if name.startswith("/") or len(parts[0]) == 2 and parts[0][1] == ":":
                    raise SecurityError(f"zip entry is an absolute path: {info.filename!r}")
                ignored_idx = next(
                    (i for i, p in enumerate(parts[:-1]) if _is_ignored_dir(p)), None
                )
                if ignored_idx is not None or _is_ignored_dir(parts[0]):
                    stop = ignored_idx + 1 if ignored_idx is not None else 1
                    result.ignored_paths.append("/".join(parts[:stop]))
                    continue
                if _is_ignored_file(parts[-1]):
                    result.ignored_paths.append("/".join(parts))
                    continue
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise SecurityError(f"zip entry is a symlink: {info.filename!r}")
                if info.flag_bits & 0x1:
                    raise SecurityError(f"zip entry is encrypted: {info.filename!r}")
                if info.file_size > self._settings.max_file_size_bytes:
                    result.skipped.append(
                        SkipInfo(path="/".join(parts), reason="too_large")
                    )
                    continue
                file_count += 1
                if file_count > self._settings.max_files:
                    raise FetcherError(
                        f"zip exceeds max_files limit ({self._settings.max_files})"
                    )
                result.total_bytes += info.file_size
                if result.total_bytes > self._settings.max_total_size_bytes:
                    raise FetcherError(
                        f"zip exceeds max_total_size limit "
                        f"({self._settings.max_total_size_bytes} bytes)"
                    )
                target = (dest_dir / Path(*parts)).resolve()
                if not target.is_relative_to(dest_resolved):
                    raise SecurityError(f"zip entry escapes destination: {info.filename!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                result.copied_files.append("/".join(parts))
        logger.info(
            "extracted zip %s -> %s (%d files, %d bytes)",
            zip_path,
            dest_dir,
            len(result.copied_files),
            result.total_bytes,
        )
        return result

    # ------------------------------------------------------------------ git

    def _fetch_git(self, spec: RepoSpec, dest_dir: Path) -> FetchResult:
        if dest_dir.exists() and any(dest_dir.iterdir()):
            raise FetcherError(f"destination already exists: {dest_dir}")
        dest_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", spec.location, str(dest_dir)],
                capture_output=True,
                text=True,
                timeout=self._settings.git_clone_timeout_seconds,
            )
        except FileNotFoundError:
            raise FetcherError("git executable not found on PATH")
        except subprocess.TimeoutExpired:
            raise FetcherError(f"git clone timed out after "
                               f"{self._settings.git_clone_timeout_seconds}s")
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[-500:]
            raise FetcherError(f"git clone failed: {_redact_credentials(detail)}")
        return self._walk(dest_dir)

    # ----------------------------------------------------------------- walk

    def _walk(self, root: Path) -> FetchResult:
        """Re-derive a FetchResult for a directory that is already in place."""
        root = root.resolve()
        result = FetchResult(repo_root=root)
        file_count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            pruned = [d for d in dirnames if _is_ignored_dir(d)]
            dirnames[:] = [d for d in dirnames if not _is_ignored_dir(d)]
            rel_dir = Path(dirpath).relative_to(root)
            for d in pruned:
                result.ignored_paths.append((rel_dir / d).as_posix())
            for name in sorted(filenames):
                if _is_ignored_file(name):
                    rel = Path(dirpath).relative_to(root).as_posix()
                    result.ignored_paths.append(f"{rel}/{name}" if rel != "." else name)
                    continue
                abs_path = Path(dirpath) / name
                rel = abs_path.relative_to(root)
                if abs_path.is_symlink():
                    result.skipped.append(SkipInfo(path=rel.as_posix(), reason="symlink"))
                    continue
                try:
                    size = abs_path.stat().st_size
                except OSError as exc:
                    result.skipped.append(
                        SkipInfo(path=rel.as_posix(), reason=f"stat_error: {exc}")
                    )
                    continue
                if size > self._settings.max_file_size_bytes:
                    result.skipped.append(SkipInfo(path=rel.as_posix(), reason="too_large"))
                    continue
                file_count += 1
                if file_count > self._settings.max_files:
                    raise FetcherError(
                        f"repository exceeds max_files limit ({self._settings.max_files})"
                    )
                result.total_bytes += size
                if result.total_bytes > self._settings.max_total_size_bytes:
                    raise FetcherError(
                        f"repository exceeds max_total_size limit "
                        f"({self._settings.max_total_size_bytes} bytes)"
                    )
                result.copied_files.append(rel.as_posix())
        logger.info("walked %s (%d files, %d bytes)", root, len(result.copied_files), result.total_bytes)
        return result

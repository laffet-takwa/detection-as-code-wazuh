"""Filesystem helpers with deterministic ordering and safe write semantics."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path

__all__ = [
    "SIGMA_SUFFIXES",
    "iter_files",
    "iter_sigma_files",
    "read_text",
    "write_text",
    "ensure_directory",
    "relative_posix",
    "file_sha256",
]

#: File suffixes that are treated as Sigma rule files.
SIGMA_SUFFIXES: frozenset[str] = frozenset({".yml", ".yaml"})


def iter_files(root: Path, suffixes: Iterable[str] | None = None) -> list[Path]:
    """Return every matching file below *root* in a stable, sorted order.

    Sorting is performed on the POSIX representation of the relative path so the
    result does not depend on the host operating system.
    """

    if not root.exists():
        return []
    allowed = {suffix.lower() for suffix in suffixes} if suffixes else None
    collected: list[tuple[str, Path]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if allowed is not None and path.suffix.lower() not in allowed:
            continue
        collected.append((path.relative_to(root).as_posix(), path))
    return [path for _, path in sorted(collected, key=lambda item: item[0])]


def iter_sigma_files(root: Path) -> list[Path]:
    """Return every Sigma rule file below *root* in deterministic order."""

    return iter_files(root, SIGMA_SUFFIXES)


def read_text(path: Path) -> str:
    """Read *path* as UTF-8 text, replacing undecodable bytes."""

    return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, content: str) -> None:
    """Write *content* to *path* atomically.

    The content is written to a temporary file in the destination directory and
    then moved into place, so a failure never leaves a partially written rule
    catalogue behind.
    """

    ensure_directory(path.parent)
    handle, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    temp_path = Path(temp_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        temp_path.replace(path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def ensure_directory(path: Path) -> Path:
    """Create *path* (and parents) when missing and return it."""

    path.mkdir(parents=True, exist_ok=True)
    return path


def relative_posix(path: Path, root: Path) -> str:
    """Return *path* relative to *root* using POSIX separators."""

    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def file_sha256(path: Path) -> str:
    """Return the SHA-256 digest of the file at *path*."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_lines(path: Path) -> Iterator[str]:
    """Yield the stripped, non-empty lines of *path*."""

    for line in read_text(path).splitlines():
        stripped = line.strip()
        if stripped:
            yield stripped

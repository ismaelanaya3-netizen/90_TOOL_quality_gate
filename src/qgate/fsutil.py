"""File-system helpers with POSIX-style glob exclusions (portable to Windows)."""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath


def rel_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def matches_any(rel: str, patterns: Sequence[str]) -> bool:
    """Glob match on a POSIX relative path. ``dir/**`` also matches ``dir`` itself."""
    pure = PurePosixPath(rel)
    for pattern in patterns:
        if fnmatchcase(rel, pattern) or fnmatchcase(pure.name, pattern):
            return True
        if pattern.endswith("/**"):
            base = pattern[:-3]
            if rel == base or fnmatchcase(rel, base) or rel.startswith(base + "/"):
                return True
            if base.startswith("**/") and base[3:] in pure.parts:
                return True
    return False


def iter_files(root: Path, bases: Sequence[str], suffixes: Sequence[str], excludes: Sequence[str]) -> Iterator[Path]:
    """Yield files under ``bases`` (relative to ``root``) with one of ``suffixes``."""
    seen: set[Path] = set()
    for base in bases:
        start = (root / base).resolve()
        if start.is_file():
            if start.suffix in suffixes and start not in seen:
                seen.add(start)
                yield start
            continue
        for dirpath, dirnames, filenames in os.walk(start):
            current = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames if not matches_any(rel_posix(current / d, root), excludes))
            for filename in sorted(filenames):
                path = current / filename
                if path.suffix not in suffixes or path in seen:
                    continue
                if matches_any(rel_posix(path, root), excludes):
                    continue
                seen.add(path)
                yield path


def count_lines(path: Path) -> int:
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def glob_to_regex(pattern: str) -> str:
    """Translate a POSIX glob into a regex usable by gitleaks/detect-secrets."""
    out = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            if i < len(pattern) and pattern[i] == "/":
                i += 1
            continue
        if char == "*":
            out.append("[^/\\\\]*")
        elif char == "?":
            out.append(".")
        elif char == "/":
            out.append("[/\\\\]")
        else:
            out.append("\\" + char if char in ".^$+{}[]()|\\" else char)
        i += 1
    return "".join(out)

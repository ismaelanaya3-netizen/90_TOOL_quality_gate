"""Locate or download a pinned gitleaks binary (SHA-256 verified)."""

from __future__ import annotations

import io
import os
import platform
import stat
import tarfile
import zipfile
from pathlib import Path

from qgate import net, tools

GITLEAKS_VERSION = "8.21.2"
_BASE = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"
# Checksums pinned from the official release (gitleaks_8.21.2_checksums.txt).
CHECKSUMS = {
    "linux_x64.tar.gz": "5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba",
    "linux_arm64.tar.gz": "654c935542c89f565aabe7bf7c6c500830f116c114f0aeb509d2460c1ac2e6da",
    "darwin_x64.tar.gz": "5b42c6e4b1fd693eaeb2b5b7faa5f17a1434299d4deb2de63d4b2efd7c753128",
    "darwin_arm64.tar.gz": "cad3de5dc9a4d5447d967a70a4d49499c557f04db028274cc324f9ff983f6502",
    "windows_x64.zip": "f238c85e5f47e18fac779ce71ee11091cf70a0a8fb4415f165efba2800eef133",
}


def asset_name(system: str | None = None, machine: str | None = None) -> str:
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "x64"
    if system.startswith("win"):
        return "windows_x64.zip"
    if system == "darwin":
        return f"darwin_{arch}.tar.gz"
    return f"linux_{arch}.tar.gz"


def binary_name() -> str:
    return "gitleaks.exe" if os.name == "nt" else "gitleaks"


def search_dirs(root: Path) -> list[Path]:
    return [root / ".qgate" / "bin", Path.home() / ".qgate" / "bin"]


def find(root: Path) -> str | None:
    configured = os.environ.get("QGATE_GITLEAKS", "")
    if configured and Path(configured).is_file():
        return configured
    return tools.find_executable("gitleaks", search_dirs(root))


def _extract(archive: Path, dest_dir: Path) -> Path:
    target = dest_dir / binary_name()
    data = archive.read_bytes()
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zipped:
            target.write_bytes(zipped.read(binary_name()))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            member = tar.getmember(binary_name())
            handle = tar.extractfile(member)
            if handle is None:
                msg = "El archivo descargado no contiene el binario de gitleaks."
                raise ValueError(msg)
            target.write_bytes(handle.read())
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return target


def download(dest_dir: Path) -> Path:
    """Download the pinned release for this OS, verify checksum and extract it."""
    asset = asset_name()
    filename = f"gitleaks_{GITLEAKS_VERSION}_{asset}"
    archive = dest_dir / filename
    net.download(f"{_BASE}/{filename}", archive, CHECKSUMS[asset])
    try:
        return _extract(archive, dest_dir)
    finally:
        archive.unlink(missing_ok=True)


def ensure(root: Path) -> tuple[str | None, str]:
    """Return ``(path, note)``; tries a verified download when not installed."""
    found = find(root)
    if found:
        return found, ""
    if os.environ.get("QGATE_NO_DOWNLOAD"):
        return None, "gitleaks no instalado y QGATE_NO_DOWNLOAD activo."
    if not net.reachable("https://github.com/"):
        return None, "gitleaks no instalado y sin acceso a GitHub para descargarlo."
    try:
        path = download(root / ".qgate" / "bin")
    except (OSError, ValueError, KeyError) as exc:
        return None, f"No se pudo descargar gitleaks: {exc}"
    return str(path), f"gitleaks {GITLEAKS_VERSION} descargado y verificado (SHA-256)."

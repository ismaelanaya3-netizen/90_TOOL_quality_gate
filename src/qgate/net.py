"""Network helpers. ``urllib`` honours HTTP_PROXY / HTTPS_PROXY automatically."""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from pathlib import Path

ENDPOINTS = {
    "PyPI": "https://pypi.org/simple/pip/",
    "OSV": "https://api.osv.dev/v1/vulns/PYSEC-2021-1",
    "GitHub": "https://github.com/",
    "Semgrep Registry": "https://semgrep.dev/c/p/python",
}

_cache: dict[str, bool] = {}


def _require_https(url: str) -> None:
    if not url.startswith("https://"):
        msg = f"Solo se permiten URLs https: {url}"
        raise ValueError(msg)


def reachable(url: str, timeout: float = 6.0) -> bool:
    """True if ``url`` answers with any HTTP status below 500 (cached per run)."""
    if url in _cache:
        return _cache[url]
    _require_https(url)
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "qgate"})  # noqa: S310
    try:
        # nosemgrep: qgate-ssrf-dynamic-url - fixed https endpoints from ENDPOINTS
        with urllib.request.urlopen(request, timeout=timeout):  # noqa: S310  # nosec B310 - https only
            ok = True
    except urllib.error.HTTPError as exc:
        ok = exc.code < 500
    except (urllib.error.URLError, OSError, TimeoutError):
        ok = False
    _cache[url] = ok
    return ok


def download(url: str, dest: Path, sha256: str, timeout: float = 120.0) -> None:
    """Download ``url`` to ``dest`` and verify its SHA-256 (raises on mismatch)."""
    _require_https(url)
    request = urllib.request.Request(url, headers={"User-Agent": "qgate"})  # noqa: S310
    # nosemgrep: qgate-ssrf-dynamic-url - pinned release URL, verified by SHA-256
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310 - https only
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        msg = f"Checksum inválido para {url}: esperado {sha256}, obtenido {digest}"
        raise ValueError(msg)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)

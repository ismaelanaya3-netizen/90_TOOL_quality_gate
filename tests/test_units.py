"""Unit tests for helpers: file system, tools, network, gitleaks bootstrap and dependencies."""

from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from qgate import net, tools
from qgate.checks import gitleaks_bin
from qgate.checks.code_checks import cc_rank
from qgate.checks.deps_checks import DEFAULT_DENYLIST, parse_requirements
from qgate.checks.full_checks import read_locust_stats
from qgate.checks.tests_cov import critical_coverage, junit_counts
from qgate.fsutil import glob_to_regex, iter_files, matches_any
from qgate.models import Severity


def test_matches_any_globs() -> None:
    assert matches_any("examples/vulnerable_fixtures/a.py", ["examples/**"])
    assert matches_any("examples", ["examples/**"])
    assert matches_any("pkg/__pycache__/x.pyc", ["**/__pycache__/**"])
    assert matches_any("a/b/c.egg-info", ["*.egg-info/**"])
    assert not matches_any("src/app.py", ["examples/**"])


def test_glob_to_regex() -> None:
    import re

    rx = re.compile(glob_to_regex("examples/vulnerable_fixtures/**"))
    assert rx.search("examples/vulnerable_fixtures/vulnapp/a.py")
    assert rx.search("examples\\vulnerable_fixtures\\x.py")
    assert re.fullmatch(glob_to_regex("*.py"), "a.py")
    assert not re.fullmatch(glob_to_regex("*.py"), "dir/a.py")
    assert re.fullmatch(glob_to_regex("a?c.txt"), "abc.txt")


def test_iter_files_respects_excludes(tmp_path: Path) -> None:
    for rel in ("app/a.py", "app/b.txt", ".venv/lib/c.py", "app/sub/d.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x = 1\n", encoding="utf-8")
    found = sorted(
        p.relative_to(tmp_path).as_posix()
        for p in iter_files(tmp_path, [".", "app/a.py"], [".py"], [".venv/**", "app/sub/**"])
    )
    assert found == ["app/a.py"]


def test_tools_run_and_versions() -> None:
    out = tools.run([sys.executable, "-c", "print('hola 1.2.3')"])
    assert out.ok
    assert tools.version_of([sys.executable, "-c", "print('v 4.5.6')"]) == "4.5.6"
    missing = tools.run(["qgate-no-existe-xyz"])
    assert missing.missing
    assert not missing.ok
    slow = tools.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert slow.timed_out
    assert tools.version_of(["qgate-no-existe-xyz"]) == ""
    assert tools.module_available("json")
    assert not tools.module_available("qgate_modulo_inexistente")
    assert tools.find_executable("qgate-no-existe-xyz") is None
    assert tools.python_module_cmd("vermin")[1] == "-c"


def test_net_rejects_plain_http(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="https"):
        net.reachable("http://example.com")
    with pytest.raises(ValueError, match="https"):
        net.download("http://example.com/x", tmp_path / "x", "0")


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def test_download_verifies_checksum(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"binario"
    monkeypatch.setattr(net.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(payload))
    good = hashlib.sha256(payload).hexdigest()
    net.download("https://example.com/x", tmp_path / "ok.bin", good)
    assert (tmp_path / "ok.bin").read_bytes() == payload
    with pytest.raises(ValueError, match="Checksum inválido"):
        net.download("https://example.com/x", tmp_path / "bad.bin", "0" * 64)
    assert not (tmp_path / "bad.bin").exists()


def test_reachable_handles_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    def refuse(*args: object, **kwargs: object) -> None:
        raise urllib.error.URLError("sin red")

    def forbidden(*args: object, **kwargs: object) -> None:
        raise urllib.error.HTTPError("https://x", 403, "no", {}, None)  # type: ignore[arg-type]

    net._cache.clear()
    monkeypatch.setattr(net.urllib.request, "urlopen", refuse)
    assert not net.reachable("https://qgate-test-1.invalid/")
    monkeypatch.setattr(net.urllib.request, "urlopen", forbidden)
    assert net.reachable("https://qgate-test-2.invalid/")
    monkeypatch.setattr(net.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(b""))
    assert net.reachable("https://qgate-test-3.invalid/")
    net._cache.clear()


def test_gitleaks_assets_and_extract(tmp_path: Path) -> None:
    assert gitleaks_bin.asset_name("Windows", "AMD64") == "windows_x64.zip"
    assert gitleaks_bin.asset_name("Linux", "aarch64") == "linux_arm64.tar.gz"
    assert gitleaks_bin.asset_name("Darwin", "arm64") == "darwin_arm64.tar.gz"
    assert set(gitleaks_bin.CHECKSUMS) >= {"windows_x64.zip", "linux_x64.tar.gz"}
    name = gitleaks_bin.binary_name()
    tgz = tmp_path / "g.tar.gz"
    with tarfile.open(tgz, "w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = 4
        tar.addfile(info, io.BytesIO(b"bin!"))
    out = tmp_path / "out"
    out.mkdir()
    assert gitleaks_bin._extract(tgz, out).read_bytes() == b"bin!"
    zipped = tmp_path / "g.zip"
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr(name, b"zip!")
    assert gitleaks_bin._extract(zipped, out).read_bytes() == b"zip!"


def test_gitleaks_ensure_without_download(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitleaks_bin, "find", lambda root: None)
    monkeypatch.setenv("QGATE_NO_DOWNLOAD", "1")
    assert gitleaks_bin.ensure(tmp_path) == (None, "gitleaks no instalado y QGATE_NO_DOWNLOAD activo.")
    monkeypatch.delenv("QGATE_NO_DOWNLOAD")
    monkeypatch.setattr(gitleaks_bin.net, "reachable", lambda url: False)
    assert "sin acceso" in gitleaks_bin.ensure(tmp_path)[1]
    monkeypatch.setattr(gitleaks_bin.net, "reachable", lambda url: True)

    def broken(dest: Path) -> Path:
        raise OSError("disco lleno")

    monkeypatch.setattr(gitleaks_bin, "download", broken)
    assert "disco lleno" in gitleaks_bin.ensure(tmp_path)[1]
    monkeypatch.setenv("QGATE_GITLEAKS", sys.executable)
    monkeypatch.undo()
    monkeypatch.setenv("QGATE_GITLEAKS", sys.executable)
    assert gitleaks_bin.find(tmp_path) == sys.executable


def test_parse_requirements(tmp_path: Path) -> None:
    (tmp_path / "base.txt").write_text("idna==3.7\n", encoding="utf-8")
    (tmp_path / "req.txt").write_text(
        "# comentario\n-r base.txt\nfastapi==0.115.0  # api\nrequests>=2\n"
        'colorama==0.4.6 ; platform_system == "Windows"\n-e ./local\n--index-url https://x\n'
        "uvicorn[standard]==0.30.0 \\\n    --hash=sha256:abc\npytest\n",
        encoding="utf-8",
    )
    reqs = {r.name: r for r in parse_requirements(tmp_path / "req.txt", tmp_path)}
    assert reqs["idna"].pinned
    assert reqs["fastapi"].pinned
    assert reqs["colorama"].pinned
    assert reqs["uvicorn"].pinned
    assert not reqs["requests"].pinned
    assert not reqs["pytest"].pinned
    assert reqs["./local"].spec == "editable"


def test_license_denylist() -> None:
    import re

    def denied(text: str) -> bool:
        return any(re.search(rx, text) for rx in DEFAULT_DENYLIST)

    assert denied("GPL-3.0-only")
    assert denied("GNU Affero General Public License v3")
    assert denied("AGPL-3.0")
    assert not denied("LGPL-2.1-or-later")
    assert not denied("GNU Lesser General Public License v3")
    assert not denied("MIT License")


def test_junit_and_coverage_helpers(tmp_path: Path) -> None:
    xml = tmp_path / "j.xml"
    xml.write_text(
        '<testsuites><testsuite name="p" errors="1" failures="2" skipped="0" tests="9"/></testsuites>', encoding="utf-8"
    )
    assert junit_counts(xml) == {"tests": 9, "failures": 2, "errors": 1, "skipped": 0}
    assert junit_counts(tmp_path / "none.xml")["tests"] == 0
    data = {"files": {"app\\auth.py": {"summary": {"percent_covered": 90.0}}, "app/x.py": {"summary": {}}}}
    assert critical_coverage(data, ["app/auth*.py"]) == [("app/auth.py", 90.0)]


def test_locust_stats(tmp_path: Path) -> None:
    csv_path = tmp_path / "s.csv"
    csv_path.write_text(
        "Type,Name,Request Count,Failure Count,95%\nGET,/h,10,0,12\n,Aggregated,10,1,15\n", encoding="utf-8"
    )
    assert read_locust_stats(csv_path) == (15.0, 10.0, 10)
    csv_path.write_text("Type,Name\n", encoding="utf-8")
    assert read_locust_stats(csv_path) == (0.0, 100.0, 0)


def test_misc_mappings() -> None:
    assert [cc_rank(v) for v in (1, 6, 11, 21, 31, 41)] == list("ABCDEF")
    assert Severity.parse("error") is Severity.HIGH
    assert Severity.parse("warning") is Severity.MEDIUM
    assert Severity.LOW.rank < Severity.HIGH.rank

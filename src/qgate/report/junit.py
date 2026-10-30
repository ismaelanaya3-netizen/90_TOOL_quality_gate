"""JUnit XML with one test case per gate check (``qgate-junit.xml``)."""

from __future__ import annotations

from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring  # nosec B405 - writing only

from qgate.models import GateResult, Status


def build(gate: GateResult) -> bytes:
    failures = sum(1 for r in gate.results if r.status is Status.FAIL)
    errors = sum(1 for r in gate.results if r.status is Status.ERROR)
    skipped = sum(1 for r in gate.results if r.status is Status.SKIPPED)
    suite = Element(
        "testsuite",
        name=f"qgate-{gate.level.value}",
        tests=str(len(gate.results)),
        failures=str(failures),
        errors=str(errors),
        skipped=str(skipped),
        time=f"{gate.duration_s:.2f}",
        timestamp=gate.started_at,
    )
    for result in gate.results:
        case = SubElement(
            suite, "testcase", classname=f"qgate.{result.level.value}", name=result.check_id,
            time=f"{result.duration_s:.2f}",
        )  # fmt: skip
        detail = "\n".join(
            f"[{f.severity.value}] {f.rule} {f.file}:{f.line} {f.message}" for f in result.active_findings
        )
        if result.status is Status.FAIL:
            SubElement(case, "failure", message=result.reason or "FAIL").text = detail
        elif result.status is Status.ERROR:
            SubElement(case, "error", message=result.reason or "ERROR")
        elif result.status is Status.SKIPPED:
            SubElement(case, "skipped", message=result.reason)
        elif result.status in {Status.WARN, Status.INFO}:
            SubElement(case, "system-out").text = f"{result.status.value}: {result.reason}"
    root = Element("testsuites", name="qgate")
    root.append(suite)
    body: bytes = tostring(root, encoding="utf-8")
    return body if body.startswith(b"<?xml") else b'<?xml version="1.0" encoding="UTF-8"?>\n' + body


def write(gate: GateResult, out_dir: Path) -> Path:
    path = out_dir / "qgate-junit.xml"
    path.write_bytes(build(gate))
    return path

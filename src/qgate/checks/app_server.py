"""Serve the project's ASGI app with uvicorn on an ephemeral local port."""

from __future__ import annotations

import http.client
import json
import socket
import subprocess  # nosec B404 - only for type hints and TimeoutExpired
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from qgate import tools
from qgate.checks.fastapi_config import production_env
from qgate.context import RunContext

HOST = "127.0.0.1"

DUMP_OPENAPI = """
import importlib, json, os, sys
sys.path.insert(0, os.getcwd())
module, _, attr = sys.argv[1].partition(":")
app = getattr(importlib.import_module(module), attr or "app")
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(app.openapi(), handle)
"""


class AppStartError(RuntimeError):
    """The application could not be started."""


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass
class RunningApp:
    host: str
    port: int
    log: Path

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def request(
        self, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None
    ) -> Response:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=15)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return Response(resp.status, {k.lower(): v for k, v in resp.getheaders()}, data)
        finally:
            conn.close()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        port: int = sock.getsockname()[1]
        return port


def dump_openapi(ctx: RunContext, dest: Path) -> str:
    """Write the OpenAPI schema by importing the app (docs may stay disabled)."""
    out = tools.run(
        [ctx.python, "-c", DUMP_OPENAPI, ctx.cfg.app_module, str(dest)],
        cwd=ctx.root, timeout=120, env=production_env(ctx),
    )  # fmt: skip
    if not dest.is_file():
        return (out.stderr or out.stdout).strip()[-400:]
    json.loads(dest.read_text(encoding="utf-8"))
    return ""


def _wait(app: RunningApp, proc: subprocess.Popen[bytes], health: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log = app.log.read_text(encoding="utf-8", errors="replace")[-600:]
            msg = f"uvicorn terminó al iniciar (código {proc.returncode}): {log}"
            raise AppStartError(msg)
        try:
            if app.request("GET", health).status < 500:
                return
        except OSError:
            time.sleep(0.3)
    msg = f"La app no respondió en {timeout:.0f} s en {app.base_url}{health}"
    raise AppStartError(msg)


@contextmanager
def serve(ctx: RunContext, name: str) -> Iterator[RunningApp]:
    if not ctx.cfg.app_module:
        msg = "No hay app_module configurado en [proyecto]."
        raise AppStartError(msg)
    port = free_port()
    app = RunningApp(HOST, port, ctx.out_dir / f"uvicorn-{name}.log")
    args = [
        ctx.python, "-m", "uvicorn", ctx.cfg.app_module, "--host", HOST, "--port", str(port),
        "--log-level", "warning", "--no-server-header", "--no-access-log",
    ]  # fmt: skip
    proc = tools.spawn(args, ctx.root, production_env(ctx), app.log)
    try:
        _wait(app, proc, str(ctx.cfg.option("fastapi", "ruta_salud", "/health")), 60.0)
        yield app
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

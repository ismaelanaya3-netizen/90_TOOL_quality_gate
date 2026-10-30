from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient
from starlette.types import Message, Receive, Scope, Send

from app.security import SECURITY_HEADERS, BodySizeLimitMiddleware, SecurityHeadersMiddleware


def test_security_headers_on_every_response(client: TestClient) -> None:
    for path in ("/health", "/", "/no-existe"):
        response = client.get(path)
        for header, value in SECURITY_HEADERS.items():
            assert response.headers[header] == value


def test_not_found_does_not_leak_traces(client: TestClient) -> None:
    response = client.get("/no-existe")
    assert response.status_code == 404
    assert "Traceback" not in response.text


def test_untrusted_host_rejected(client: TestClient) -> None:
    response = client.get("/health", headers={"Host": "evil.example.com"})
    assert response.status_code == 400
    assert "X-Frame-Options" in response.headers


def test_cors_is_restricted(client: TestClient) -> None:
    response = client.get("/health", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in response.headers


def test_large_body_rejected_by_content_length(client: TestClient) -> None:
    response = client.post("/health", content=b"x" * 2048)
    assert response.status_code == 413


def test_method_not_allowed(client: TestClient) -> None:
    assert client.delete("/health").status_code == 405


async def _echo_app(scope: Scope, receive: Receive, send: Send) -> None:
    while (await receive()).get("more_body"):
        pass
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _run(app: BodySizeLimitMiddleware, chunks: list[bytes], headers: list[tuple[bytes, bytes]]) -> list[Message]:
    sent: list[Message] = []
    pending = list(chunks)

    async def receive() -> Message:
        body = pending.pop(0) if pending else b""
        return {"type": "http.request", "body": body, "more_body": bool(pending)}

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {"type": "http", "headers": headers}
    asyncio.run(app(scope, receive, send))
    return sent


def test_streamed_body_over_limit_rejected() -> None:
    app = BodySizeLimitMiddleware(_echo_app, max_bytes=10)
    sent = _run(app, [b"x" * 6, b"x" * 6], [])
    assert sent[0]["status"] == 413


def test_streamed_body_within_limit_passes() -> None:
    app = BodySizeLimitMiddleware(_echo_app, max_bytes=10)
    sent = _run(app, [b"x" * 3, b"x" * 3], [])
    assert sent[0]["status"] == 200


def test_invalid_content_length_rejected() -> None:
    app = BodySizeLimitMiddleware(_echo_app, max_bytes=10)
    sent = _run(app, [b""], [(b"content-length", b"abc")])
    assert sent[0]["status"] == 413


def test_limit_after_response_started_is_not_overwritten() -> None:
    async def early_app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        while (await receive()).get("more_body"):
            pass

    sent = _run(BodySizeLimitMiddleware(early_app, max_bytes=4), [b"xxx", b"xxx"], [])
    assert [m["status"] for m in sent if m["type"] == "http.response.start"] == [200]


def test_non_http_scopes_pass_through() -> None:
    calls: list[str] = []

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        calls.append(scope["type"])

    async def noop_receive() -> Message:
        return {}

    async def noop_send(message: Message) -> None:
        return None

    for middleware in (SecurityHeadersMiddleware(inner), BodySizeLimitMiddleware(inner, 1)):
        asyncio.run(middleware({"type": "lifespan"}, noop_receive, noop_send))
    assert calls == ["lifespan", "lifespan"]

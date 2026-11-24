"""ASGI helpers shared by the HTTP services."""

from __future__ import annotations

DEFAULT_MAX_BODY = 64 * 1024


class BodyLimit:
    """Reject request bodies over `max_bytes` with 413 before the app or pydantic sees them.

    Checks Content-Length up front and also counts streamed (chunked) bytes, so a missing or
    lying header cannot get a larger body through (review F6).
    """

    def __init__(self, app, max_bytes: int = DEFAULT_MAX_BODY) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                if not v.isdigit() or int(v) > self.max_bytes:
                    await _too_large(send)
                    return
        body = bytearray()
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            body += msg.get("body", b"")
            if len(body) > self.max_bytes:
                await _too_large(send)
                return
            if not msg.get("more_body", False):
                break
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


async def _too_large(send) -> None:
    payload = b'{"detail":"request body too large"}'
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode()),
                    (b"connection", b"close")],
    })
    await send({"type": "http.response.body", "body": payload})

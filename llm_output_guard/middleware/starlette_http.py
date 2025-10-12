from __future__ import annotations
from starlette.types import ASGIApp, Scope, Receive, Send

class OutputGuardMiddleware:
    """
    Placeholder for now: just forwards the call.
    We’ll add scanning/redaction logic in M1.
    """
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        await self.app(scope, receive, send)

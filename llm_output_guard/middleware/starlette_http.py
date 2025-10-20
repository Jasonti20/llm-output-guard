from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import json
from starlette.types import ASGIApp, Scope, Receive, Send, Message

from llm_output_guard.core.engine import ScanEngine
from llm_output_guard.policy.loader import load_policy

TEXT_CT_PREFIXES = ("text/",)
JSON_CT = "application/json"


class OutputGuardMiddleware:
    """
    ASGI middleware that buffers non-streaming HTTP responses (text/*, application/json),
    scans them with the guard, then enforces policy: block / redact / quarantine / pass.
    """

    def __init__(
        self, app: ASGIApp, *, profile: str = "balanced", max_bytes: int = 512_000
    ):
        self.app = app
        self.policy = load_policy(profile=profile)
        self.engine = ScanEngine(policy=self.policy, max_bytes=max_bytes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        status_code: Optional[int] = None
        headers: List[Tuple[bytes, bytes]] = []
        body_chunks: List[bytes] = []

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, headers, body_chunks
            if message["type"] == "http.response.start":
                status_code = message.get("status")
                headers = message.get("headers", [])
            elif message["type"] == "http.response.body":
                body_chunks.append(message.get("body", b""))
            else:
                await send(message)

        await self.app(scope, receive, send_wrapper)

        if status_code is None:
            return  # Nothing to send

        # Determine content-type
        content_type = b""
        for k, v in headers:
            if k.lower() == b"content-type":
                content_type = v
                break
        ct = content_type.decode("latin1").split(";")[0].strip().lower()
        body = b"".join(body_chunks)

        # Skip scanning for non-success or unsupported content types
        if (
            status_code < 200
            or status_code >= 400
            or not (ct.startswith(TEXT_CT_PREFIXES) or ct == JSON_CT)
        ):
            await send(
                {
                    "type": "http.response.start",
                    "status": status_code,
                    "headers": headers,
                }
            )
            await send({"type": "http.response.body", "body": body, "more_body": False})
            return

        # ---Scan & enforace --
        try:
            findings: List[Dict[str, Any]] = []
            action = "pass"
            redacted_bytes = body

            if ct == JSON_CT:
                data = json.loads(body.decode("utf-8", errors="replace"))
                result = self.engine.scan_json(data)
                findings = result.findings
                action = result.action
                if action in ("redact", "block", "quarantine"):
                    data = self.engine.apply_json_redactions(data, result)
                    redacted_bytes = json.dumps(data, ensure_ascii=False).encode(
                        "utf-8"
                    )
            else:
                text = body.decode("utf-8", errors="replace")
                result = self.engine.scan_text(text)
                findings = result.findings
                action = result.action
                if action in ("redact", "block", "quarantine"):
                    text = self.engine.apply_text_redactions(text, result)
                    redacted_bytes = text.encode("utf-8")

        except Exception as e:
            # Fail opne; add error marker
            headers = _set_header(
                headers, b"x-llm-guard-error", str(type(e).__name__).encode("latin-1")
            )
            await send(
                {
                    "type": "http.response.start",
                    "status": status_code,
                    "headers": headers,
                }
            )
            await send({"type": "http.response.body", "body": body, "more_body": False})
            return

        # Enforce action
        if action == "block":
            payload = json.dumps(
                {
                    "error": "output_blocked",
                    "reason": "Policy blocked risky content.",
                    "findings": findings,
                },
                ensure_ascii=False,
            ).encode("utf-8")
            headers = _replace_content_type(headers, JSON_CT)
            headers = _set_header(
                headers, b"x-llm-guard-findings", str(len(findings)).encode("latin-1")
            )
            headers = _set_header(headers, b"x-llm-guard-action", b"block")
            await send(
                {"type": "http.response.start", "status": 422, "headers": headers}
            )
            await send(
                {"type": "http.response.body", "body": payload, "more_body": False}
            )
            return

        if action == "quarantine":
            payload = json.dumps(
                {"status": "quarantined", "findings": findings}, ensure_ascii=False
            ).encode("utf-8")
            headers = _replace_content_type(headers, JSON_CT)
            headers = _set_header(
                headers, b"x-llm-guard-findings", str(len(findings)).encode("latin-1")
            )
            headers = _set_header(headers, b"x-llm-guard-action", b"quarantine")
            await send(
                {"type": "http.response.start", "status": 202, "headers": headers}
            )
            await send(
                {"type": "http.response.body", "body": payload, "more_body": False}
            )
            return

        # redact or pass
        headers = _set_header(
            headers, b"x-llm-guard-findings", str(len(findings)).encode("latin-1")
        )
        if findings:
            headers = _set_header(
                headers, b"x-llm-guard-action", action.encode("latin-1")
            )
        await send(
            {"type": "http.response.start", "status": status_code, "headers": headers}
        )
        await send(
            {"type": "http.response.body", "body": redacted_bytes, "more_body": False}
        )


def _set_header(
    headers: List[Tuple[bytes, bytes]], key: bytes, value: bytes
) -> List[Tuple[bytes, bytes]]:
    lower = key.lower()
    out: List[Tuple[bytes, bytes]] = []
    replaced = False
    for k, v in headers:
        if k.lower() == lower:
            out.append((k, value))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((key, value))
    return out


def _replace_content_type(
    headers: List[Tuple[bytes, bytes]], ct: str
) -> List[Tuple[bytes, bytes]]:
    return _set_header(headers, b"content-type", ct.encode("latin-1"))

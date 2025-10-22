from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import json
from starlette.types import ASGIApp, Scope, Receive, Send, Message

from llm_output_guard.core.adapter import (
    apply_text,
    apply_json_values,
)

TEXT_CT_PREFIXES = ("text/",)
JSON_CT = "application/json"
MW_MAX_SCAN_BYTES = 2_000_000  # middleware-level safety cap


class OutputGuardMiddleware:
    """
    ASGI middleware (Step 1): buffer non-streaming HTTP responses (text/*, application/json),
    run detection ONLY, and add headers. Do NOT mutate body or block yet.
    """

    def __init__(self, app: ASGIApp, *, profile: str = "balanced"):
        self.app = app
        self.profile = profile

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
        raw_ct = b""
        for k, v in headers:
            if k.lower() == b"content-type":
                raw_ct = v
                break
        ct_full = raw_ct.decode("latin1").strip()
        ct_only = ct_full.split(";", 1)[0].strip().lower()
        charset = _charset_from(ct_full)
        body = b"".join(body_chunks)

        # Skip scanning for non-success or unsupported content types
        if (
            status_code < 200
            or status_code >= 400
            or not (ct_only.startswith(TEXT_CT_PREFIXES) or ct_only == JSON_CT)
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

        # ---- Apply actions
        truncated_by_mw = False
        scan_payload = body
        if len(scan_payload) > MW_MAX_SCAN_BYTES:
            truncated_by_mw = True
            scan_payload = scan_payload[:MW_MAX_SCAN_BYTES]

        findings_count = 0
        blocked = False
        timed_out = False
        detect_ms = 0.0
        action = "pass"
        redacted_bytes = body

        try:
            if ct_only == JSON_CT:
                try:
                    obj = json.loads(scan_payload.decode(charset, errors="replace"))
                except Exception:
                    # If invalid JSON, treat as text
                    text = scan_payload.decode(charset, errors="replace")
                    action, out_text, rep = apply_text(text, profile=self.profile)
                    redacted_bytes = out_text.encode(charset, errors="replace")
                else:
                    action, out_obj, rep = apply_json_values(obj, profile=self.profile)
                    redacted_bytes = json.dumps(out_obj, ensure_ascii=False).encode(
                        "utf-8"
                    )
            else:
                text = scan_payload.decode(charset, errors="replace")
                action, out_text, rep = apply_text(text, profile=self.profile)
                redacted_bytes = out_text.encode(charset, errors="replace")

            if rep:
                findings_count = int(rep.findings_count)
                blocked = bool(rep.blocked)
                timed_out = bool(rep.timed_out)
                detect_ms = float(rep.detect_time_ms)

        except Exception as e:
            headers = _set_header(
                headers,
                b"x-llm-output-guard-error",
                str(type(e).__name__).encode("latin-1"),
            )
            # Fail-open: return original body
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
        headers = _set_header(
            headers, b"x-llm-guard-findings", str(findings_count).encode("latin-1")
        )
        headers = _set_header(headers, b"x-llm-guard-action", action.encode("latin-1"))
        headers = _set_header(
            headers, b"x-llm-guard-blocked", b"true" if blocked else b"false"
        )
        headers = _set_header(
            headers, b"x-llm-guard-timedout", b"true" if timed_out else b"false"
        )
        headers = _set_header(
            headers, b"x-llm-guard-detectms", f"{detect_ms:.2f}".encode("latin-1")
        )
        headers = _set_header(
            headers, b"x-llm-guard-profile", self.profile.encode("latin-1")
        )
        if truncated_by_mw:
            headers = _set_header(headers, b"x-llm-guard-truncated", b"true")

        if action == "block":
            payload = json.dumps(
                {
                    "error": "output_blocked",
                    "message": "Policy blocked risky content.",
                    "findings": findings_count,
                },
                ensure_ascii=False,
            ).encode("utf-8")
            headers = _set_header(headers, b"content-type", JSON_CT.encode("latin-1"))
            headers = _set_or_drop_content_length(headers, len(payload))
            await send(
                {"type": "http.response.start", "status": 422, "headers": headers}
            )
            await send(
                {"type": "http.response.body", "body": payload, "more_body": False}
            )
            return
        # redact or pass
        final_body = redacted_bytes if action == "redact" else body
        headers = _set_or_drop_content_length(headers, len(final_body))
        await send(
            {"type": "http.response.start", "status": status_code, "headers": headers}
        )
        await send(
            {"type": "http.response.body", "body": final_body, "more_body": False}
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


def _charset_from(content_type: str) -> str:
    # Default to UTF-8 per RFC
    if not content_type:
        return "utf-8"
    parts = [p.strip() for p in content_type.split(";")]
    for p in parts[1:]:
        if p.lower().startswith("charset="):
            val = p.split("=", 1)[1].strip()
            return val or "utf-8"
    return "utf-8"


def _set_or_drop_content_length(
    headers: list[tuple[bytes, bytes]], length: int | None
) -> list[tuple[bytes, bytes]]:
    # remove any existing content-length
    filtered = [(k, v) for (k, v) in headers if k.lower() != b"content-length"]
    if length is not None:
        filtered.append((b"content-length", str(length).encode("latin-1")))
    return filtered

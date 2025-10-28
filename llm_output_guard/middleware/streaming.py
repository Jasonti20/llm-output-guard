from __future__ import annotations
import codecs
from typing import Any, Awaitable, Callable, Dict, Optional

from llm_output_guard.core.adapter import apply_text

DEFAULT_BUFFER_CHARS = 8192  # rolling window size in *characters*


def _is_text_like(content_type: Optional[str]) -> bool:
    if not content_type:
        return False
    ct = content_type.lower()
    return (
        ct.startswith("text/") or "application/json" in ct or "text/event-stream" in ct
    )


class StreamingOutputGuardMiddleware:
    """
    Phase 1 (redact-only):
      - Intercepts streaming text/SSE/JSON-ish responses.
      - Maintains a redacted rolling buffer across body frames.
      - Uses adapter.apply_text(profile=...) each frame.
      - If engine says 'block', we still *redact* for now (abort logic in next step).
    """

    def __init__(
        self,
        app,
        *,
        profile: str = "balanced",
        buffer_chars: int = DEFAULT_BUFFER_CHARS,
    ):
        self.app = app
        self.profile = profile
        self.buffer_chars = buffer_chars

    async def __call__(
        self,
        scope: Dict[str, Any],
        receive: Callable[[], Awaitable[Dict[str, Any]]],
        send: Callable[[Dict[str, Any]], Awaitable[None]],
    ):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        content_type: Optional[str] = None
        inc_decoder = None
        inc_encoder = None
        rolling = ""  # keep the *redacted* rolling buffer

        async def guarded_send(message: Dict[str, Any]):
            nonlocal content_type, inc_decoder, inc_encoder, rolling

            mtype = message.get("type")
            if mtype == "http.response.start":
                # Capture content-type
                for k, v in message.get("headers") or []:
                    try:
                        if k.decode("latin1").lower() == "content-type":
                            content_type = v.decode("latin1")
                    except Exception:
                        pass
                await send(message)
                return

            if mtype != "http.response.body":
                await send(message)
                return

            body: bytes = message.get("body", b"")
            more_body: bool = bool(message.get("more_body", False))

            # Non-text or empty → passthrough
            if not body or not _is_text_like(content_type):
                await send(message)
                return

            # Lazy codecs (UTF-8 safe)
            if inc_decoder is None:
                inc_decoder = codecs.getincrementaldecoder("utf-8")()
            if inc_encoder is None:
                inc_encoder = codecs.getincrementalencoder("utf-8")()

            # Decode this chunk; final=True only on last frame
            decoded_piece = inc_decoder.decode(body, final=not more_body)

            # Append to rolling, cap size
            rolling += decoded_piece
            if len(rolling) > self.buffer_chars:
                rolling = rolling[-self.buffer_chars :]

            # Redact the entire rolling buffer using your engine
            action, redacted_full, _report = apply_text(
                rolling, profile=self.profile, coerce_block_to_redact=True
            )

            # In phase 1, treat "block" as "redact"
            # Emit only the *tail* corresponding to the newly added piece
            tail_len = len(decoded_piece)
            emit_segment = (
                redacted_full[-tail_len:]
                if tail_len <= len(redacted_full)
                else redacted_full
            )

            # Re-encode and send
            out_bytes = inc_encoder.encode(emit_segment, final=False)
            await send(
                {
                    "type": "http.response.body",
                    "body": out_bytes,
                    "more_body": more_body,
                }
            )

            # keep redacted buffer
            rolling = redacted_full

            # On last frame, flush encoder (usually a no-op)
            if not more_body:
                leftover = inc_encoder.encode("", final=True)
                if leftover:
                    await send(
                        {
                            "type": "http.response.body",
                            "body": leftover,
                            "more_body": False,
                        }
                    )

        await self.app(scope, receive, guarded_send)

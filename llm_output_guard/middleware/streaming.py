from __future__ import annotations
import codecs
from typing import Any, Awaitable, Callable, Dict, Optional

from llm_output_guard.core.adapter import apply_text

DEFAULT_BUFFER_CHARS = 8192  # rolling window size in *characters*
DEFAULT_HOLDBACK_CHARS = 64  # trailing chars to hold back to prevent cross-chunk leaks


def _is_text_like(content_type: Optional[str]) -> bool:
    if not content_type:
        return False
    ct = content_type.lower()
    return (
        ct.startswith("text/") or "application/json" in ct or "text/event-stream" in ct
    )


class StreamingOutputGuardMiddleware:
    """
    Streaming guard:
      - Intercepts streaming text/SSE/JSON-ish responses.
      - Maintains a redacted rolling buffer across body frames.
       - Uses adapter.apply_text(profile=...) each frame.
      - Redacts inline; if a CRITICAL finding is detected and block_critical_stream=True, stop the stream immediately.
    """

    def __init__(
        self,
        app,
        *,
        profile: str = "balanced",
        buffer_chars: int = DEFAULT_BUFFER_CHARS,
        holdback_chars: int = DEFAULT_HOLDBACK_CHARS,
        block_critical_stream: bool = False,
        sse_error_message: str = "LLM Output Guard: critical content detected; stream stopped.",
    ):
        self.app = app
        self.profile = profile
        self.buffer_chars = buffer_chars
        self.holdback_chars = max(0, int(holdback_chars))
        self.block_critical_stream = block_critical_stream
        self.sse_error_message = sse_error_message

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
        rolling = ""  # working buffer (we keep it updated to the redacted buffer)
        sent_upto = 0  # number of chars (in redacted space) already emitted
        aborted = False

        async def guarded_send(message: Dict[str, Any]):
            nonlocal content_type, inc_decoder, inc_encoder, rolling, sent_upto, aborted

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
            if aborted:
                # drop further body frames once aborted
                return

            body: bytes = message.get("body", b"")
            more_body: bool = bool(message.get("more_body", False))

            # Non-text → passthrough
            if not _is_text_like(content_type):
                await send(message)
                return

            # Lazy codecs (UTF-8 safe)
            if inc_decoder is None:
                inc_decoder = codecs.getincrementaldecoder("utf-8")()
            if inc_encoder is None:
                inc_encoder = codecs.getincrementalencoder("utf-8")()

            # Starlette StreamingResponse often ends with an empty final frame:
            #   body=b"", more_body=False
            # Flush any held-back content here (otherwise nothing is emitted).
            if not body and not more_body:
                action, redacted_full, report = apply_text(
                    rolling, profile=self.profile, coerce_block_to_redact=True
                )

                # Must-stop: end stream when a critical finding is present
                if self.block_critical_stream and getattr(report, "critical", False):
                    if content_type and "text/event-stream" in content_type.lower():
                        payload = f"event: error\ndata: {self.sse_error_message}\n\n"
                        await send(
                            {
                                "type": "http.response.body",
                                "body": payload.encode("utf-8"),
                                "more_body": False,
                            }
                        )
                    else:
                        placeholder = "[stream stopped: sensitive content]\n"
                        await send(
                            {
                                "type": "http.response.body",
                                "body": placeholder.encode("utf-8"),
                                "more_body": False,
                            }
                        )
                    aborted = True
                    return

                # Emit everything not yet emitted.
                emit_segment = ""
                if sent_upto < len(redacted_full):
                    emit_segment = redacted_full[sent_upto:]
                    sent_upto = len(redacted_full)

                rolling = redacted_full

                out_bytes = inc_encoder.encode(emit_segment, final=False)
                leftover = inc_encoder.encode("", final=True)
                await send(
                    {
                        "type": "http.response.body",
                        "body": out_bytes + leftover,
                        "more_body": False,
                    }
                )
                return
            # Empty mid-stream chunk: passthrough
            if not body and more_body:
                await send(message)
                return

            # Decode this chunk; final=True only on last frame
            decoded_piece = inc_decoder.decode(body, final=not more_body)

            # Append to rolling, cap size
            rolling += decoded_piece
            if len(rolling) > self.buffer_chars:
                excess = len(rolling) - self.buffer_chars
                # Prefer dropping already-emitted prefix first
                drop = min(excess, sent_upto)
                if drop > 0:
                    rolling = rolling[drop:]
                    sent_upto -= drop
                    excess -= drop
                # If still too big, drop remaining (best-effort)
                if excess > 0:
                    rolling = rolling[excess:]
                    sent_upto = 0

            # Redact the entire rolling buffer using your engine
            action, redacted_full, report = apply_text(
                rolling, profile=self.profile, coerce_block_to_redact=True
            )

            # Holdback strategy:
            # While streaming, do NOT emit the last holdback_chars so that
            # cross-chunk sensitive tokens can be detected/redacted before ANY part is emitted.
            if more_body:
                safe_upto = max(0, len(redacted_full) - self.holdback_chars)
            else:
                safe_upto = len(redacted_full)

            emit_segment = ""
            if safe_upto > sent_upto:
                emit_segment = redacted_full[sent_upto:safe_upto]
                sent_upto = safe_upto

            # Must-stop: end stream when a critical finding is present
            if self.block_critical_stream and getattr(report, "critical", False):
                if content_type and "text/event-stream" in content_type.lower():
                    payload = f"event: error\ndata: {self.sse_error_message}\n\n"
                    await send(
                        {
                            "type": "http.response.body",
                            "body": payload.encode("utf-8"),
                            "more_body": False,
                        }
                    )
                else:
                    placeholder = "[stream stopped: sensitive content]\n"
                    await send(
                        {
                            "type": "http.response.body",
                            "body": placeholder.encode("utf-8"),
                            "more_body": False,
                        }
                    )
                aborted = True
                return

            # keep redacted buffer (so sent_upto aligns with redacted space next frame)
            rolling = redacted_full

            # Re-encode and send (send empty only on final frame to close response)
            if emit_segment or not more_body:
                out_bytes = inc_encoder.encode(emit_segment, final=False)
                await send(
                    {
                        "type": "http.response.body",
                        "body": out_bytes,
                        "more_body": more_body,
                    }
                )


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

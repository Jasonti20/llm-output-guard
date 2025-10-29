import asyncio
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.responses import StreamingResponse
from llm_output_guard.middleware import StreamingOutputGuardMiddleware


async def sse_endpoint(request):
    async def gen():
        # split a VISA number across two events to test cross-chunk redaction
        yield "data: Partial: 4242 4242 4242 42\n\n"
        await asyncio.sleep(0.03)
        yield "data: 42 and more text\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


async def sse_pem(request):
    async def gen():
        # benign first message
        yield "data: hello...\n\n"
        await asyncio.sleep(0.03)
        # CRITICAL trigger: PEM header (policy key: pem_key, severity: critical)
        yield "data: -----BEGIN PRIVATE KEY-----\n\n"
        await asyncio.sleep(0.03)
        # This must NOT appear when block_critical_stream=True
        yield "data: MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


app = Starlette(
    routes=[
        Route("/sse", sse_endpoint),
        Route("/sse-pem", sse_pem),
    ],
    middleware=[
        Middleware(
            StreamingOutputGuardMiddleware,
            profile="balanced",
            buffer_chars=8192,
            block_critical_stream=True,
        ),
    ],
)


# Run with: uvicorn llm_output_guard.examples.streaming_app:app --reload
# Then:      curl -N http://127.0.0.1:8000/sse

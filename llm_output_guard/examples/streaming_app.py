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


app = Starlette(
    routes=[Route("/sse", sse_endpoint)],
    middleware=[
        Middleware(
            StreamingOutputGuardMiddleware, profile="balanced", buffer_chars=8192
        ),
    ],
)


# Run with: uvicorn llm_output_guard.examples.streaming_app:app --reload
# Then:      curl -N http://127.0.0.1:8000/sse

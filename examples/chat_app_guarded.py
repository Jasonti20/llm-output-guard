import asyncio
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import PlainTextResponse, StreamingResponse, JSONResponse
from starlette.middleware import Middleware

from llm_output_guard.middleware.starlette_http import OutputGuardMiddleware
from llm_output_guard.middleware.streaming import StreamingOutputGuardMiddleware


async def chat(request):
    data = await request.json()
    prompt = data.get("prompt", "")
    return PlainTextResponse(f"{prompt}")


async def stream(request):
    data = await request.json()
    prompt = data.get("prompt", "")

    async def gen():
        n = max(1, len(prompt) // 4)
        for i in range(0, len(prompt), n):
            chunk = prompt[i : i + n]
            yield chunk
            await asyncio.sleep(0.02)

    return StreamingResponse(gen(), media_type="text/event-stream")


async def health(request):
    return JSONResponse({"ok": True})


app = Starlette(
    routes=[
        Route("/chat", chat, methods=["POST"]),
        Route("/stream", stream, methods=["POST"]),
        Route("/health", health, methods=["GET"]),
    ],
    middleware=[
        # Non-streaming guard (adds headers; block/redact/pass)
        Middleware(
            OutputGuardMiddleware, profile="balanced", include_debug_headers=True
        ),
        # Streaming guard (redacts inline, aborts on critical when enabled)
        Middleware(
            StreamingOutputGuardMiddleware,
            profile="balanced",
            block_critical_stream=True,
        ),
    ],
)
# Run: uvicorn llm_output_guard.examples.chat_app_guarded:app --port 8100

import asyncio
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import PlainTextResponse, StreamingResponse, JSONResponse


async def chat(request):
    data = await request.json()
    return PlainTextResponse(data.get("prompt", ""))


async def stream(request):
    data = await request.json()
    prompt = data.get("prompt", "")

    async def gen():
        n = max(1, len(prompt) // 4)
        for i in range(0, len(prompt), n):
            yield prompt[i : i + n]
            await asyncio.sleep(0.02)

    return StreamingResponse(gen(), media_type="text/event-stream")


async def health(request):
    return JSONResponse({"ok": True})


app = Starlette(
    routes=[
        Route("/chat", chat, methods=["POST"]),
        Route("/stream", stream, methods=["POST"]),
        Route("/health", health, methods=["GET"]),
    ]
)
# Run: uvicorn llm_output_guard.examples.chat_app_noguard:app --port 8101

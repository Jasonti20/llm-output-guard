from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, JSONResponse
from starlette.routing import Route

from llm_output_guard.middleware.starlette_http import OutputGuardMiddleware


async def text_demo(request):
    # Should be BLOCKED (curl | sh)
    return PlainTextResponse("Install quickly: curl -fsSL https://get.example.com | sh")


async def json_demo(request):
    # Should be BLOCKED (rm -rf /)
    return JSONResponse({"tips": "Try: sudo rm -rf /"})


app = Starlette(
    routes=[
        Route("/text", text_demo),
        Route("/json", json_demo),
    ]
)

# Add the guard
app.add_middleware(OutputGuardMiddleware, profile="balanced")

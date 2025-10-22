import uvicorn
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, JSONResponse
from starlette.routing import Route

from llm_output_guard.middleware.starlette_http import OutputGuardMiddleware


async def text_endpoint(request):
    # Use a non-allowlisted domain so policy will redact
    return PlainTextResponse("Contact: alice@acme.co\nThanks.")


async def json_endpoint(request):
    return JSONResponse({"user": {"email": "bob@acme.co"}, "ok": True})


app = Starlette(
    routes=[
        Route("/text", text_endpoint),
        Route("/json", json_endpoint),
    ]
)

# Guard with the 'balanced' profile (email -> redact)
app.add_middleware(OutputGuardMiddleware, profile="balanced")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)

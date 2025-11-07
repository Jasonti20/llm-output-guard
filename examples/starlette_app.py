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


async def risky_text(request):
    # Triggers block in balanced policy (card + dangerous shell hint)
    return PlainTextResponse(
        "demo card: 4111 1111 1111 1111; also rm -rf / (do not run)"
    )


async def risky_json(request):
    return JSONResponse({"note": "sample", "card": "5555555555554444"})


app = Starlette(
    routes=[
        Route("/text", text_endpoint),
        Route("/json", json_endpoint),
        Route("/risky-text", risky_text),
        Route("/risky-json", risky_json),
    ]
)

# Guard with the 'balanced' profile (email -> redact; credit_card -> block)
app.add_middleware(
    OutputGuardMiddleware,
    profile="balanced",
    coerce_block_to_redact=False,  # keep block behavior for demo
    include_debug_headers=True,  # set True to expose extra timing headers
)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)

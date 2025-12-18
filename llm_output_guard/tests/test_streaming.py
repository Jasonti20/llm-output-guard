from starlette.applications import Starlette
from starlette.responses import StreamingResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from llm_output_guard.middleware.streaming import StreamingOutputGuardMiddleware

def test_streaming_redacts_split_credit_card():
    async def sse(request):
        # 4111 1111 1111 1111 split across chunks
        chunks = [
            "data: card=411111111111",
            "1111\n\n",
        ]
        
        async def gen():
            for c in chunks:
                yield c.encode("utf-8")
        
        return StreamingResponse(gen(), media_type="text/event-stream")
    
    app = Starlette(routes=[Route("/sse", sse)])
    
    # middleware is ASGI-style; Starlette will instantiate it with (app, **kwargs)
    app.add_middleware(
        StreamingOutputGuardMiddleware,
        profile="balanced",
        buffer_chars=8192,
        block_critical_stream=False, # not needed for this test
    )
    
    client = TestClient(app)
    r = client.get("/sse")
    assert r.status_code == 200
    
    body = r.text
    assert "4111111111111111" not in body, "raw card leaked through streaming response"
    # Last 4 may remain visible per policy; this just sanity-checks redaction happened.
    assert "1111" in body
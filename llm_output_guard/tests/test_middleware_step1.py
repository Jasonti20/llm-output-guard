# llm_output_guard/tests/test_middleware_step1.py
from starlette.testclient import TestClient
from examples.starlette_app import app

client = TestClient(app)


def test_text_headers_and_action_present():
    r = client.get("/text")
    assert r.status_code == 200
    # Detection + action headers should always be present
    assert "X-LLM-Guard-Findings" in r.headers
    assert "X-LLM-Guard-Action" in r.headers

    action = r.headers["X-LLM-Guard-Action"].lower()
    if action == "redact":
        assert "alice@acme.co" not in r.text
    elif action == "pass":
        assert "alice@acme.co" in r.text
    else:
        # block/quarantine are not expected for this endpoint
        raise AssertionError(f"Unexpected action for /text: {action}")


def test_json_headers_and_action_present():
    r = client.get("/json")
    assert r.status_code == 200
    assert "X-LLM-Guard-Findings" in r.headers
    assert "X-LLM-Guard-Action" in r.headers

    data = r.json()
    action = r.headers["X-LLM-Guard-Action"].lower()
    if action == "redact":
        assert data["user"]["email"] != "bob@acme.co"
    elif action == "pass":
        assert data["user"]["email"] == "bob@acme.co"
    else:
        raise AssertionError(f"Unexpected action for /json: {action}")

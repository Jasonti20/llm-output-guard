from starlette.testclient import TestClient
from examples.starlette_app import app

client = TestClient(app)


def test_text_redacts_when_needed():
    r = client.get("/text")
    assert r.status_code == 200
    assert r.headers.get("X-LLM-Guard-Action", "").lower() == "redact"
    # confirm original email is not visible
    assert "alice@acme.co" not in r.text


def test_json_redacts_string_values():
    r = client.get("/json")
    assert r.status_code == 200
    assert r.headers.get("X-LLM-Guard-Action", "").lower() == "redact"
    data = r.json()
    assert data["user"]["email"] != "bob@acme.co"

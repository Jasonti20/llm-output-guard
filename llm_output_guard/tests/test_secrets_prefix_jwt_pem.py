from llm_output_guard.core.engine import scan_and_apply

def test_prefix_openai_blocks():
    res = scan_and_apply("leak sk-abcABC123xyzXYZ7890morechars", "balanced")
    assert res.blocked is True

def test_prefix_aws_blocks():
    res = scan_and_apply("AKIAABCDEFGHJKLMNPQRST", "balanced")
    assert res.blocked is True

def test_jwt_blocks():
    s = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    res = scan_and_apply(f"token={s}", "balanced")
    assert res.blocked is True

def test_pem_blocks():
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...\n"
        "-----END PRIVATE KEY-----"
    )
    res = scan_and_apply(pem, "balanced")
    assert res.blocked is True
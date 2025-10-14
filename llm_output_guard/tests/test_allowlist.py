from llm_output_guard.core.engine import scan_and_apply

def test_email_allowlist_balanced():
    txt = "Contact admin@example.com and joe@notallowed.com"
    res = scan_and_apply(txt, "balanced")
    assert "admin@example.com" in res.text        # allowed by @example.com
    assert "joe@notallowed.com" not in res.text   # redacted
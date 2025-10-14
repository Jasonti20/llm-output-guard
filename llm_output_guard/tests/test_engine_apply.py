from llm_output_guard.core.engine import scan_and_apply


def test_redact_email_and_phone_balanced():
    txt = "Contact alice@realemail.com or +15551234567 today."
    res = scan_and_apply(txt, "balanced")
    assert not res.blocked
    assert "alice@realemail.com" not in res.text
    assert "+15551234567" not in res.text
    # text still contains surrounding words
    assert "Contact " in res.text and " today." in res.text


def test_block_on_ssn_balanced():
    txt = "Employee SSN 123-45-6789"
    res = scan_and_apply(txt, "balanced")
    assert res.blocked is True
    # blocked → engine does not mutate text; middleware will handle response status
    assert "123-45-6789" in res.text


def test_permissive_flags_email_not_redacted():
    txt = "Email bob@x.com"
    res = scan_and_apply(txt, "permissive")
    assert not res.blocked
    # permissive profile flags email (no redaction)
    assert "bob@x.com" in res.text
    # findings should include one with type 'email' (optional check if your FindingType exposes value)
    assert any(f.type.value == "email" for f in res.findings)

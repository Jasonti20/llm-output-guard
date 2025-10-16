from __future__ import annotations
from llm_output_guard.detectors.pii import scan_pii


def _kinds(findings):
    return sorted({f.type.value for f in findings})


def test_email_and_phone_detected():
    s = "Reach me at Foo.Bar+dev@Example.COM or +14155550123"
    pii_findings, _ = scan_pii(s)
    kinds = _kinds(pii_findings)
    assert "email" in kinds
    assert "phone_e164" in kinds


def text_zero_width_mapping_is_correct():
    # zero-width spaces between 't', 'e', 's', 't'
    s = "t\u200be\u200bs\u200bt@example.com"
    f = [x for x in scan_pii(s) if x.type.value == "email"][0]
    # The original slice should equal the original substring (incl. zero-widths)
    assert s[f.start : f.end] == f.snippet
    # If we remove zero-widths from the snippet, we should get the normalized email
    no_zw = f.snippet.replace("\u200b", "")
    assert no_zw == "test@example.com"

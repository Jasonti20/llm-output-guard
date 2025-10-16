from llm_output_guard.core.engine import scan_and_apply, MAX_SCAN_BYTES, MAX_FINDINGS

def test_truncation_flag_set_for_large_payload():
    s = "a" * (MAX_SCAN_BYTES + 10_000)
    res = scan_and_apply(s, "balanced")
    assert res.truncated is True
    assert isinstance(res.scanned_bytes, int) and res.scanned_bytes <= MAX_SCAN_BYTES

def test_findings_are_capped_and_flagged():
    # 300 emails -> exceed default cap 200
    many = " ".join([f"user{i}@x.com" for i in range(300)])
    res = scan_and_apply(many, "balanced")
    assert res.blocked is False
    assert len(res.findings) <= MAX_FINDINGS
    assert res.findings_capped is True
    assert res.findings_count >= len(res.findings)
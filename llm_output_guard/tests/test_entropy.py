from llm_output_guard.detectors.secrets import estimate_entropy

def test_entropy_low_for_english():
    s = "this is a common english sentence with spaces"
    h = estimate_entropy(s, window=20)
    assert h < 3.5

def test_entropy_high_for_random_base64ish():
    s = "Qm9yZWRtQXNraW5nVG9rZW5BMTIzNDU2Nzg5YWJjZGVm"
    h = estimate_entropy(s, window=20)
    assert h >= 3.5

def test_entropy_handles_short_strings():
    assert estimate_entropy("", window=20) == 0.0
    assert estimate_entropy("aaaaaaaaaa", window=20) < 0.1
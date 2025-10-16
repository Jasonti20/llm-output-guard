from llm_output_guard.core.engine import scan_and_apply

def test_detector_budget_sets_timeout(monkeypatch):
    # Monkeypatch a tiny budget by importing and modifying the constant
    import llm_output_guard.core.engine as eng
    old = eng.DETECT_BUDGET_MS
    eng.DETECT_BUDGET_MS = 0.01  # ~10 microseconds, guaranteed to trip
    try:
        s = " ".join([f"user{i}@x.com" for i in range(10_000)])
        res = eng.scan_and_apply(s, "balanced")
        assert res.timed_out is True
    finally:
        eng.DETECT_BUDGET_MS = old

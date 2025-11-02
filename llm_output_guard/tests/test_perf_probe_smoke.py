# tests/test_perf_probe_smoke.py
from llm_output_guard.core.engine import scan_and_apply


def _run_small(kind: str, n: int) -> str:
    if kind == "english":
        s = "Lorem ipsum " * 100
    elif kind == "base64":
        s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" * 10
    else:  # random-ish base64
        s = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 10
    return s[:n]


def test_scan_and_apply_flags_do_not_crash():
    for kind in ("english", "base64", "random"):
        payload = _run_small(kind, 2000)
        res = scan_and_apply(payload, profile="balanced")
        # Should always return a ScanResult with timing and flags
        assert hasattr(res, "detect_time_ms")
        assert hasattr(res, "truncated")
        assert hasattr(res, "findings_capped")
        assert hasattr(res, "timed_out")
        assert isinstance(res.text, str)

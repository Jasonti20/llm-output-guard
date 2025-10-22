from __future__ import annotations
import json
from typing import Any, Tuple, Dict
from .engine import scan_and_apply


class GuardReport:
    __slots__ = (
        "findings_count",
        "blocked",
        "truncated",
        "timed_out",
        "detect_time_ms",
    )

    def __init__(
        self,
        findings_count: int,
        blocked: bool,
        truncated: bool,
        timed_out: bool,
        detect_time_ms: float,
    ):
        self.findings_count = findings_count
        self.blocked = blocked
        self.truncated = truncated
        self.timed_out = timed_out
        self.detect_time_ms = detect_time_ms


def _to_report(result) -> GuardReport:
    # Convert engine’s ScanResult (whatever its exact shape) into a stable Data transfer object.
    return GuardReport(
        findings_count=int(getattr(result, "findings_count", 0) or 0),
        blocked=bool(getattr(result, "blocked", False)),
        truncated=bool(getattr(result, "truncated", False)),
        timed_out=bool(getattr(result, "timed_out", False)),
        detect_time_ms=float(getattr(result, "detect_time_ms", 0.0) or 0.0),
    )


def scan_text_only(text: str, *, profile: str = "balanced") -> GuardReport:
    """
    Step 1: detection-only. Calls engine.scan_and_apply(text) but intentionally ignores
    engine mutations (result.text) and policy enforcement here; middleware just needs counts/flags.
    """
    result = scan_and_apply(text, profile=profile)
    return _to_report(result)


def scan_json_as_text(obj: Any, *, profile: str = "balanced") -> GuardReport:
    """
    Serialize JSON compactly and scan as text for Step 1. This avoids needing JSON-pointer
    logic now; we’ll add JSON-safe patching in Step 2.
    """
    serialized = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return scan_text_only(serialized, profile=profile)


def apply_text(text: str, *, profile: str = "balanced") -> Tuple[str, str, GuardReport]:
    """
    Returns (action, out_text, report) where action in {"block","redact","pass"}.
    Uses engine.scan_and_apply which can redact and/or mark blocked.
    """
    result = scan_and_apply(text, profile=profile)
    action = (
        "block" if result.blocked else ("redact" if (result.text != text) else "pass")
    )
    return action, result.text, _to_report(result)


def apply_json_values(
    obj: Any, *, profile: str = "balanced"
) -> Tuple[str, Any, GuardReport]:
    """
    Traverse obj; for every string value, run scan_and_apply on that string.
    If any child result.blocked, overall action=block.
    Else if any child changed text, overall action=redact.
    Returns (action, new_obj, aggregated_report).
    """
    findings = 0
    blocked_any = False
    redacted_any = False
    truncated_any = False
    timedout_any = False
    detect_ms_total = 0.0

    def walk(x):
        nonlocal findings, blocked_any, redacted_any, truncated_any, timedout_any, detect_ms_total
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v) for v in x]
        if isinstance(x, str):
            res = scan_and_apply(x, profile=profile)
            findings += int(res.findings_count or 0)
            blocked_any = blocked_any or bool(res.blocked)
            truncated_any = truncated_any or bool(res.truncated)
            timedout_any = timedout_any or bool(res.timed_out)
            detect_ms_total += float(res.detect_time_ms or 0.0)
            if res.blocked:
                return x  # value irrelevant; caller will block overall
            if res.text != x:
                redacted_any = True
                return res.text
            return x
        return x  # leave other types unchanged

    new_obj = walk(obj)
    action = "block" if blocked_any else ("redact" if redacted_any else "pass")
    report = GuardReport(
        findings_count=findings,
        blocked=blocked_any,
        truncated=truncated_any,
        timed_out=timedout_any,
        detect_time_ms=detect_ms_total,
    )
    return action, new_obj, report

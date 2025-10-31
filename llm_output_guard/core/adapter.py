from __future__ import annotations
import json
from typing import Any, Tuple, Dict
from .engine import scan_and_apply
from ..policy.loader import load_policy
from ..policy.model import decide
from ..io.findings import serialize_findings_safe


class GuardReport:
    __slots__ = (
        "findings_count",
        "blocked",
        "truncated",
        "timed_out",
        "detect_time_ms",
        "critical",
    )

    def __init__(
        self,
        findings_count: int,
        blocked: bool,
        truncated: bool,
        timed_out: bool,
        detect_time_ms: float,
        critical: bool = False,
    ):
        self.findings_count = findings_count
        self.blocked = blocked
        self.truncated = truncated
        self.timed_out = timed_out
        self.detect_time_ms = detect_time_ms
        self.critical = critical


def _to_report(result) -> GuardReport:
    # Convert engine’s ScanResult (whatever its exact shape) into a stable Data transfer object.
    return GuardReport(
        findings_count=int(getattr(result, "findings_count", 0) or 0),
        blocked=bool(getattr(result, "blocked", False)),
        truncated=bool(getattr(result, "truncated", False)),
        timed_out=bool(getattr(result, "timed_out", False)),
        detect_time_ms=float(getattr(result, "detect_time_ms", 0.0) or 0.0),
        critical=bool(getattr(result, "critical", False)),
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


def apply_text(
    text: str,
    *,
    profile: str = "balanced",
    coerce_block_to_redact: bool = False,
) -> Tuple[str, str, GuardReport]:
    """
    Returns (action, out_text, report) where action in {"block","redact","pass"}.
    If coerce_block_to_redact=True and the engine blocks without redacting,
    we will *actively redact* the blocked spans before returning (streaming safety).
    """
    result = scan_and_apply(text, profile=profile)
    policy = load_policy(profile)
    # Mark "critical" if any finding maps to a rule with severity=critical
    critical_hit = False
    for f in getattr(result, "findings", []) or []:
        rule = decide(policy, f.type.value)
        if rule and str(getattr(rule, "severity", "")).lower() == "critical":
            critical_hit = True
            break
    setattr(result, "critical", critical_hit)

    action = (
        "block" if result.blocked else ("redact" if (result.text != text) else "pass")
    )
    out_text = result.text
    # Streaming safety: never leak when blocked
    if result.blocked and coerce_block_to_redact:

        def _mask_slice(
            seg: str, preserve_len: bool, keep_last_n: int, mask_char: str = "*"
        ) -> str:
            if not preserve_len:
                if keep_last_n <= 0:
                    return mask_char
                return mask_char + seg[-keep_last_n:]
            n = len(seg)
            keep = max(0, min(keep_last_n, n))
            return (mask_char * (n - keep)) + (seg[-keep:] if keep else "")

        edits: list[tuple[int, int, bool, int]] = []

        for f in getattr(result, "findings", []) or []:
            rule = decide(policy, f.type.value)
            if not rule:
                continue
            if rule.action in ("block", "redact"):
                preserve_len = (
                    bool(rule.preserve_len) if rule.preserve_len is not None else False
                )
                keep_last_n = int(rule.keep_last_n or 0)
                edits.append((f.start, f.end, preserve_len, keep_last_n))

        # Apply all masks once, in reverse order
        out = text
        for s, e, preserve_len, keep_last_n in sorted(
            edits, key=lambda t: (t[0], t[1]), reverse=True
        ):
            s = max(0, min(len(out), s))
            e = max(0, min(len(out), e))
            if e > s:
                out = (
                    out[:s]
                    + _mask_slice(out[s:e], preserve_len, keep_last_n, "*")
                    + out[e:]
                )

        out_text = out
        action = "redact"
    return action, out_text, _to_report(result)


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


def summarize_findings(
    text: str,
    result: Any,
    *,
    profile: str = "balanced",
    max_snippet: int = 64,
):
    return serialize_findings_safe(
        text,
        getattr(result, "findings", []) or [],
        profile=profile,
        max_snippet=max_snippet,
    )

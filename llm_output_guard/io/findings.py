# llm_output_guard/io/findings.py
from __future__ import annotations
from typing import Any, Dict, List
from ..policy.loader import load_policy
from ..policy.model import decide

_MASK = "█"


def _mask_slice(seg: str, *, preserve_len: bool, keep_last_n: int) -> str:
    if not seg:
        return ""
    if not preserve_len:
        # single mask + optional last-N tail
        return _MASK + (seg[-keep_last_n:] if keep_last_n > 0 else "")
    n = len(seg)
    keep = max(0, min(keep_last_n, n))
    return (_MASK * (n - keep)) + (seg[-keep:] if keep else "")


def _type_value(ft: Any) -> str:
    # Handles Enum or str
    try:
        v = getattr(ft, "value", None)
        return str(v if v is not None else ft)
    except Exception:
        return str(ft)


def serialize_findings_safe(
    text: str,
    findings: List[Any],
    *,
    profile: str = "balanced",
    max_snippet: int = 64,
) -> List[Dict[str, Any]]:
    """
    Convert engine findings into leak-safe dicts.
    Never echo the original sensitive content.
    Uses policy to decide masking rules (preserve_len, keep_last_n).
    """
    policy = load_policy(profile)
    out: List[Dict[str, Any]] = []
    N = len(text or "")
    for f in findings or []:
        s = int(getattr(f, "start", 0) or 0)
        e = int(getattr(f, "end", 0) or 0)
        s = max(0, min(N, s))
        e = max(0, min(N, e))
        raw = (text or "")[s:e]

        tval = _type_value(getattr(f, "type", "unknown"))
        rule = decide(policy, tval) if tval else None
        preserve_len = bool(getattr(rule, "preserve_len", False)) if rule else False
        keep_last_n = int(getattr(rule, "keep_last_n", 0) or 0) if rule else 0

        masked = _mask_slice(raw, preserve_len=preserve_len, keep_last_n=keep_last_n)
        if len(masked) > max_snippet:
            masked = masked[:max_snippet] + "..."

        out.append(
            {
                "type": tval,
                "span": [s, e],
                "action": getattr(rule, "action", None) if rule else None,
                "severity": (
                    str(getattr(rule, "severity", None)).lower() if rule else None
                ),
                "snippet": masked,
            }
        )
    return out

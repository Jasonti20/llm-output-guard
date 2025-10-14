from __future__ import annotations
from ..policy.loader import load_policy
from ..policy.model import decide
from ..types import ScanResult


def _clamp(a: int, lo: int, hi: int) -> int:
    return lo if a < lo else hi if a > hi else a


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping/adjacent [start,end) spans. Input need not be sorted."""
    if not spans:
        return []
    spans = sorted(((s, e) for s, e in spans if s < e), key=lambda x: (x[0], x[1]))
    merged = []
    cs, ce = spans[0]
    for s, e in spans[1:]:
        if s <= ce:  # overlap or adjacent
            ce = max(ce, e)
        else:
            merged.append((cs, ce))
            cs, ce = s, e
    merged.append((cs, ce))
    return merged


def _mask_slice(s: str, preserve_len: bool, keep_last_n: int, mask_char: str) -> str:
    if not preserve_len:
        # Collapse to a single token while keeping last N if requested
        if keep_last_n <= 0:
            return mask_char
        kept = s[-keep_last_n:]
        return mask_char + kept
    # preserve original length
    n = len(s)
    keep = max(0, min(n, keep_last_n))
    masked_len = n - keep
    return (mask_char * masked_len) + (s[-keep:] if keep else "")


def redact_text(
    orig: str,
    spans: list[tuple[int, int]],
    *,
    preserve_len: bool,
    keep_last_n: int = 0,
    mask_char: str = "*",
) -> str:
    """
    Redact character slices [start,end) in `orig`.
    - Spans are in ORIGINAL indices.
    - Overlaps are merged.
    - Replacements applied right-to-left.
    """
    if not spans:
        return orig

    L = len(orig)
    # Clamp + sanitize
    norm_spans = [(_clamp(s, 0, L), _clamp(e, 0, L)) for s, e in spans if s < e]
    if not norm_spans:
        return orig

    merged = _merge_spans(norm_spans)

    out = orig
    # Apply from rightmost to leftmost so indices remain valid
    for s, e in reversed(merged):
        replacement = _mask_slice(out[s:e], preserve_len, keep_last_n, mask_char)
        out = out[:s] + replacement + out[e:]
    return out


def scan_and_apply(text: str, profile: str = "balanced") -> ScanResult:
    policy = load_policy(profile)
    # Import here to avoid circular imports at module load
    from ..detectors.pii import scan_pii

    policy = load_policy(profile)
    email_rule = policy.rules.get("email")
    email_allow = (email_rule.allowlist if email_rule and email_rule.allowlist else [])
    findings = scan_pii(text, email_allowlist=email_allow)

    # if any finding's rule is "block" -> block
    for f in findings:
        rule = decide(policy, f.type.value)
        if rule and rule.action == "block":
            return ScanResult(text=text, findings=findings, blocked=True)

    # Collect per-finding edits: (start, end, preserve_len, keep_last_n)
    edits: list[tuple[int, int, bool, int]] = []
    for f in findings:
        rule = decide(policy, f.type.value)
        if not rule or rule.action != "redact":
            continue
        preserve_len = (
            bool(rule.preserve_len) if rule.preserve_len is not None else False
        )
        keep_last_n = int(rule.keep_last_n or 0)
        edits.append((f.start, f.end, preserve_len, keep_last_n))

    out = text
    for s, e, preserve_len, keep_last_n in sorted(
        edits, key=lambda t: (t[0], t[1]), reverse=True
    ):
        # Clamp for safety
        s = max(0, min(len(out), s))
        e = max(0, min(len(out), e))
        if e > s:
            repl = _mask_slice(out[s:e], preserve_len, keep_last_n, "*")
            out = out[:s] + repl + out[e:]

    return ScanResult(text=out, findings=findings, blocked=False)

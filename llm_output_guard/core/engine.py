from __future__ import annotations
from ..policy.loader import load_policy
from ..policy.model import decide
from ..types import ScanResult

MAX_SCAN_BYTES = 200_000  # ~200 KB cap for scanning
MAX_FINDINGS = 200  # max findings to return
DETECT_BUDGET_MS = 40.0  # max time to spend in detection (not enforced)


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


def scan_and_apply(text: str, profile: str = "balanced", policy_obj=None) -> ScanResult:
    import time
    from urllib.parse import unquote

    # Import here to avoid circular imports at module load
    from ..detectors.pii import scan_pii
    from ..detectors.secrets import scan_secrets
    from ..detectors.tools import detect_tools

    try:
        # Make prompt detector optional; skip if the module isn’t present yet
        from ..detectors.prompt import detect_prompt_leak
    except Exception:
        detect_prompt_leak = None

    t0 = time.perf_counter()

    deadline = t0 + (DETECT_BUDGET_MS / 1000.0)

    policy = policy_obj if policy_obj is not None else load_policy(profile)
    raw_bytes = text.encode("utf-8", errors="ignore")
    truncated = False
    if len(raw_bytes) > MAX_SCAN_BYTES:
        truncated = True
        raw_bytes = raw_bytes[:MAX_SCAN_BYTES]
        text = raw_bytes.decode("utf-8", errors="ignore")

    norm_text = unquote(text)
    email_rule = policy.rules.get("email")
    email_allow = email_rule.allowlist if email_rule and email_rule.allowlist else []
    pii_findings, pii_timed_out = scan_pii(
        norm_text, email_allowlist=email_allow, deadline=deadline
    )
    sec_findings, sec_timed_out = scan_secrets(norm_text, deadline=deadline)
    # Tools (shell/SQL/etc.) and Prompt-leak (optional)
    tool_findings = detect_tools(norm_text) or []
    prompt_findings = []
    if detect_prompt_leak is not None:
        try:
            prompt_findings = detect_prompt_leak(norm_text) or []
        except Exception:
            prompt_findings = []
    findings = pii_findings + sec_findings + tool_findings + prompt_findings
    total_findings = len(findings)
    findings_capped = False
    if total_findings > MAX_FINDINGS:
        findings = findings[:MAX_FINDINGS]
        findings_capped = True

    timed_out = bool(pii_timed_out or sec_timed_out)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    # if any finding's rule is "block" -> block
    for f in findings:
        rule = decide(policy, f.type.value)
        if rule and rule.action == "block":
            return ScanResult(
                text=text,
                findings=findings,
                blocked=True,
                truncated=truncated,
                scanned_bytes=len(raw_bytes),
                findings_count=total_findings,
                findings_capped=findings_capped,
                timed_out=timed_out,
                detect_time_ms=elapsed_ms,
            )

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

    return ScanResult(
        text=out,
        findings=findings,
        blocked=False,
        truncated=truncated,
        scanned_bytes=len(raw_bytes),
        findings_count=total_findings,
        findings_capped=findings_capped,
        timed_out=timed_out,
        detect_time_ms=elapsed_ms,
    )

from __future__ import annotations
import re
from typing import List
from ..types import Finding, FindingType, Severity, Action
from ..core.normalization import normalize_text, to_original_span

# Pragmatic email pattern that avoids catastrophic backtracking
EMAIL_RE = re.compile(
    r"""(?ix)
    \b
    [A-Z0-9._%+\-]+      # local part
    @
    [A-Z0-9.\-]+         # domain
    \.
    [A-Z]{2,24}          # TLD
    \b
    """
)

# E.164: + followed by 8–15 digits (conservative)
PHONE_E164_RE = re.compile(r"\B\+[0-9]{8,15}\b")


def scan_pii(text: str) -> List[Finding]:
    """
    Normalize the text, run detectors on the normalized string, and
    map spans back to ORIGINAL indices for safe redaction.
    """
    norm, map_norm_to_orig, _ = normalize_text(text)
    out: List[Finding] = []

    # Emails
    for m in EMAIL_RE.finditer(norm):
        ns, ne = m.span()
        os, oe = to_original_span(ns, ne, map_norm_to_orig)
        out.append(
            Finding(
                type=FindingType.EMAIL,
                severity=Severity.MEDIUM,
                start=os,
                end=oe,
                snippet=text[os:oe],
                action_suggested=Action.REDACT,
                norm_span=(ns, ne),
            )
        )

    # Phone numbers
    for m in PHONE_E164_RE.finditer(norm):
        ns, ne = m.span()
        os, oe = to_original_span(ns, ne, map_norm_to_orig)
        out.append(
            Finding(
                type=FindingType.PHONE_E164,
                severity=Severity.MEDIUM,
                start=os,
                end=oe,
                snippet=text[os:oe],
                action_suggested=Action.REDACT,
                norm_span=(ns, ne),
            )
        )
    return out

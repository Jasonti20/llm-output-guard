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
_DIGIT_RE = re.compile(r"\d")
_SSN_DASHED = re.compile(
    r"(?<!\d)(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})(?!\d)",
    flags=re.ASCII,
)
_SSN_NODASH = re.compile(r"(?<!\d)(\d{9})(?!\d)")


def _email_allowed(addr: str, allowlist: List[str]) -> bool:
    a = addr.lower()
    for pat in allowlist:
        p = pat.lower()
        if p.startswith("@") and a.endswith(p):
            return True
    return False


def scan_pii(text: str, *, email_allowlist: list[str] | None = None) -> List[Finding]:
    """
    Normalize the text, run detectors on the normalized string, and
    map spans back to ORIGINAL indices for safe redaction.
    """
    norm, map_norm_to_orig, _ = normalize_text(text)
    out: List[Finding] = []
    email_allowlist = email_allowlist or []

    # Emails
    for m in EMAIL_RE.finditer(norm):
        ns, ne = m.span()
        os, oe = to_original_span(ns, ne, map_norm_to_orig)
        candidate = text[os:oe]
        if _email_allowed(candidate, email_allowlist):
            continue
        out.append(
            Finding(
                type=FindingType.EMAIL,
                severity=Severity.MEDIUM,
                start=os,
                end=oe,
                snippet=candidate,
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

    # SSN (dashed & no-dash) — detect on NORMALIZED or ORIGINAL?
    # We detect on ORIGINAL here since the SSN regex is ASCII-stable.
    for s, e, _raw in find_ssn_spans(text):
        out.append(
            Finding(
                type=FindingType.SSN,
                severity=Severity.HIGH,
                start=s,
                end=e,
                snippet=text[s:e],
                action_suggested=None,
                norm_span=None,
            )
        )
    return out


def _only_digits(s: str) -> str:
    return "".join(ch for ch in s if "0" <= ch <= "9")


# luhn algorithm start from right to left double every second digit
def luhn_ok(numbers: str) -> bool:
    digits = _only_digits(numbers)
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    alt = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return (total % 10) == 0


def _ssn_parts_ok(area: str, group: str, serial: str) -> bool:
    if area == "000" or area == "666" or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def find_ssn_spans(text: str) -> List[tuple[int, int, str]]:
    spans = []
    for m in _SSN_DASHED.finditer(text):
        area, group, serial = m.group(1), m.group(2), m.group(3)
        if _ssn_parts_ok(area, group, serial):
            spans.append((m.start(), m.end(), f"{area}-{group}-{serial}"))

    for m in _SSN_NODASH.finditer(text):
        raw = m.group(1)
        area, group, serial = raw[:3], raw[3:5], raw[5:]
        if _ssn_parts_ok(area, group, serial):
            spans.append((m.start(), m.end(), raw))
    return spans

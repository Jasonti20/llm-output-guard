# llm_output_guard/detectors/secrets.py
from __future__ import annotations
from math import log2
from typing import Iterable, List, Tuple
import re
from ..types import Finding, FindingType, Severity, Action
from ..core.normalization import normalize_text, to_original_span
import time


def _shannon_entropy(chars: Iterable[str]) -> float:
    """Shannon entropy H(X) in bits/char for a multiset of characters."""
    freq: dict[str, int] = {}
    total = 0
    for c in chars:
        freq[c] = freq.get(c, 0) + 1
        total += 1
    if total == 0:
        return 0.0
    h = 0.0
    for n in freq.values():
        p = n / total
        h -= p * log2(p)
    return h


def estimate_entropy(s: str, window: int = 20) -> float:
    """
    Sliding-window mean entropy (bits/char).
    If len(s) <= window, compute on the whole string.
    """
    n = len(s)
    if n == 0:
        return 0.0
    if n <= window:
        return _shannon_entropy(s)
    ent_sum = 0.0
    count = 0
    for i in range(0, n - window + 1):
        ent_sum += _shannon_entropy(s[i : i + window])
        count += 1
    return ent_sum / count


# ---------- Prefix detectors (HIGH confidence) ----------
# Keep patterns simple/anchored to avoid backtracking
AKIA_RE = re.compile(
    r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16,20}(?![A-Za-z0-9])", re.ASCII | re.IGNORECASE
)
# OpenAI-style: accept sk-<env>-<token> and sk-<token>
# Examples: sk-live-..., sk-test-..., sk-XXXXXXXXXXXXXXXXXXXXXXXX
OPENAI_RE = re.compile(
    r"(?<![A-Za-z0-9])sk-(?:[A-Za-z]{2,10}-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])",
    re.ASCII | re.IGNORECASE,
)
GITHUB_RE = re.compile(
    r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,}(?![A-Za-z0-9])", re.ASCII | re.IGNORECASE
)
SLACK_RE = re.compile(
    r"(?<![A-Za-z0-9])xoxb-[A-Za-z0-9-]{20,}(?![A-Za-z0-9])", re.ASCII | re.IGNORECASE
)

# --- AWS Secret Access Key (common “Secret=...” form in copy-pastes)
# We keep it simple: grab reasonably long base64/hex-ish secrets after "Secret="
AWS_SECRET_VALUE_RE = re.compile(r"(?i)\bSecret\s*=\s*([A-Za-z0-9+/=]{30,})")

PREFIX_RES = [
    ("secret_prefix", AKIA_RE),
    ("secret_prefix", OPENAI_RE),
    ("secret_prefix", GITHUB_RE),
    ("secret_prefix", SLACK_RE),
    ("secret_prefix", AWS_SECRET_VALUE_RE),
]

# ---------- JWT detector (HIGH confidence) ----------
# base64url segment: letters, digits, '-', '_'
_B64U = r"[A-Za-z0-9_-]+"  # keep JWT case-sensitive
JWT_RE = re.compile(
    rf"(?<![A-Za-z0-9_-])({_B64U})\.({_B64U})\.({_B64U})(?![A-Za-z0-9_-])", re.ASCII
)

PEM_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |PRIVATE |ENCRYPTED )?PRIVATE KEY-----",
    re.ASCII | re.IGNORECASE,
)
# Header-only detector for streaming: triggers on BEGIN line alone (no END required)
PEM_BEGIN_RE = re.compile(
    r"-----BEGIN\s+(?:(?:RSA|EC|OPENSSH|PRIVATE|ENCRYPTED)\s+)?PRIVATE\s+KEY-----"
)


def scan_secrets(
    text: str, *, deadline: float | None = None
) -> Tuple[List[Finding], bool]:
    """
    Detect secrets on normalized text; map spans back to original indices.
    Returns Findings for: secret_prefix, jwt_token, pem_key.
    """
    findings: List[Finding] = []
    timed_out = False
    norm, map_norm_to_orig, _ = normalize_text(text)

    def _over_budget() -> bool:
        return deadline is not None and time.perf_counter() > deadline

    def _emit(ftype: FindingType, ns: int, ne: int):
        os, oe = to_original_span(ns, ne, map_norm_to_orig)
        findings.append(
            Finding(
                type=ftype,
                severity=Severity.HIGH,
                start=os,
                end=oe,
                snippet=text[os:oe],
                action_suggested=Action.BLOCK,
                norm_span=(ns, ne),
            )
        )

    # Prefix-based secrets
    for kind, rx in PREFIX_RES:
        if _over_budget():
            timed_out = True
            break
        for m in rx.finditer(norm):
            if _over_budget():
                timed_out = True
                break
            _emit(FindingType.SECRET_PREFIX, *m.span())
        if timed_out:
            break

    # AWS Secret=... value (treat as secret_prefix category for policy)
    if not timed_out:
        for m in AWS_SECRET_VALUE_RE.finditer(norm):
            if _over_budget():
                timed_out = True
                break
            _emit(FindingType.SECRET_PREFIX, *m.span())

    # JWT tokens
    if not timed_out:
        for m in JWT_RE.finditer(norm):
            if _over_budget():
                timed_out = True
                break
            _emit(FindingType.JWT_TOKEN, *m.span())

    # PEM keys (treat as CRITICAL)
    if not timed_out:
        for m in PEM_RE.finditer(norm):
            if _over_budget():
                timed_out = True
                break
            ns, ne = m.span()
            os, oe = to_original_span(ns, ne, map_norm_to_orig)
            findings.append(
                Finding(
                    type=FindingType.PEM_KEY,
                    severity=Severity.CRITICAL,
                    start=os,
                    end=oe,
                    snippet=text[os:oe],
                    action_suggested=Action.BLOCK,
                    norm_span=(ns, ne),
                )
            )
    # PEM header-only (streaming, partial block): fail-closed as CRITICAL immediately
    if not timed_out:
        for m in PEM_BEGIN_RE.finditer(norm):
            if _over_budget():
                timed_out = True
                break
            ns, ne = m.span()
            os, oe = to_original_span(ns, ne, map_norm_to_orig)
            findings.append(
                Finding(
                    type=FindingType.PEM_KEY,
                    severity=Severity.CRITICAL,
                    start=os,
                    end=oe,
                    snippet=text[os:oe],
                    action_suggested=Action.BLOCK,
                    norm_span=(ns, ne),
                )
            )

    return findings, timed_out

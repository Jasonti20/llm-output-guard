from __future__ import annotations
import re
import base64
import binascii
import urllib.parse
from typing import List
from llm_output_guard.types import Finding, FindingType, Severity

# Notes:
# - Patterns focus on *execution intent*: code fences, subshells, pipelines to sh, etc.
# - Keep patterns precompiled and relatively safe; avoid catastrophic backtracking.

# ---- Module knobs (defensive caps) ----
MAX_FINDINGS_TOOLS = 100  # hard cap to avoid noise/DoS
MAX_DECODE_BYTES = 4096  # skip huge decodes
B64_MIN_LEN = 24  # ignore tiny base64-ish blobs

# --- Shell indicators (UNIX-like) ---
SHELL_CODE_FENCE = re.compile(r"(?ms)```(?:bash|sh|zsh)\s+(.+?)```")

BACKTICKS_INLINE = re.compile(r"(?s)`([^`]+)`")

SUBSHELL = re.compile(r"\$\([^)]+?\)")  # $( ... )

BACKTICK_SUBSHELL = re.compile(r"`[^`]+?`")  # legacy backtick subshell

PIPE_TO_SHELL = re.compile(
    r"(curl|wget)\b[^|]{0,200}\|\s*(sh|bash)\b", flags=re.IGNORECASE
)

RM_RF = re.compile(r"\brm\s+-rf?\s+/(?:\s|$)", flags=re.IGNORECASE)

DANGEROUS_CHOWN_CHMOD = re.compile(
    r"\b(chmod\s+777|chown\s+root:root)\b", flags=re.IGNORECASE
)

SYSTEM_CALLS = re.compile(
    r"\b(os\.system|subprocess\.(run|Popen|call)|exec\()", flags=re.IGNORECASE
)

# Command separators & chaining that often imply execution
SHELL_CHAIN = re.compile(
    r"(;|\|\||&&)\s*(rm\b|curl\b|wget\b|python\b|bash\b|sh\b)", flags=re.IGNORECASE
)

# --- SQL indicators ---
SQL_DROP_TABLE = re.compile(r"\bDROP\s+TABLE\b", flags=re.IGNORECASE)

SQL_XP_CMDSHELL = re.compile(r"\bxp_cmdshell\b", flags=re.IGNORECASE)

# --- Windows / PowerShell indicators ---
POWERSHELL_INVOKE = re.compile(
    r"\bInvoke-Expression\b|\bIEX\b|\bInvoke-WebRequest\b|\bNew-Object\s+Net\.WebClient\b",
    flags=re.IGNORECASE,
)
# --- Markdown links / URLs / Encoded payloads ---
MD_LINK = re.compile(r"\[([^\]]{1,200})\]\(([^)\s]{1,1000})\)", re.IGNORECASE)
BARE_URL = re.compile(r"https?://[^\s)>'\"`]{4,}", re.IGNORECASE)
URL_RISK_HINT = re.compile(
    r"(evil\.example\.com|cmd=|rm%20\-rf|/exfil|/run\?|/install|/payload)",
    re.IGNORECASE,
)
SUSPICIOUS_HOST = re.compile(
    r"(evil\.example\.com|pastebin\.com|raw\.githubusercontent\.com)",
    re.IGNORECASE,
)
BASE64_LIKE = re.compile(r"\b[A-Za-z0-9+/_-]{24,}={0,2}\b")
POWERSHELL_ENC = re.compile(
    r"\bpowershell(?:\.exe)?\s+(-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)


def _emit(
    matches, *, ftype: FindingType, severity: Severity, text: str
) -> List[Finding]:
    out: List[Finding] = []
    for m in matches:
        s, e = m.span()
        out.append(
            Finding(
                type=ftype,
                severity=severity,
                start=s,
                end=e,
                snippet=text[s:e][:160],
            )
        )
    return out


def _emit_unique(existing: List[Finding], new_items: list[Finding]) -> list[Finding]:
    """Merge, de-duplicating by (type,start,end)."""
    seen = {(f.type, f.start, f.end) for f in existing}
    out = existing[:]
    for f in new_items:
        if (f.type, f.start, f.end) in seen:
            continue
        out.append(f)
        seen.add((f.type, f.start, f.end))
        if len(out) >= MAX_FINDINGS_TOOLS:
            break
    return out


def _safe_b64_decode(s: str) -> str | None:
    try:
        if len(s) > MAX_DECODE_BYTES:
            return None
        s_norm = s.replace("-", "+").replace("_", "/")
        pad = (-len(s_norm)) % 4
        if pad:
            s_norm += "=" * pad
        data = base64.b64decode(s_norm, validate=False)
        if not data or len(data) > MAX_DECODE_BYTES:
            return None
        try:
            return data.decode("utf-8", "ignore")
        except Exception:
            return data.decode("latin-1", "ignore")
    except (binascii.Error, ValueError):
        return None


def _scan_decoded_shell(decoded: str) -> bool:
    """Reuse primary shell heuristics on decoded text."""
    if PIPE_TO_SHELL.search(decoded):
        return True
    if RM_RF.search(decoded):
        return True
    if SYSTEM_CALLS.search(decoded):
        return True
    if SHELL_CHAIN.search(decoded):
        return True
    if POWERSHELL_INVOKE.search(decoded):
        return True
    return False


def detect_tools(text: str) -> List[Finding]:
    findings: List[Finding] = []
    shell = FindingType.TOOL_SHELL

    # Shell family
    findings += _emit(
        SHELL_CODE_FENCE.finditer(text), ftype=shell, severity=Severity.HIGH, text=text
    )
    findings += _emit(
        BACKTICKS_INLINE.finditer(text),
        ftype=shell,
        severity=Severity.MEDIUM,
        text=text,
    )
    findings += _emit(
        SUBSHELL.finditer(text), ftype=shell, severity=Severity.HIGH, text=text
    )
    findings += _emit(
        BACKTICK_SUBSHELL.finditer(text), ftype=shell, severity=Severity.HIGH, text=text
    )
    findings += _emit(
        PIPE_TO_SHELL.finditer(text), ftype=shell, severity=Severity.CRITICAL, text=text
    )
    findings += _emit(
        RM_RF.finditer(text), ftype=shell, severity=Severity.CRITICAL, text=text
    )
    findings += _emit(
        DANGEROUS_CHOWN_CHMOD.finditer(text),
        ftype=shell,
        severity=Severity.HIGH,
        text=text,
    )
    findings += _emit(
        SYSTEM_CALLS.finditer(text), ftype=shell, severity=Severity.HIGH, text=text
    )
    findings += _emit(
        SHELL_CHAIN.finditer(text), ftype=shell, severity=Severity.MEDIUM, text=text
    )

    # SQL family (destructive)
    findings += _emit(
        SQL_DROP_TABLE.finditer(text),
        ftype=FindingType.TOOL_SQL_DROP,
        severity=Severity.HIGH,
        text=text,
    )
    findings += _emit(
        SQL_XP_CMDSHELL.finditer(text),
        ftype=FindingType.TOOL_SQL_DROP,
        severity=Severity.CRITICAL,
        text=text,
    )

    # PowerShell download/execute — bucket under shell for now
    findings += _emit(
        POWERSHELL_INVOKE.finditer(text), ftype=shell, severity=Severity.HIGH, text=text
    )
    # --- Markdown link deception / risky URLs ---
    for m in MD_LINK.finditer(text):
        url = m.group(2)
        if URL_RISK_HINT.search(url) or SUSPICIOUS_HOST.search(url):
            findings = _emit_unique(
                findings, _emit([m], ftype=shell, severity=Severity.HIGH, text=text)
            )
            if len(findings) >= MAX_FINDINGS_TOOLS:
                return findings

    for m in BARE_URL.finditer(text):
        url = m.group(0)
        if URL_RISK_HINT.search(url) or SUSPICIOUS_HOST.search(url):
            findings = _emit_unique(
                findings, _emit([m], ftype=shell, severity=Severity.MEDIUM, text=text)
            )
            if len(findings) >= MAX_FINDINGS_TOOLS:
                return findings
    # --- URL-encoded payloads (curl%20http... or cmd=rm%20-rf) ---
    for m in BARE_URL.finditer(text):
        raw = m.group(0)
        try:
            decoded = urllib.parse.unquote(raw)
        except Exception:
            decoded = ""
        if decoded and decoded != raw and _scan_decoded_shell(decoded):
            findings = _emit_unique(
                findings, _emit([m], ftype=shell, severity=Severity.HIGH, text=text)
            )
            if len(findings) >= MAX_FINDINGS_TOOLS:
                return findings

    # --- Base64 / PowerShell -enc blobs that decode to shell-y content ---
    for m in BASE64_LIKE.finditer(text):
        b = m.group(0)
        if len(b) < B64_MIN_LEN:
            continue
        decoded = _safe_b64_decode(b)
        if decoded and _scan_decoded_shell(decoded):
            findings = _emit_unique(
                findings, _emit([m], ftype=shell, severity=Severity.HIGH, text=text)
            )
            if len(findings) >= MAX_FINDINGS_TOOLS:
                return findings

    for m in POWERSHELL_ENC.finditer(text):
        b = m.group(2)
        decoded = _safe_b64_decode(b) or ""
        sev = Severity.CRITICAL if _scan_decoded_shell(decoded) else Severity.HIGH
        findings = _emit_unique(
            findings, _emit([m], ftype=shell, severity=sev, text=text)
        )
        if len(findings) >= MAX_FINDINGS_TOOLS:
            return findings

    return findings

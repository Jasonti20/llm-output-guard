from __future__ import annotations
import re
from typing import List
from llm_output_guard.types import Finding, FindingType, Severity

# Notes:
# - Patterns focus on *execution intent*: code fences, subshells, pipelines to sh, etc.
# - Keep patterns precompiled and relatively safe; avoid catastrophic backtracking.

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

    return findings

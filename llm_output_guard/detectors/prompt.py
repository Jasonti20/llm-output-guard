# llm_output_guard/detectors/prompt.py
from __future__ import annotations
import re
from typing import List
from llm_output_guard.types import Finding, FindingType, Severity

# A few high-signal phrases in English + Chinese.
# Keep it conservative to avoid noise; you can expand later.
PROMPT_LEAK_REGEX = re.compile(
    r"""
    (system\s+prompt)|
    (reveal\s+(your|the)\s+(instructions|prompt))|
    (ignore\s+all\s+(rules|instructions))|
    (developer\s+message)|
    (hidden\s+(config|instructions))|
    (打印你的系统提示词)|
    (忽略所有规则)
    """,
    re.IGNORECASE | re.VERBOSE,
)


def detect_prompt_leak(text: str) -> List[Finding]:
    m = PROMPT_LEAK_REGEX.search(text)
    if not m:
        return []
    s, e = m.span()
    return [
        Finding(
            type=FindingType.PROMPT_LEAK,
            severity=Severity.HIGH,
            start=s,
            end=e,
            snippet=text[s:e][:160],
        )
    ]

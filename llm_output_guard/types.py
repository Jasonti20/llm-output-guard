from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class FindingType(str, Enum):
    EMAIL = "email"
    PHONE_E164 = "phone_e164"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    SECRET_PREFIX = "secret.known_prefix"
    SECRET_ENTROPY = "secret.high_entropy"
    JWT = "secret.jwt"
    PEM = "secret.pem"
    TOOL_SHELL = "tools.shell"
    TOOL_SQL_DROP = "tools.sql_drop"
    PROMPT_LEAK = "prompt.leak_prompt"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    NONE = "none"
    FLAG = "flag"
    REDACT = "redact"
    BLOCK = "block"
    QUARANTINE = "quarantine"


@dataclass
class Finding:
    type: FindingType
    severity: Severity
    start: int
    end: int
    snippet: str
    action_suggested: Action = Action.NONE
    norm_span: Optional[Tuple[int, int]] = None


@dataclass
class ScanResult:
    text: str
    findings: list[Finding]
    blocked: bool

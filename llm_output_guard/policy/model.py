from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class Rule:
    action: str  # "block" | "redact" | "flag" | "quarantine"
    severity: str  # "low" | "medium" | "high" | "critical"
    preserve_len: bool = False  # mask keeps same length as original
    keep_last_n: int = 0  # show last N chars (e.g., last 4 of card)
    allowlist: Optional[list[str]] = None  # for types that support allowlist


@dataclass(frozen=True)
class Policy:
    profile: str
    rules: Dict[str, Rule]  # keyed by finding type, e.g. "credit_card", "ssn"


def decide(policy: Policy, finding_type: str) -> Optional[Rule]:
    return policy.rules.get(finding_type)

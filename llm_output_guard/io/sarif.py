from __future__ import annotations
import json
from typing import List, Dict, Optional

SARIF_VERSION = "2.1.0"


# Map guard actions/severities → SARIF level
# Prefer action when present; fall back to severity.
def _to_level(action: str | None, severity: str | None) -> str:
    a = (action or "").lower()
    s = (severity or "").lower()
    if a == "block":
        return "error"
    if a == "redact":
        return "warning"
    # flags and everything else → note, unless severity is critical/high
    if s in ("critical", "high"):
        return "warning"
    return "note"


def _rule_id(t: str) -> str:
    # e.g., "credit_card" → "LLMOG.credit_card"
    return f"LLMOG.{t}"


def _make_rules(findings_rows: List[Dict]) -> List[Dict]:
    # One rule per finding type
    seen = {}
    rules = []
    for r in findings_rows:
        t = r.get("type", "unknown")
        if t in seen:
            continue
        seen[t] = True
        rules.append(
            {
                "id": _rule_id(t),
                "name": t,
                "shortDescription": {"text": f"Guard rule for {t}"},
                "fullDescription": {
                    "text": f"Finds and mitigates '{t}' in model outputs."
                },
                "help": {"text": "See README for policy and mitigation details."},
                "defaultConfiguration": {
                    "level": _to_level(r.get("action"), r.get("severity"))
                },
            }
        )
    return rules


def _region_for(r: Dict) -> Dict:
    # Prefer character offsets if available; fall back to snippet-only.
    start = r.get("start")
    end = r.get("end")
    snippet = r.get("snippet", "")
    if isinstance(start, int) and isinstance(end, int) and end > start:
        return {
            "charOffset": start,
            "charLength": end - start,
            "snippet": {"test": snippet[:200]} if snippet else None,
        }
    # No offsets → still provide a snippet for context
    return {
        "startLine": 1,
        "snippet": {"text": snippet[:200]} if snippet else None,
    }


def rows_to_sarif(
    findings_rows: List[Dict],
    *,
    artifact_uri: Optional[str] = None,
    tool_name: str = "LLM Output Guard",
    tool_version: str = "0.1.0",
    policy_profile: str = "balanced",
) -> Dict:
    results = []
    for r in findings_rows:
        t = r.get("type", "unkown")
        msg = r.get("message") or f"{t} detected (action={r.get('action')})"
        res = {
            "ruleId": _rule_id(t),
            "level": _to_level(r.get("action"), r.get("severity")),
            "message": {"text": msg},
            "properties": {
                "action": r.get("action"),
                "severity": r.get("severity"),
                "where": r.get("where"),
                "profile": policy_profile,
            },
        }
        if artifact_uri:
            res["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}
            ]
        elif r.get("snippet"):
            # Provide location-less, but keep snippet in properties
            res.setdefault("propertues", {})["snippet"] = r["snippet"][:200]
        results.append(res)

    sarif = {
        "version": SARIF_VERSION,
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "semanticVersion": tool_version,
                        "informationUri": "https://github.com/your-org/llm-output-guard",
                        "rules": _make_rules(findings_rows),
                    }
                },
                "automationDetails": {"id": f"profile:{policy_profile}"},
                "results": results,
            }
        ],
    }
    return sarif


def dumps_sarif(*args, **kwargs) -> str:
    return json.dumps(rows_to_sarif(*args, **kwargs), ensure_ascii=False, indent=2)

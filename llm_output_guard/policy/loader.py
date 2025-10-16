import yaml
from .model import Policy, Rule

_DEFAULT_YAML = """
profiles:
  balanced:
    credit_card: { action: block, severity: high, preserve_len: true, keep_last_n: 4 }
    ssn:         { action: block, severity: high, preserve_len: true, keep_last_n: 0 }
    email:
      action: redact
      severity: medium
      allowlist:
        - "@example.com"          # any user at example.com
        - "noreply@yourco.com"    # exact match
    phone_e164:  { action: redact, severity: medium, preserve_len: false, keep_last_n: 2 }
    
    #Secrets (flat keys must match FindingType values)
    secret_prefix: { action: block, severity: high }
    jwt_token:     { action: block, severity: high }
    pem_key:       { action: block, severity: critical }
  strict:
    credit_card: { action: block, severity: high, preserve_len: true, keep_last_n: 4 }
    ssn:         { action: block, severity: high, preserve_len: true }
    email:       { action: block, severity: medium }
    phone_e164:  { action: redact, severity: medium }
    secret_prefix: { action: block, severity: high }
    jwt_token:     { action: block, severity: high }
    pem_key:       { action: block, severity: critical }
  permissive:
    credit_card: { action: block, severity: high, preserve_len: true, keep_last_n: 4 }
    ssn:         { action: block, severity: high, preserve_len: true }
    email:       { action: flag,  severity: low }
    phone_e164:  { action: flag,  severity: low }
    secret_prefix: { action: block, severity: high }
    jwt_token:     { action: block, severity: high }
    pem_key:       { action: block, severity: critical }
"""


def _parse_profile(data: dict, profile: str) -> Policy:
    profiles = data.get("profiles") or {}
    raw = profiles.get(profile)
    if not raw:
        raw = profiles.get("balanced") or {}

    rules = {}
    for k, v in raw.items():
        if not isinstance(v, dict) or "action" not in v or "severity" not in v:
            continue
        rules[k] = Rule(
            action=str(v["action"]),
            severity=str(v["severity"]),
            preserve_len=bool(v.get("preserve_len", False)),
            keep_last_n=int(v.get("keep_last_n", 0)),
            allowlist=list(v.get("allowlist", [])),
        )
    return Policy(profile=profile, rules=rules)


def load_policy(profile: str = "balanced", yaml_text: str | None = None) -> Policy:
    text = yaml_text if yaml_text is not None else _DEFAULT_YAML
    data = yaml.safe_load(text) or {}
    return _parse_profile(data, profile)

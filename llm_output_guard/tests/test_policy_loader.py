from llm_output_guard.policy.loader import load_policy
from llm_output_guard.policy.model import decide

def test_load_balanced_rules_present():
    p = load_policy("balanced")
    cc = decide(p, "credit_card")
    ssn = decide(p, "ssn")
    assert cc and cc.action == "block" and cc.keep_last_n == 4 and cc.preserve_len
    assert ssn and ssn.action == "block" and ssn.preserve_len

def test_fallback_to_balanced():
    p = load_policy("nonexistent_profile_name")
    assert decide(p, "credit_card") is not None

def test_permissive_email_flag():
    p = load_policy("permissive")
    email = decide(p, "email")
    assert email and email.action == "flag"
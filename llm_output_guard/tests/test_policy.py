from llm_output_guard.policy.loader import load_policy
from llm_output_guard.policy.model import decide


def test_balanced_rules():
    p = load_policy("balanced")
    assert decide(p, "email").action == "redact"
    assert decide(p, "credit_card").action == "block"
    assert decide(p, "tools.shell").action == "block"
    assert decide(p, "pem_key").severity == "critical"


def test_profiles_differ():
    strict = load_policy("strict")
    perm = load_policy("permissive")

    assert decide(strict, "email").action == "block"
    assert decide(perm, "email").action == "flag"

    assert decide(strict, "tools.shell").action == "block"
    assert decide(perm, "tools.shell").action == "flag"

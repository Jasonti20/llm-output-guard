from __future__ import annotations
import json, pathlib, sys
from llm_output_guard.core.engine import scan_and_apply
from llm_output_guard.io.findings import serialize_findings_safe

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = [
    ("case1_credit_card", "balanced"),
    ("case2_pem_key", "balanced"),
    ("case3_email_phone", "balanced"),
]


def run_case(case_dir: pathlib.Path, profile: str):
    inp = (case_dir / "input.txt").read_text(encoding="utf-8")
    res = scan_and_apply(inp, profile=profile)

    # Guarded text
    (case_dir / "garded.txt").write_text(res.text, encoding="utf-8")

    # Summary JSON (action + findings rows)
    action = "block" if res.blocked else ("redact" if res.text != inp else "none")
    rows = serialize_findings_safe(
        inp, getattr(res, "findings", []) or [], profile=profile, max_snippet=160
    )

    summary = {
        "action": action,
        "findings": getattr(res, "findings_count", len(rows)),
        "truncated": getattr(res, "truncated", False),
        "timed_out": getattr(res, "timed_out", False),
        "detect_ms": getattr(res, "detect_time_ms", 0.0),
        "rows": rows,
    }
    (case_dir / "guarded_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def main():
    base = ROOT / "examples" / "traces_before_after"
    for name, profile in CASES:
        run_case(base / name, profile)
    print("Traces generated under examples/traces_before_after/")


if __name__ == "__main__":
    sys.exit(main())

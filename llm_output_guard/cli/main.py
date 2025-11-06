from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Literal, Optional, List

# Internal imports
from llm_output_guard.core.engine import scan_and_apply
from llm_output_guard.policy.loader import load_policy, load_policy_from_file
from llm_output_guard.io.findings import serialize_findings_safe
from llm_output_guard.io.sarif import rows_to_sarif

Fmt = Literal["json", "pretty", "sarif"]
_ACTION_RANK = {"none": 0, "flag": 1, "redact": 2, "block": 3, "quarantine": 3}


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Input path not found or not a file: {path}")
    return p.read_text(encoding="utf-8", errors="ignore")


def _exit_code(action: str) -> int:
    return _ACTION_RANK.get(action, 3)


def _pretty(findings_rows: List[dict], summary_line: str) -> str:
    if not findings_rows:
        return summary_line
    lines = [summary_line, "-" * 80]
    for i, f in enumerate(findings_rows, 1):
        t = f.get("type", "unknown")
        sev = f.get("severity", "unknown")
        act = f.get("action", "flag")
        where = f.get("where", "text")
        snip = f.get("snippet", "")
        if len(snip) > 220:
            snip = snip[:217] + "..."
        lines.append(f"[{i}] type={t} severity={sev} action={act} where={where}")
        if snip:
            lines.append(f"     snippet: {snip}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="guard",
        description="LLM Output Guard — offline scanner for text/JSON files or stdin.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="Scan text from a file or stdin.")
    scan.add_argument(
        "--in", dest="in_path", required=True, help="Path to file or '-' for stdin."
    )
    scan.add_argument(
        "--format",
        dest="fmt",
        choices=["json", "pretty", "sarif"],
        default="pretty",
        help="Output format.",
    )
    scan.add_argument(
        "--profile",
        default="balanced",
        help="Policy profile (balanced|strict|permissive).",
    )
    scan.add_argument(
        "--policy",
        dest="policy_file",
        default=None,
        help="Optional policy YAML path (overrides profile).",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "scan":
        try:
            text = _read_input(args.in_path)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 3

        # Load policy (file overrides profile)
        try:
            policy = (
                load_policy_from_file(args.policy_file, profile=args.profile)
                if args.policy_file
                else load_policy(profile=args.profile)
            )
        except Exception as e:
            print(f"ERROR loading policy: {e}", file=sys.stderr)
            return 3

        # Engine run (need .findings for rendering)
        res = scan_and_apply(text, profile=args.profile, policy_obj=policy)

        # Overall action: block > redact > none
        action = (
            "block" if res.blocked else ("redact" if (res.text != text) else "none")
        )

        rows = serialize_findings_safe(
            text,
            getattr(res, "findings", []) or [],
            profile=args.profile,
            max_snippet=200,
        )
        summary = (
            f"action={action} findings={getattr(res,'findings_count', len(rows))} "
            f"truncated={getattr(res,'truncated', False)} timed_out={getattr(res,'timed_out', False)} "
            f"detect_ms={round(getattr(res,'detect_time_ms', 0.0), 2)}"
        )

        if args.fmt == "json":
            payload = {
                "summary": {
                    "action": action,
                    "findings": getattr(res, "findings_count", len(rows)),
                    "truncated": getattr(res, "truncated", False),
                    "timed_out": getattr(res, "timed_out", False),
                    "detect_ms": getattr(res, "detect_time_ms", 0.0),
                },
                "findings": rows,
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        elif args.fmt == "sarif":
            sarif = rows_to_sarif(
                rows,
                artifact_uri=(args.in_path if args.in_path != "-" else "STDIN"),
                policy_profile=args.profile,
            )
            print(json.dumps(sarif, ensure_ascii=False, indent=2))
        else:
            print(_pretty(rows, summary))

        return _exit_code(action)
    return 3


if __name__ == "__main__":
    sys.exit(main())

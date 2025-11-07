# llm-output-guard
Starlette middleware + CLI to scan/block/redact risky LLM outputs (PII, secrets, unsafe tool calls). Ships with a balanced policy, SARIF output, a pre-commit hook, and reproducible before/after traces.

## Features
- **Starlette middleware**: scans `text/*` and `application/json` responses.
- **Streaming support**: incremental scanning/redaction (SSE/text).
- **Detectors**: credit cards (Luhn), SSN, emails/phones, JWT/PEM/known prefixes, basic risky shell/SQL patterns.
- **Policies**: `balanced` (default), `strict`, `permissive`.
- **CLI**: offline scanner with `pretty | json | sarif`.
- **Dev tooling**: pre-commit hook; SARIF for code-scanning UIs.
- **Traces**: reproducible before/after examples.

## Install (dev)
```bash
pip install -e .

### Red-Team dataset
See `examples/redteam.jsonl` for 10 prompts (jailbreak, secrets, command suggestions, encodings).  
Used by the Step 11 red-team runner to compare guard **OFF vs ON**.

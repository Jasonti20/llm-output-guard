# Threat Model — LLM Output Guard (v0.1, Oct 12, 2025)

## What we protect (scope: **model outputs**)
- **Sensitive data** in outputs: emails, phone numbers, credit cards, SSNs.
- **Secrets**: API keys, tokens, JWTs, private keys.
- **Risky instructions**: commands or SQL likely to harm systems if auto-executed.

## Who might cause problems
- **Curious/malicious users** prompting the model to leak or suggest harmful actions.
- **Poisoned or careless data sources** (RAG docs that contain secrets/PII).
- **Model hallucinations** that fabricate dangerous commands or sensitive values.

## Where things go wrong (surfaces)
- HTTP responses (text/JSON) from server to client.
- **Streaming** responses (partial leaks over time).
- Logs and traces (if raw outputs are logged).

## Assumptions (today’s stage)
- We run detectors on **normalized** text (NFKC, zero-width removed).
- We **map spans back** to the original text for precise redaction.
- Today’s detectors: **email + E.164 phone** (credit cards, SSN, secrets in upcoming steps).
- Middleware placeholder exists; full block/redact/flag logic arrives by M1.

## Out of scope (for now)
- Inbound prompt/filtering (this project is focused on **outputs**).
- Full RFC email coverage and all Intl phone formats (we use pragmatic patterns).
- Authentication/authorization for your app (handled by the app itself).

## Risks we accept short-term
- Some false negatives for rare encodings or edge RFC cases.
- Conservative phone rule (E.164) may miss local formats by design.
- No policy engine yet; detectors return suggested actions only.

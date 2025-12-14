#!/usr/bin/env python3
"""
RAG Faithfulness Evaluator (Step 12)

Computes 3-gram containment and sentence-level support metrics
for RAG answers vs. their source passages.

Usage:
    python scripts/rag_eval.py --input examples/rag_test.csv
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path
from textwrap import shorten
from typing import TypedDict
import html

# ---------- Metrics: 3-gram containment & sentence support ----------


def compute_3gram_containment(answer: str, passages: str) -> float:
    """
    Compute 3-gram containment: fraction of answer trigrams that appear in passages.

    Returns:
        Float between 0.0 and 1.0.
    """
    # Normalize to lowercase and split on whitespace
    answer_words = answer.lower().split()
    passage_words = passages.lower().split()

    # If the answer is too short, treat as trivially contained
    if len(answer_words) < 3:
        return 1.0

    # Build answer 3-grams
    answer_3grams: set[tuple[str, str, str]] = set()
    for i in range(len(answer_words) - 2):
        answer_3grams.add((answer_words[i], answer_words[i + 1], answer_words[i + 2]))

    if not answer_3grams:
        return 0.0

    # Build passage 3-grams
    passage_3grams: set[tuple[str, str, str]] = set()
    for i in range(len(passage_words) - 2):
        passage_3grams.add(
            (passage_words[i], passage_words[i + 1], passage_words[i + 2])
        )

    if not passage_3grams:
        return 0.0

    matches = len(answer_3grams & passage_3grams)
    total = len(answer_3grams)
    return matches / total if total > 0 else 0.0


_SENT_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")


def split_sentences(answer: str) -> list[str]:
    return [s.strip() for s in _SENT_SPLIT_RE.split(answer.strip()) if s.strip()]


def sentence_supported(sent: str, passage_words: set[str]) -> bool:
    sent_words = re.findall(r"\b\w+\b", sent.lower())
    if not sent_words:
        return True
    overlap = sum(1 for w in sent_words if w in passage_words)
    return (overlap / len(sent_words)) > 0.5


def compute_sentence_support_flags(
    answer: str, passages: str
) -> tuple[float, list[str], list[bool]]:
    """
    Compute sentence-level support: fraction of answer sentences supported by passages
    (>50% word overlap). Returns ratio + sentence list + per-sentence support flags.

    Returns:
        (support_ratio, sentences, supported_flags)
    """
    sentences = split_sentences(answer)
    if not sentences:
        return 1.0, [], []

    passage_words = set(re.findall(r"\b\w+\b", passages.lower()))
    if not passage_words:
        return 0.0, sentences, [False] * len(sentences)

    flags = [sentence_supported(s, passage_words) for s in sentences]
    ratio = sum(1 for x in flags if x) / len(flags)
    return ratio, sentences, flags


# ---------- Data structures & CSV helpers ----------


class RagCase(TypedDict):
    id: str
    question: str
    answer: str
    passages: str


class RagResult(TypedDict):
    id: str
    question: str
    answer: str
    containment: float
    support: float
    answer_sentences: list[str]
    supported_sentences: list[bool]
    passages_joined: str


def split_passages(passages_str: str) -> list[str]:
    """
    Split a 'passages' field on the |;| separator into a list of passages.
    """
    return [p.strip() for p in passages_str.split("|;|") if p.strip()]


def load_cases(path: Path) -> list[RagCase]:
    """
    Load RAG cases from a CSV file with columns:
    id, question, answer, passages
    """
    cases: list[RagCase] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cases.append(
                RagCase(
                    id=row["id"],
                    question=row["question"],
                    answer=row["answer"],
                    passages=row["passages"],
                )
            )
    return cases


def evaluate_cases(cases: list[RagCase]) -> list[RagResult]:
    """
    Compute containment and sentence support metrics for each case.
    """
    results: list[RagResult] = []

    for case in cases:
        passes_joined = " ".join(split_passages(case["passages"]))
        containment = compute_3gram_containment(case["answer"], passes_joined)
        support, sents, flags = compute_sentence_support_flags(
            case["answer"], passes_joined
        )

        results.append(
            RagResult(
                id=case["id"],
                question=case["question"],
                answer=case["answer"],
                containment=containment,
                support=support,
                answer_sentences=sents,
                supported_sentences=flags,
                passages_joined=passes_joined,
            )
        )
    return results


# ---------- Aggregation & printing ----------


def summarize(results: list[RagResult]) -> tuple[float, float]:
    """
    Compute mean containment and mean sentence support across all results.
    """
    if not results:
        return 0.0, 0.0

    n = len(results)
    avg_containment = sum(r["containment"] for r in results) / n
    avg_support = sum(r["support"] for r in results) / n
    return avg_containment, avg_support


def print_summary(results: list[RagResult]) -> None:
    """
    Print aggregate KPIs for the dataset.
    """
    avg_containment, avg_support = summarize(results)

    print("=== RAG Faithfulness Metrics ===")
    print(f"Total cases: {len(results)}")
    print()
    print(f"Average 3-gram containment: {avg_containment:.2f}")
    print(f"Average sentence support:   {avg_support:.2f}")
    print()


def print_worst_cases(results: list[RagResult], top_k: int = 5) -> None:
    """
    Print the top-k worst cases by sentence support (ascending).
    """
    worst = sorted(results, key=lambda r: (r["support"], r["containment"]))[:top_k]

    print(f"=== Top {len(worst)} Worst Cases (by sentence support) ===")

    for i, r in enumerate(worst, start=1):
        print(
            f"{i}. id={r['id']}  support={r['support']:.2f}  "
            f"containment={r['containment']:.2f}"
        )
        preview = shorten(r["answer"], width=120, placeholder="...")
        print(f'   Answer: "{preview}"')
        print()


# ---------- HTML report ----------


def _pct(x: float) -> str:
    x = max(0.0, min(1.0, x))
    return f"{x * 100:.1f}%"


def render_html_report(
    results: list[RagResult], out_path: Path, top_k: int = 5
) -> None:
    """
    Render reports/rag_report.html with summary cards + top-k worst examples.
    Unsupported sentences are highlighted in red.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    avg_containment, avg_support = summarize(results)
    fully_supported = sum(1 for r in results if abs(r["support"] - 1.0) < 1e-9)
    fully_supported_pct = fully_supported / len(results)

    worst = sorted(results, key=lambda r: (r["support"], r["containment"]))[:top_k]

    def highlight_answer(r: RagResult) -> str:
        parts: list[str] = []
        for sent, ok in zip(r["answer_sentences"], r["supported_sentences"]):
            safe = html.escape(sent)
            cls = "ok" if ok else "bad"
            parts.append(f"<span class='sent {cls}'>{safe}</span>")
        return " ".join(parts)

    def truncate(text: str, limit: int = 1800) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + "..."

    worst_blocks: list[str] = []
    for r in worst:
        worst_blocks.append(
            f"""
            <div class="worst-item">
                <div class="meta"><b>id:</b> {html.escape(r["id"])} • <b>support:</b> {_pct(r["support"])} • <b>containment:</b> {_pct(r["containment"])}</div>
                
                <div class = "block">
                    <div class="label"> Question</div>
                    <div class="text">{html.escape(r["question"])}</div>
                </div>
                
                <div class = "block">
                    <div class="label"> Answer (highlighted)</div>
                    <div class="answer">{highlight_answer(r)}</div>
                    <div class="legend">
                        <span class="pill ok">Supported</span>
                        <span class="pill bad">Unsupported</span>
                    </div>
                </div>
                
                <details class="block">
                    <summary class="label">Passages (truncated)</summary>
                    <pre class="passages">{html.escape(truncate(r["passages_joined"]))}</pre>
                </details>
            </div>
            """
        )
    doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>RAG Faithfulness Report</title>
  <style>
    :root {{
      --bg: #0b0c10;
      --panel: rgba(255,255,255,0.04);
      --text: #e8e8ea;
      --muted: #a8abb6;
      --border: rgba(255,255,255,0.08);
      --ok: rgba(0,200,120,0.18);
      --bad: rgba(255,80,80,0.18);
      --shadow: 0 10px 30px rgba(0,0,0,0.35);
      --radius: 14px;
    }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      background: radial-gradient(1200px 800px at 20% 0%, rgba(120,70,255,0.18), transparent 55%),
                  radial-gradient(1000px 700px at 90% 10%, rgba(0,180,255,0.14), transparent 60%),
                  var(--bg);
      color: var(--text);
    }}
    .wrap {{ max-width: 1100px; margin: 32px auto; padding: 0 18px 48px; }}
    h1 {{ font-size: 22px; margin: 0 0 10px; }}
    .sub {{ color: var(--muted); margin: 0 0 22px; font-size: 14px; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 18px 0 26px; }}
    @media (max-width: 900px) {{ .cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
    @media (max-width: 520px) {{ .cards {{ grid-template-columns: 1fr; }} }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 14px 14px 12px;
    }}
    .card-title {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.9px;
      margin-bottom: 10px;
    }}
    .card-value {{ font-size: 22px; font-weight: 700; margin-bottom: 4px; }}
    .card-sub {{ color: var(--muted); font-size: 12px; }}
    .section-title {{ margin: 26px 0 10px; font-size: 16px; font-weight: 700; }}
    .worst-item {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 14px;
      margin: 12px 0;
    }}
    .meta {{ color: var(--muted); font-size: 12px; margin-bottom: 10px; }}
    .block {{ margin: 12px 0; }}
    .label {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.9px;
      margin-bottom: 6px;
      cursor: pointer;
    }}
    .text {{ line-height: 1.45; font-size: 14px; white-space: pre-wrap; }}
    .answer {{ line-height: 1.55; font-size: 14px; white-space: pre-wrap; }}
    .sent {{
      padding: 2px 4px;
      border-radius: 8px;
      border: 1px solid var(--border);
      margin-right: 2px;
    }}
    .sent.ok {{ background: var(--ok); }}
    .sent.bad {{ background: var(--bad); }}
    .legend {{ margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap; }}
    .pill {{
      font-size: 12px;
      color: var(--muted);
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 3px 10px;
    }}
    .pill.ok {{ background: var(--ok); }}
    .pill.bad {{ background: var(--bad); }}
    details pre.passages {{
      margin: 0;
      padding: 12px;
      background: rgba(0,0,0,0.25);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: auto;
      max-height: 280px;
      line-height: 1.4;
      font-size: 12px;
      color: #d7d7db;
      white-space: pre-wrap;
    }}
    .footer {{ margin-top: 26px; color: var(--muted); font-size: 12px; }}
    code {{
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 2px 6px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>RAG Faithfulness Report</h1>
    <p class="sub">
      Overlap-based heuristic metrics (not ground-truth). Treat as a fast hallucination smoke test.
    </p>

    <div class="cards">
      <div class="card">
        <div class="card-title">Rows</div>
        <div class="card-value">{len(results)}</div>
        <div class="card-sub">Total evaluated</div>
      </div>
      <div class="card">
        <div class="card-title">Avg support ratio</div>
        <div class="card-value">{_pct(avg_support)}</div>
        <div class="card-sub">Sentence-level overlap support</div>
      </div>
      <div class="card">
        <div class="card-title">Avg containment</div>
        <div class="card-value">{_pct(avg_containment)}</div>
        <div class="card-sub">3-gram containment in passages</div>
      </div>
      <div class="card">
        <div class="card-title">Fully supported</div>
        <div class="card-value">{_pct(fully_supported_pct)}</div>
        <div class="card-sub">Support ratio == 100%</div>
      </div>
    </div>

    <div class="section-title">Top {len(worst)} worst examples</div>
    {''.join(worst_blocks)}

    <div class="footer">
      Generated by <code>scripts/rag_eval.py</code>. HTML is escaped for safety.
    </div>
  </div>
</body>
</html>
"""

    out_path.write_text(doc, encoding="utf-8")


# ---------- CLI entrypoint ----------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate RAG faithfulness metrics "
            "(3-gram containment & sentence-level support)."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to CSV file (columns: id,question,answer,passages)",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Number of worst cases to display (default: 5)",
    )
    parser.add_argument(
        "--html-out",
        default=None,
        help="If set, write an HTML report to this path (e.g., reports/rag_report.html)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        return 1

    cases = load_cases(input_path)
    if not cases:
        print("Error: No cases found in CSV", file=sys.stderr)
        return 1

    results = evaluate_cases(cases)
    print_summary(results)
    print_worst_cases(results, top_k=args.top_k)

    if args.html_out:
        out_path = Path(args.html_out)
        render_html_report(results, out_path, top_k=args.top_k)
        print(f"Wrote HTML report to: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

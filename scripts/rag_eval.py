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


_SENT_SPLIT_RE = re.compile(r"[.!?]+")


def compute_sentece_support(answer: str, passages: str) -> float:
    """
    Compute sentence-level support: fraction of answer sentences
    that are supported by passages (>50% word overlap).

    Steps:
    - Split the answer into sentences on . ! ?
    - For each sentence, compute how many of its words appear in passages.
    - A sentence is "supported" if overlap / len(sentence_words) > 0.5.
    - Return supported_sentences / total_sentences.

    Returns:
        Float between 0.0 and 1.0.
    """
    # Split into sentences
    sentences = [s.strip() for s in _SENT_SPLIT_RE.split(answer) if s.strip()]

    if not sentences:
        # Nothing to evaluate; treat as trivially supported
        return 1.0

    # All words in passages
    passage_words = set(re.findall(r"\b\w+\b", passages.lower()))

    if not passage_words:
        # No evidence to support anything
        return 0.0

    supported_count = 0
    total_count = 0

    for sent in sentences:
        sent_words = re.findall(r"\b\w+\b", sent.lower())
        if not sent_words:
            continue

        total_count += 1
        overlap = sum(1 for w in sent_words if w in passage_words)
        ratio = overlap / len(sent_words)

        if ratio > 0.5:
            supported_count += 1

    if total_count == 0:
        # All sentences were empty after tokenization
        return 1.0

    return supported_count / total_count


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
        support = compute_sentece_support(case["answer"], passes_joined)

        results.append(
            RagResult(
                id=case["id"],
                question=case["question"],
                answer=case["answer"],
                containment=containment,
                support=support,
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
    worst = sorted(results, key=lambda r: r["support"])[:top_k]

    print(f"=== Top {len(worst)} Worst Cases (by sentence support) ===")

    for i, r in enumerate(worst, start=1):
        print(
            f"{i}. id={r['id']}  support={r['support']:.2f}  "
            f"containment={r['containment']:.2f}"
        )
        preview = shorten(r["answer"], width=120, placeholder="...")
        print(f'   Answer: "{preview}"')
        print()


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

    return 0


if __name__ == "__main__":
    sys.exit(main())

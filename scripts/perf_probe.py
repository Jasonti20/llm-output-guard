# scripts/perf_probe.py
from __future__ import annotations
import random, time
from statistics import median
import os, sys

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from llm_output_guard.core.engine import scan_and_apply


def _blob(kind: str, n: int) -> str:
    """Generate synthetic text with different entropy profiles."""
    if kind == "english":
        words = [
            "the",
            "cat",
            "sat",
            "on",
            "the",
            "mat",
            "lorem",
            "ipsum",
            "data",
            "value",
        ]
        return " ".join(random.choice(words) for _ in range(max(1, n // 5)))
    if kind == "base64ish":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return "".join(random.choice(alphabet) for _ in range(n))
    if kind == "code":
        tokens = [
            "int",
            "var",
            "let",
            "=",
            "(",
            ")",
            "{",
            "}",
            ";",
            "foo",
            "bar",
            "baz",
            "12345",
        ]
        return " ".join(random.choice(tokens) for _ in range(max(1, n // 3)))
    return "x" * n  # fallback


def run_case(kind: str, size: int, iters: int = 10) -> None:
    """Measure p50/min/max latency (ms) for one (kind, size)."""
    s = _blob(kind, size)

    # warmup (JIT caches, imports, etc.)
    scan_and_apply(s, "balanced")

    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        _ = scan_and_apply(s, "balanced")
        dt_ms = (time.perf_counter() - t0) * 1000.0
        samples.append(dt_ms)

    print(
        f"{kind:9} {size:7d} bytes  p50={median(samples):6.1f} ms  "
        f"min={min(samples):6.1f}  max={max(samples):6.1f}"
    )


def main() -> None:
    random.seed(0)
    kinds = ["english", "base64ish", "code"]
    sizes = [1_000, 5_000, 20_000, 100_000, 250_000]
    print("LLM Output Guard — perf probe (ms per call)")
    for kind in kinds:
        for size in sizes:
            run_case(kind, size)


if __name__ == "__main__":
    main()

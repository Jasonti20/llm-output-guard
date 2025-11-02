from __future__ import annotations
import argparse
import base64
import os
import statistics
import string
import sys
import time
from typing import List

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from llm_output_guard.core.engine import scan_and_apply  # returns ScanResult

# -------- Payload generators (exact length) --------
_LOREM = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
    "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
    "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. "
    "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. "
)


def gen_english(n: int) -> str:
    if n <= 0:
        return ""
    return (_LOREM * ((n // len(_LOREM)) + 2))[:n]


def gen_random_base64(n: int) -> str:
    # real base64 of random bytes; repeat & slice to exact n chars
    raw = os.urandom(max(4, int(n * 0.75) + 8))
    b64 = base64.b64encode(raw).decode("ascii")
    return (b64 * ((n // len(b64)) + 2))[:n]


def gen_alphabetic_base64(n: int) -> str:
    # base64 alphabet stream (structured, medium entropy)
    alphabet = string.ascii_letters + string.digits + "+/="
    out, i, L = [], 0, len(alphabet)
    while len(out) < n:
        out.append(alphabet[i % L])
        i += 7
    return "".join(out)[:n]


GENS = {
    "english": gen_english,
    "random": gen_random_base64,  # high-entropy, true base64 text
    "base64": gen_alphabetic_base64,  # structured base64-like stream
}


# -------- Metrics helpers --------
def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    idx = max(0, min(len(vals) - 1, int(round((p / 100.0) * (len(vals) - 1)))))
    return vals[idx]


def ms_per_1k(elapsed_s: float, n_chars: int) -> float:
    if n_chars <= 0:
        return 0.0
    return (elapsed_s * 1000.0) / (n_chars / 1000.0)


# -------- Runner --------
def run_probe(
    sizes: List[int],
    kinds: List[str],
    trials: int,
    warmup: int,
    profile: str,
    budget_ms_per_1k: float | None,
) -> None:
    print(f"Profile: {profile}")
    print(f"Trials: warmup={warmup}, measured={trials}")
    print(f"Sizes: {', '.join(map(str, sizes))} chars")
    if budget_ms_per_1k is not None:
        print(f"Budget: {budget_ms_per_1k:.2f} ms/1k")
    print()

    for kind in kinds:
        if kind not in GENS:
            print(f"[skip] unknown kind '{kind}' (options: {', '.join(GENS.keys())})")
            continue
        gen = GENS[kind]
        print(f"=== {kind} ===")

        for n in sizes:
            payload = gen(n)

            # Warmups
            for _ in range(warmup):
                _ = scan_and_apply(payload, profile=profile)

            # Mesaured trials
            samples_ms_per_k: List[float] = []
            trunc = capped = timedout = False
            for _ in range(trials):
                t0 = time.perf_counter()
                result = scan_and_apply(payload, profile=profile)
                t1 = time.perf_counter()
                samples_ms_per_k.append(ms_per_1k(t1 - t0, len(payload)))
                trunc = trunc or bool(getattr(result, "truncated", False))
                capped = capped or bool(getattr(result, "findings_capped", False))
                timedout = timedout or bool(getattr(result, "timed_out", False))

            p50 = percentile(samples_ms_per_k, 50)
            p95 = percentile(samples_ms_per_k, 95)
            notes = []
            if trunc:
                notes.append("truncated")
            if capped:
                notes.append("findings_capped")
            if timedout:
                notes.append("timed_out")
            if budget_ms_per_1k is not None and p95 > budget_ms_per_1k:
                notes.append("over_budget_p95")
            suffix = (" [" + ", ".join(notes) + "]") if notes else ""
            print(f"{n:>8} chars  p50={p50:6.2f} ms/1k  p95={p95:6.2f} ms/1k{suffix}")
        print()


# -------- CLI --------
def _parse_size_token(tok: str) -> int:
    tok = tok.strip().lower()
    if tok.endswith("k"):
        return int(float(tok[:-1]) * 1000)
    if tok.endswith("m"):
        return int(float(tok[:-1]) * 1_000_000)
    return int(tok)


def parse_args(argv: List[str]):
    p = argparse.ArgumentParser(
        description="Perf probe for llm-output-guard (ms per 1k chars)."
    )
    p.add_argument("--sizes", nargs="+", default=["1k", "5k", "20k", "100k", "250k"])
    p.add_argument("--kinds", nargs="+", default=["english", "random", "base64"])
    p.add_argument("--trials", type=int, default=10)
    p.add_argument("--warmup", type=int, default=3)
    p.add_argument("--profile", type=str, default="balanced")
    p.add_argument("--budget-ms-per-1k", type=float, default=None)
    return p.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    ns = parse_args(sys.argv[1:] if argv is None else argv)
    sizes = [_parse_size_token(s) for s in ns.sizes]
    run_probe(
        sizes=sizes,
        kinds=ns.kinds,
        trials=ns.trials,
        warmup=ns.warmup,
        profile=ns.profile,
        budget_ms_per_1k=ns.budget_ms_per_1k,
    )


if __name__ == "__main__":
    main()

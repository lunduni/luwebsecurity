"""Commitment scheme probabilities for truncated-hash commitments.

Scheme:
  Commit(v, k) = Truncate(h(v || k), X)

Parameters:
  v ∈ {0,1}
  k ∈ {0,1}^K (uniform)
  output x ∈ {0,1}^X

This script computes (and optionally plots) the probability of breaking:
  - Binding: attacker finds (0,k0) and (1,k1) with same commitment.
  - Hiding: receiver can uniquely determine v from x.

Model: random oracle / ideal hash.

Run:
  python commitmentscheme/commitment_probabilities.py --min-x 4 --max-x 48 --outdir commitmentscheme/out

Outputs:
  - outdir/probabilities.csv
  - outdir/probabilities.png (if matplotlib is installed)
"""

from __future__ import annotations

import argparse
import csv
import math
import os
from dataclasses import dataclass
from typing import Iterable, List, Tuple


@dataclass(frozen=True)
class Params:
    K: int = 16


def _pow2(n: int) -> float:
    # float is fine here; we only use it for exponent sizes / denominators.
    return float(2**n)


def binding_break_probability(K: int, X: int) -> float:
    """Probability a cross-collision exists between {h(0||k)} and {h(1||k)}.

    Let N = 2^K possible k values per bit, and M = 2^X possible digests.

    Under the ideal-hash model, each (v,k) maps independently uniformly into [0, M).

    Binding is breakable iff the two size-N sets intersect:
      S0 = {Trunc(h(0||k),X) : k ∈ {0,1}^K}
      S1 = {Trunc(h(1||k),X) : k ∈ {0,1}^K}

    P[S0 ∩ S1 ≠ ∅] = 1 - (1 - 1/M)^(N^2).

    Uses log1p for numeric stability.
    """
    if X <= 0:
        return 1.0
    if K < 0:
        raise ValueError("K must be non-negative")

    N2 = 2 ** (2 * K)  # exact int
    M = 2.0 ** X

    # log( (1 - 1/M)^(N^2) ) = N^2 * log(1 - 1/M)
    log_no_intersection = float(N2) * math.log1p(-1.0 / M)

    # If log_no_intersection is very negative, exp() underflows to 0 (fine).
    no_intersection = math.exp(log_no_intersection)
    return 1.0 - no_intersection


def hiding_break_probability(K: int, X: int) -> float:
    """Probability a random commitment digest x reveals v uniquely.

    We follow the assignment's definition:
      P_break = (# of digests x for which v can be uniquely determined) / 2^X.

    For a fixed v, define Sv as the set of X-bit digests reachable by varying k:
      Sv = {Trunc(h(v||k),X) : k ∈ {0,1}^K}

    For a uniformly random digest x ∈ {0,1}^X:
      p = Pr[x ∈ Sv] = 1 - (1 - 1/M)^N
        where N=2^K, M=2^X.

    Assuming independence between v=0 and v=1 images (ideal hash),
      Pr[x uniquely determines v] = Pr[(x∈S0 xor x∈S1)] = 2 p (1-p).

    Uses log1p for numeric stability.
    """
    if X <= 0:
        return 0.0
    if K < 0:
        raise ValueError("K must be non-negative")

    N = 2**K
    M = 2.0 ** X

    # p = 1 - (1 - 1/M)^N
    log_absent = float(N) * math.log1p(-1.0 / M)
    absent = math.exp(log_absent)
    present = 1.0 - absent

    return 2.0 * present * (1.0 - present)


def compute_series(K: int, xs: Iterable[int]) -> List[Tuple[int, float, float]]:
    rows: List[Tuple[int, float, float]] = []
    for X in xs:
        pb = binding_break_probability(K, X)
        ph = hiding_break_probability(K, X)
        rows.append((X, pb, ph))
    return rows


def write_csv(rows: List[Tuple[int, float, float]], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["X", "p_break_binding", "p_break_hiding"])
        writer.writerows(rows)


def plot_png(rows: List[Tuple[int, float, float]], path: str) -> bool:
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        return False

    xs = [r[0] for r in rows]
    pb = [r[1] for r in rows]
    ph = [r[2] for r in rows]

    os.makedirs(os.path.dirname(path), exist_ok=True)

    plt.figure(figsize=(8, 4.5))
    plt.plot(xs, pb, label="Break binding")
    plt.plot(xs, ph, label="Break hiding")
    plt.yscale("logit")  # emphasizes transition regions (still shows 0/1 as inf)

    # Matplotlib logit can't plot exact 0 or 1; clamp for display.
    eps = 1e-12
    pb2 = [min(1 - eps, max(eps, v)) for v in pb]
    ph2 = [min(1 - eps, max(eps, v)) for v in ph]
    plt.clf()
    plt.figure(figsize=(8, 4.5))
    plt.plot(xs, pb2, label="Break binding")
    plt.plot(xs, ph2, label="Break hiding")
    plt.yscale("logit")
    plt.ylim(eps, 1 - eps)

    plt.xlabel("Truncation length X (bits)")
    plt.ylabel("Probability")
    plt.title("Truncated-hash commitment: break probabilities vs X (K=16)")
    plt.grid(True, which="both", linestyle=":", linewidth=0.8)
    plt.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()
    return True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--K", type=int, default=16, help="Randomness size K (bits). Default 16.")
    p.add_argument("--min-x", type=int, default=4, help="Minimum X (bits) to evaluate.")
    p.add_argument("--max-x", type=int, default=48, help="Maximum X (bits) to evaluate (inclusive).")
    p.add_argument("--step", type=int, default=1, help="Step size for X.")
    p.add_argument(
        "--outdir",
        type=str,
        default=os.path.join("commitmentscheme", "out"),
        help="Output directory for CSV/PNG.",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    xs = list(range(args.min_x, args.max_x + 1, args.step))
    rows = compute_series(args.K, xs)

    csv_path = os.path.join(args.outdir, "probabilities.csv")
    png_path = os.path.join(args.outdir, "probabilities.png")

    write_csv(rows, csv_path)
    plotted = plot_png(rows, png_path)

    print(f"Wrote: {csv_path}")
    if plotted:
        print(f"Wrote: {png_path}")
    else:
        print("Matplotlib not available; skipped PNG plot (CSV still written).")

    # Also print a small table to stdout for quick inspection.
    print("\nX\tP_break_binding\tP_break_hiding")
    for X, pb, ph in rows:
        print(f"{X}\t{pb:.6g}\t{ph:.6g}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

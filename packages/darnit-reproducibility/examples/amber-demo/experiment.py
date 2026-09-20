"""A tiny, deterministic 'scientific experiment' for the Amber capture demo.

Stands in for the PDF's Dr. Brown lightning simulation: a NumPy Monte-Carlo estimate with a fixed
seed, so a faithful reproduction produces a bit-for-bit identical ``result.json`` — exactly the
property Amber's capture is meant to make checkable.
"""
from __future__ import annotations

import json
import platform

import numpy as np


def estimate() -> dict[str, float | int | str]:
    rng = np.random.default_rng(42)  # fixed seed -> reproducible output
    # crude Monte-Carlo estimate of pi, plus a couple of summary stats
    n = 200_000
    pts = rng.random((n, 2))
    inside = int(np.count_nonzero((pts[:, 0] ** 2 + pts[:, 1] ** 2) <= 1.0))
    samples = rng.normal(loc=1.21, scale=0.3, size=10_000)  # "gigawatts"
    return {
        "pi_estimate": 4.0 * inside / n,
        "mean_gigawatts": float(np.mean(samples)),
        "std_gigawatts": float(np.std(samples)),
        "n_samples": n,
        "numpy_version": np.__version__,
        "python": platform.python_version(),
    }


def main() -> None:
    result = estimate()
    with open("result.json", "w") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    print("experiment complete:", result)


if __name__ == "__main__":
    main()

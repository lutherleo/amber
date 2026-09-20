"""Deliberately NON-reproducible experiment — the counter-example for Amber's verdict.

Uses an **unseeded** RNG and the wall-clock, so two runs produce different ``result.json``. Running the
Amber loop on this (`amber verify`, or `examples/repro-loop/run_loop.sh nondeterministic`) yields
`NOT_REPRODUCED` with the cause identified as nondeterminism (outputs differ while the environment is
identical) — the honest failure signal a researcher needs.
"""
from __future__ import annotations

import json
import time

import numpy as np


def main() -> None:
    rng = np.random.default_rng()  # UNSEEDED on purpose
    result = {
        "random_draw": float(rng.random()),
        "wall_clock": time.time(),
        "numpy_version": np.__version__,
    }
    with open("result.json", "w") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    print("nondeterministic run:", result)


if __name__ == "__main__":
    main()

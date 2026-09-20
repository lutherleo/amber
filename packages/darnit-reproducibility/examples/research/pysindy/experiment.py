"""Data-driven model discovery with PySINDy — a real, downloaded third-party research package.

PySINDy (Sparse Identification of Nonlinear Dynamics, Brunton et al.) is a published research library
Amber has never seen. Here it recovers a linear ODE system from trajectory data; the point is that the
capture records PySINDy and its dependency stack as exact, hashed library objects. Deterministic.
"""
from __future__ import annotations

import json

import numpy as np
import pysindy as ps


def main() -> None:
    t = np.linspace(0.0, 5.0, 500)
    dt = float(t[1] - t[0])
    # trajectories of dx/dt = -2x, dy/dt = -0.5y
    x = np.stack([np.exp(-2.0 * t), np.exp(-0.5 * t)], axis=1)
    model = ps.SINDy()
    model.fit(x, t=dt)
    result = {
        "identified_coefficients": np.round(model.coefficients(), 3).tolist(),
        "feature_names": model.get_feature_names(),
        "pysindy_version": ps.__version__,
        "numpy_version": np.__version__,
    }
    with open("result.json", "w") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    print("PySINDy identified coefficients:", result["identified_coefficients"])


if __name__ == "__main__":
    main()

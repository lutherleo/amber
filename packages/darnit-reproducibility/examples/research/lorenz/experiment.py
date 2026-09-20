"""Lorenz system (Lorenz, 1963) — canonical deterministic chaos, integrated with SciPy.

A faithful reproduction of the classic computational-physics experiment: integrate the Lorenz ODEs
and record a hash of the whole trajectory. With fixed tolerances the integration is deterministic,
so a faithful reproduction yields a bit-for-bit identical ``result.json`` — the reproducibility
property Amber's capture is meant to make checkable.
"""
from __future__ import annotations

import hashlib
import json

import numpy as np
from scipy.integrate import solve_ivp


def lorenz(t: float, s: np.ndarray, sigma: float = 10.0, beta: float = 8.0 / 3.0,
           rho: float = 28.0) -> list[float]:
    x, y, z = s
    return [sigma * (y - x), x * (rho - z) - y, x * y - beta * z]


def main() -> None:
    t_span = (0.0, 40.0)
    t_eval = np.linspace(*t_span, 20_000)
    sol = solve_ivp(lorenz, t_span, [1.0, 1.0, 1.0], t_eval=t_eval, rtol=1e-9, atol=1e-9)
    traj = np.ascontiguousarray(sol.y.T)
    result = {
        "final_state": traj[-1].tolist(),
        "n_steps": int(len(t_eval)),
        "trajectory_sha256": hashlib.sha256(traj.tobytes()).hexdigest(),
        "numpy_version": np.__version__,
        "scipy_version": __import__("scipy").__version__,
    }
    with open("result.json", "w") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    print("lorenz complete:", result["final_state"], result["trajectory_sha256"][:12])


if __name__ == "__main__":
    main()

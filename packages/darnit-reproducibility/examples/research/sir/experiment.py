"""SIR compartmental epidemic model (Kermack–McKendrick, 1927), integrated with SciPy.

A standard computational-epidemiology experiment: integrate the SIR ODEs and report the epidemic
peak and final size. Deterministic, so a faithful reproduction is bit-for-bit identical.
"""
from __future__ import annotations

import json

import numpy as np
from scipy.integrate import odeint


def sir(y: np.ndarray, t: float, beta: float, gamma: float) -> list[float]:
    s, i, r = y
    return [-beta * s * i, beta * s * i - gamma * i, gamma * i]


def main() -> None:
    beta, gamma = 0.30, 0.10
    y0 = [0.99, 0.01, 0.0]
    t = np.linspace(0.0, 160.0, 1_600)
    sol = odeint(sir, y0, t, args=(beta, gamma))
    peak_idx = int(sol[:, 1].argmax())
    result = {
        "R0": beta / gamma,
        "peak_infected_fraction": float(sol[peak_idx, 1]),
        "t_peak": float(t[peak_idx]),
        "final_recovered_fraction": float(sol[-1, 2]),
        "numpy_version": np.__version__,
        "scipy_version": __import__("scipy").__version__,
    }
    with open("result.json", "w") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    print("SIR complete:", result)


if __name__ == "__main__":
    main()

"""A paper's quantitative claims, and the deterministic check of a run against them.

A ``Claim`` is a machine-checkable statement a paper makes about its results, e.g.
the gittuf NDSS paper's "under 0.59 s per-push verification" and "less than 4 %
storage overhead". Verification is deterministic (no LLM): a run's measured
``Result`` for the claim's metric is compared under the claim's comparator, with
numeric tolerance in the same spirit as ``analysis.compare._values_close``.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# Claim verdict levels (a subset of the reproducibility levels, claim-scoped).
REPRODUCED = "REPRODUCED"
NOT_REPRODUCED = "NOT_REPRODUCED"
INCONCLUSIVE = "INCONCLUSIVE"

_COMPARATORS = ("<=", ">=", "==", "~")


@dataclass
class Claim:
    metric: str
    comparator: str  # one of _COMPARATORS
    value: float
    tolerance: float = 0.0
    unit: str | None = None

    def as_props(self) -> dict[str, object]:
        return {
            "metric": self.metric,
            "comparator": self.comparator,
            "value": self.value,
            "tolerance": self.tolerance,
            "unit": self.unit,
        }


def parse_claim(spec: str) -> Claim:
    """Parse a ``--claim`` string.

    Forms::

        metric=value±tol      # equality within tolerance   (also value+-tol)
        metric<=value         # upper bound
        metric>=value         # lower bound
        metric=value          # exact equality (tol 0)

    A trailing unit token is allowed: ``verify_seconds<=0.59s`` -> unit "s".
    """
    s = spec.strip().replace("+-", "±")
    for comp in ("<=", ">=", "=="):
        if comp in s:
            metric, rhs = s.split(comp, 1)
            value, unit = _num_unit(rhs)
            return Claim(metric.strip(), "<=" if comp == "<=" else ">=" if comp == ">=" else "==", value, 0.0, unit)
    if "=" in s:
        metric, rhs = s.split("=", 1)
        if "±" in rhs:
            val_s, tol_s = rhs.split("±", 1)
            value, unit = _num_unit(val_s)
            tol, _ = _num_unit(tol_s)
            return Claim(metric.strip(), "~", value, tol, unit)
        value, unit = _num_unit(rhs)
        return Claim(metric.strip(), "==", value, 0.0, unit)
    raise ValueError(f"unparseable claim {spec!r}; expected metric=value[±tol] | metric<=value | metric>=value")


def _num_unit(token: str) -> tuple[float, str | None]:
    t = token.strip()
    # split leading numeric (incl. sign / decimal / exponent) from a trailing unit.
    i = 0
    while i < len(t) and (t[i].isdigit() or t[i] in "+-.eE"):
        i += 1
    num = t[:i].strip()
    unit = t[i:].strip() or None
    if not num:
        raise ValueError(f"no numeric value in {token!r}")
    return float(num), unit


def check(claim: Claim, results: dict[str, float]) -> tuple[str, str]:
    """Check a claim against a run's measured metrics.

    ``results`` maps metric -> measured numeric value. Returns
    ``(level, human_summary)``. Missing metric -> INCONCLUSIVE (never a pass).
    """
    if claim.metric not in results:
        return INCONCLUSIVE, f"metric {claim.metric!r} not measured in this run"
    measured = results[claim.metric]
    ok = _satisfies(claim, measured)
    rel = {"<=": "<=", ">=": ">=", "==": "==", "~": "≈"}[claim.comparator]
    tol = f" ±{claim.tolerance:g}" if claim.comparator == "~" and claim.tolerance else ""
    detail = f"measured {measured:g} {rel} {claim.value:g}{tol}{(' ' + claim.unit) if claim.unit else ''}"
    return (REPRODUCED if ok else NOT_REPRODUCED), detail


def _satisfies(claim: Claim, measured: float) -> bool:
    if claim.comparator == "<=":
        return measured <= claim.value or math.isclose(measured, claim.value, rel_tol=1e-12, abs_tol=1e-12)
    if claim.comparator == ">=":
        return measured >= claim.value or math.isclose(measured, claim.value, rel_tol=1e-12, abs_tol=1e-12)
    if claim.comparator == "==":
        return math.isclose(measured, claim.value, rel_tol=1e-12, abs_tol=1e-12)
    # "~": within tolerance (mirrors compare._values_close's abs/rel tolerance stance).
    tol = claim.tolerance or 0.0
    return math.isclose(measured, claim.value, rel_tol=1e-9, abs_tol=abs(tol))

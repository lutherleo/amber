"""Claim parsing + deterministic checking."""
from __future__ import annotations

import pytest
from darnit_reproducibility.research.claims import (
    INCONCLUSIVE,
    NOT_REPRODUCED,
    REPRODUCED,
    check,
    parse_claim,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("spec", "metric", "comparator", "value", "tol", "unit"),
    [
        ("verify_seconds<=0.59s", "verify_seconds", "<=", 0.59, 0.0, "s"),
        ("storage_overhead_pct>=4", "storage_overhead_pct", ">=", 4.0, 0.0, None),
        ("rate=0.5±0.1", "rate", "~", 0.5, 0.1, None),
        ("rate=0.5+-0.1", "rate", "~", 0.5, 0.1, None),
        ("exit_code=0", "exit_code", "==", 0.0, 0.0, None),
    ],
)
def test_parse_claim(spec, metric, comparator, value, tol, unit):
    c = parse_claim(spec)
    assert (c.metric, c.comparator, c.value, c.tolerance, c.unit) == (metric, comparator, value, tol, unit)


@pytest.mark.unit
def test_parse_claim_rejects_garbage():
    with pytest.raises(ValueError):
        parse_claim("this is not a claim")


@pytest.mark.unit
def test_check_upper_bound_pass_and_fail():
    c = parse_claim("verify_seconds<=0.59")
    assert check(c, {"verify_seconds": 0.4})[0] == REPRODUCED
    assert check(c, {"verify_seconds": 0.59})[0] == REPRODUCED  # boundary
    assert check(c, {"verify_seconds": 0.9})[0] == NOT_REPRODUCED


@pytest.mark.unit
def test_check_tolerance_band():
    c = parse_claim("rate=0.5±0.05")
    assert check(c, {"rate": 0.52})[0] == REPRODUCED
    assert check(c, {"rate": 0.7})[0] == NOT_REPRODUCED


@pytest.mark.unit
def test_missing_metric_is_inconclusive_never_pass():
    c = parse_claim("verify_seconds<=0.59")
    level, detail = check(c, {"other": 1.0})
    assert level == INCONCLUSIVE
    assert "not measured" in detail

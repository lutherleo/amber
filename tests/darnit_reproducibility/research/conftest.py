"""Shared fixtures for the Amber research-shell tests (token-free)."""
from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
LORENZ_FX = REPO / "packages" / "darnit-reproducibility" / "examples" / "research" / "lorenz" / "fixtures"
SIR_FX = REPO / "packages" / "darnit-reproducibility" / "examples" / "research" / "sir" / "fixtures"


@pytest.fixture
def lorenz_capture():
    from darnit_reproducibility.ingest.witness import load
    return load(LORENZ_FX / "bundle.redacted.json", LORENZ_FX / "amber-pylibs.redacted.json")


@pytest.fixture
def sir_capture():
    from darnit_reproducibility.ingest.witness import load
    return load(SIR_FX / "bundle.redacted.json", SIR_FX / "amber-pylibs.redacted.json")


@pytest.fixture
def lorenz_bundle_paths():
    return LORENZ_FX / "bundle.redacted.json", LORENZ_FX / "amber-pylibs.redacted.json"

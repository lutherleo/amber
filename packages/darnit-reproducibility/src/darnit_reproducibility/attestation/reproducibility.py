"""Emit the reproducibility verdict as an in-toto statement (predicate v1).

Anchors the claim to the produced artifacts (subjects) and records both captures' git commits plus the
verdict, so "this result was independently reproduced" becomes a signable, publishable attestation —
the object later phases push to a transparency log / GUAC.
"""
from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import Any

from ..models import CaptureRecord, ReproducibilityVerdict

PREDICATE_TYPE = "https://darnit.dev/attestations/reproducibility/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def statement(original: CaptureRecord, reproduction: CaptureRecord,
              verdict: ReproducibilityVerdict) -> dict[str, Any]:
    """Build the in-toto statement. Subjects are the reproduced outputs (name + sha256)."""
    subjects = [
        {"name": a.name, "digest": {"sha256": (a.reproduction_sha256 or "").removeprefix("sha256:")}}
        for a in verdict.artifacts
        if a.reproduction_sha256
    ]
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "assessor": {
                "name": "darnit-reproducibility",
                "timestamp": datetime.now(UTC).isoformat(),
            },
            "original": {"commit": original.repo.commit, "command": original.command.cmd},
            "reproduction": {"commit": reproduction.repo.commit, "command": reproduction.command.cmd},
            "verdict": dataclasses.asdict(verdict),
        },
    }

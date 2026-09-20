"""Amber research shell — lock a paper's artifact into a verifiable state.

A thin layer over the existing Amber capture/verify pipeline that:

* records each captured run as a **research knowledge graph** (orion export format),
* keeps that graph **cross-referenced** to an orion **code graph** of the source,
* **cross-verifies** measured results against a paper's quantitative **claims**
  (deterministically, reusing ``analysis.compare``),
* packs a **portable artifact** future projects can build on, and
* exposes a **minimal Sonnet agent** that reads (never mutates) the graphs.

Reuses (never reimplements) ``capture.run``, ``ingest.witness.load``,
``analysis.compare.compare`` and ``generate.environment``. See
``specs``/the approved plan for the layered roadmap (Layer 1 = this module's
graph + claim-verify + agent over existing captures).
"""
from __future__ import annotations

__all__ = ["graph", "claims", "model", "verify", "artifact", "agent"]

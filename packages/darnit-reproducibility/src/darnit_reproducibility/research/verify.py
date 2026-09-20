"""Deterministic cross-verification: reproducibility (two runs) and claims (paper vs run).

No LLM here — this is the trustworthy half of the system. Reuses
``analysis.compare.compare`` for run-vs-run and ``research.claims.check`` for
run-vs-paper-claim, then records the verdicts into the research graph.
"""
from __future__ import annotations

from typing import Any

from ..analysis.compare import compare
from ..models import CaptureRecord
from . import model
from .claims import Claim, check
from .graph import ResearchGraph


def verify_reproducibility(
    graph: ResearchGraph,
    baseline_uid: str,
    baseline_rec: CaptureRecord,
    candidate_uid: str,
    candidate_rec: CaptureRecord,
    *,
    original_dir: str | None = None,
    reproduction_dir: str | None = None,
    rel_tol: float = 1e-9,
) -> tuple[str, str]:
    """Compare two captured runs and write a reproducibility Verdict. Returns (level, verdict_uid)."""
    verdict = compare(
        baseline_rec,
        candidate_rec,
        original_dir=original_dir,
        reproduction_dir=reproduction_dir,
        rel_tol=rel_tol,
    )
    v_uid = model.add_reproducibility_verdict(graph, baseline_uid, candidate_uid, verdict)
    return verdict.level, v_uid


def verify_claims(
    graph: ResearchGraph,
    paper_uid: str,
    run_uid: str,
    rec: CaptureRecord | None = None,
    *,
    extra_metrics: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    """Check every claim of ``paper_uid`` against a run's measured metrics.

    Metric sources, in precedence order: ``extra_metrics`` > the run's stored
    ``Result`` nodes (authoritative — they include any ingest-time custom metrics) >
    metrics recomputed from ``rec`` (a fallback when a run carries no stored
    Results). Returns one record per claim: ``{metric, comparator, value, level,
    detail, verdict_uid}`` and writes a claim Verdict per claim into the graph.
    """
    metrics: dict[str, float] = {}
    if rec is not None:
        metrics.update(model.measured_metrics(rec))
    # Stored Results override capture-recomputed values and add ingest-time metrics.
    for res_uid in graph.neighbors(run_uid, "MEASURED"):
        node = graph.node(res_uid)
        if node and isinstance(node.get("value"), (int, float)):
            metrics[node["metric"]] = float(node["value"])
    metrics.update(extra_metrics or {})

    out: list[dict[str, Any]] = []
    for claim_uid in graph.neighbors(paper_uid, "HAS_CLAIM"):
        node = graph.node(claim_uid)
        if node is None:
            continue
        claim = Claim(
            metric=node["metric"],
            comparator=node["comparator"],
            value=float(node["value"]),
            tolerance=float(node.get("tolerance") or 0.0),
            unit=node.get("unit"),
        )
        level, detail = check(claim, metrics)
        v_uid = model.add_claim_verdict(graph, claim_uid, run_uid, level, detail, claim.metric)
        out.append(
            {
                "metric": claim.metric,
                "comparator": claim.comparator,
                "value": claim.value,
                "level": level,
                "detail": detail,
                "verdict_uid": v_uid,
            }
        )
    return out

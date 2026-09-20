"""Building the graph from a real CaptureRecord, and deterministic verification."""
from __future__ import annotations

import pytest

from darnit_reproducibility.research import model, verify
from darnit_reproducibility.research.claims import parse_claim
from darnit_reproducibility.research.graph import ResearchGraph


@pytest.mark.unit
def test_measured_metrics_from_real_capture(lorenz_capture):
    m = model.measured_metrics(lorenz_capture)
    assert m["exit_code"] == 0.0
    assert m["output_count"] >= 1.0
    assert m["python_minor"] >= 3.10  # 3.12.x
    assert m["dependency_count"] >= 1.0


@pytest.mark.unit
def test_add_run_builds_full_subgraph(lorenz_capture):
    g = ResearchGraph("proj")
    run_uid = model.add_run(g, "proj", "r1", lorenz_capture,
                            experiment_path="examples/research/lorenz/experiment.py")
    # Run + its satellites and edges exist.
    assert g.node(run_uid)["run_id"] == "r1"
    assert g.neighbors(run_uid, "RAN_IN")            # Environment
    assert g.neighbors(run_uid, "USED_DEP")          # Dependencies
    assert g.neighbors(run_uid, "PRODUCED")          # Artifact(s)
    assert g.neighbors(run_uid, "MEASURED")          # Result(s)
    # Project -> run edge.
    proj = g.nodes("ResearchProject")[0]
    assert run_uid in g.neighbors(proj["uid"], "HAS_RUN")
    # Artifact carries the real output digest.
    art = g.node(g.neighbors(run_uid, "PRODUCED")[0])
    assert art["path"] and art["sha256"]


@pytest.mark.unit
def test_verify_claims_writes_verdicts(lorenz_capture):
    g = ResearchGraph("proj")
    _, paper_uid = model.seed_project(
        g, "proj", paper_title="P", paper_url="u",
        claims=[parse_claim("exit_code<=0"), parse_claim("memory_gb>=9999")],
    )
    run_uid = model.add_run(g, "proj", "r1", lorenz_capture)
    results = verify.verify_claims(g, paper_uid, run_uid, lorenz_capture)

    by_metric = {r["metric"]: r["level"] for r in results}
    assert by_metric["exit_code"] == "REPRODUCED"
    assert by_metric["memory_gb"] == "NOT_REPRODUCED"  # unmet claim surfaces
    # A claim Verdict node exists per claim and links back to the run.
    verdicts = [v for v in g.nodes("Verdict") if v.get("kind") == "claim"]
    assert len(verdicts) == 2
    checked_runs = {e["end"] for e in g.edges("CHECKS") if e["props"].get("role") == "run"}
    assert run_uid in checked_runs


@pytest.mark.unit
def test_verify_claims_uses_stored_ingest_time_metrics(lorenz_capture):
    """A custom metric supplied at ingest must be checkable, not just capture-derived ones."""
    g = ResearchGraph("proj")
    _, paper_uid = model.seed_project(
        g, "proj", paper_title="P", paper_url="u", claims=[parse_claim("verify_seconds<=0.59")],
    )
    # verify_seconds is NOT a capture-derived metric; it arrives as an ingest extra.
    run_uid = model.add_run(g, "proj", "r1", lorenz_capture, extra_metrics={"verify_seconds": 0.42})
    results = verify.verify_claims(g, paper_uid, run_uid)  # note: no rec passed
    assert {r["metric"]: r["level"] for r in results}["verify_seconds"] == "REPRODUCED"


@pytest.mark.unit
def test_verify_reproducibility_identical_is_bit_for_bit(lorenz_capture):
    g = ResearchGraph("proj")
    a = model.add_run(g, "proj", "a", lorenz_capture)
    b = model.add_run(g, "proj", "b", lorenz_capture)
    level, v_uid = verify.verify_reproducibility(g, a, lorenz_capture, b, lorenz_capture)
    assert level == "BIT_FOR_BIT"
    assert g.node(v_uid)["kind"] == "reproducibility"


@pytest.mark.unit
def test_verify_reproducibility_different_experiments_not_reproduced(lorenz_capture, sir_capture):
    g = ResearchGraph("proj")
    a = model.add_run(g, "proj", "lorenz", lorenz_capture)
    b = model.add_run(g, "proj", "sir", sir_capture)
    level, _ = verify.verify_reproducibility(g, a, lorenz_capture, b, sir_capture)
    assert level in ("NOT_REPRODUCED", "INCONCLUSIVE")

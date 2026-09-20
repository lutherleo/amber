"""Map Amber's ``CaptureRecord`` + paper claims + verdicts into research-graph nodes.

This is the only place that knows both the capture model
(``darnit_reproducibility.models``) and the graph schema
(``research.graph``). It reuses ``analysis.compare._real_outputs`` so "the files a
run produced" is defined in exactly one place.
"""
from __future__ import annotations

from typing import Any

from ..analysis.compare import _real_outputs, _used_versions
from ..models import CaptureRecord, ReproducibilityVerdict
from .claims import Claim
from .graph import ResearchGraph


def measured_metrics(rec: CaptureRecord) -> dict[str, float]:
    """Deterministic, always-available metrics for claim checking.

    Layer 1 uses generic capture-derived metrics (exit code, output count, python
    minor, dependency count, memory). A real paper artifact (Layer 2) emits its own
    metrics into ``result.json``; those are merged in by ``add_run`` when present.
    """
    metrics: dict[str, float] = {}
    if rec.command.exitcode is not None:
        metrics["exit_code"] = float(rec.command.exitcode)
    metrics["output_count"] = float(len(_real_outputs(rec)))
    metrics["dependency_count"] = float(len(rec.python_env.used_distributions))
    ver = rec.python_env.version or ""
    parts = ver.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        metrics["python_minor"] = float(f"{parts[0]}.{parts[1]}")
    mem = (rec.hardware or {}).get("memory_gb")
    if isinstance(mem, (int, float)):
        metrics["memory_gb"] = float(mem)
    return metrics


def _environment_props(rec: CaptureRecord) -> dict[str, Any]:
    num = rec.numerical or {}
    hw = rec.hardware or {}
    return {
        "os": rec.system.os,
        "python_version": rec.python_env.version,
        "platform": rec.python_env.platform,
        "blas": (num.get("blas") or {}).get("name"),
        "pythonhashseed": num.get("pythonhashseed"),
        "thread_env": num.get("thread_env"),
        "cpu": (hw.get("cpu") or {}).get("model") if isinstance(hw.get("cpu"), dict) else hw.get("cpu"),
        "memory_gb": hw.get("memory_gb"),
    }


def seed_project(
    graph: ResearchGraph,
    project: str,
    *,
    paper_title: str | None = None,
    paper_url: str | None = None,
    claims: list[Claim] | None = None,
) -> tuple[str, str | None]:
    """Create the ResearchProject (+ optional Paper and its Claims). Returns (project_uid, paper_uid)."""
    project_uid = graph.add_node("ResearchProject", project, {"name": project})
    paper_uid: str | None = None
    if paper_title or paper_url:
        paper_uid = graph.add_node(
            "Paper", paper_url or paper_title or project, {"title": paper_title, "url": paper_url}
        )
        graph.add_edge("ABOUT", project_uid, paper_uid)
        for c in claims or []:
            claim_uid = graph.add_node(
                "Claim", f"{paper_uid}:{c.metric}:{c.comparator}:{c.value}", c.as_props()
            )
            graph.add_edge("HAS_CLAIM", paper_uid, claim_uid)
    return project_uid, paper_uid


def add_run(
    graph: ResearchGraph,
    project: str,
    run_id: str,
    rec: CaptureRecord,
    *,
    experiment_path: str | None = None,
    extra_metrics: dict[str, float] | None = None,
) -> str:
    """Write a Run and all its satellites (Environment, Deps, Artifacts, Results)."""
    project_uid = graph.add_node("ResearchProject", project, {"name": project})
    run_uid = graph.add_node(
        "Run",
        run_id,
        {
            "run_id": run_id,
            "cmd": rec.command.cmd,
            "exit_code": rec.command.exitcode,
            "python_version": rec.python_env.version,
            "platform": rec.python_env.platform,
            "commit": rec.repo.commit,
            "branch": rec.repo.branch,
            "collection_type": rec.collection_type,
            "code_ref": {"file_path": experiment_path} if experiment_path else None,
        },
    )
    graph.add_edge("HAS_RUN", project_uid, run_uid)

    env_uid = graph.add_node("Environment", run_id, _environment_props(rec))
    graph.add_edge("RAN_IN", run_uid, env_uid)

    for name, version in _used_versions(rec).items():
        dep_uid = graph.add_node("Dependency", f"{name}@{version}", {"name": name, "version": version})
        graph.add_edge("USED_DEP", run_uid, dep_uid)

    for path, sha in _real_outputs(rec).items():
        art_uid = graph.add_node("Artifact", f"{run_id}:{path}", {"path": path, "sha256": sha})
        graph.add_edge("PRODUCED", run_uid, art_uid)

    metrics = measured_metrics(rec)
    metrics.update(extra_metrics or {})
    for metric, value in metrics.items():
        res_uid = graph.add_node("Result", f"{run_id}:{metric}", {"metric": metric, "value": value})
        graph.add_edge("MEASURED", run_uid, res_uid)

    return run_uid


def add_reproducibility_verdict(
    graph: ResearchGraph, baseline_run_uid: str, candidate_run_uid: str, verdict: ReproducibilityVerdict
) -> str:
    """Record a two-run reproducibility verdict (from analysis.compare)."""
    key = f"repro:{baseline_run_uid[:12]}:{candidate_run_uid[:12]}"
    v_uid = graph.add_node(
        "Verdict",
        key,
        {
            "kind": "reproducibility",
            "level": verdict.level,
            "summary": verdict.summary,
            "reproduction_rate": verdict.reproduction_rate,
            "discrepancies": verdict.discrepancies,
        },
    )
    graph.add_edge("VERIFIED_AGAINST", v_uid, baseline_run_uid, {"role": "baseline"})
    graph.add_edge("VERIFIED_AGAINST", v_uid, candidate_run_uid, {"role": "candidate"})
    return v_uid


def add_claim_verdict(
    graph: ResearchGraph, claim_uid: str, run_uid: str, level: str, detail: str, metric: str
) -> str:
    """Record a claim-vs-measured verdict."""
    key = f"claim:{run_uid[:12]}:{metric}"
    v_uid = graph.add_node(
        "Verdict", key, {"kind": "claim", "level": level, "summary": detail, "metric": metric}
    )
    graph.add_edge("CHECKS", v_uid, claim_uid, {"role": "claim"})
    graph.add_edge("CHECKS", v_uid, run_uid, {"role": "run"})
    return v_uid

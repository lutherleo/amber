"""Project workspace + begin/run orchestration.

A project lives under ``.amber-research/<project>/``::

    project.json          manifest (name, paper, claims, experiment, code graph, runs)
    graph-research.json   the research knowledge graph
    graph-code.json       (optional) the orion code graph, or a path reference in the manifest
    runs/<run_id>/        the locked state: bundle.json + amber-pylibs.json

Layer 1 ``run`` ingests an already-captured bundle. Layer 2 (`container.py`) drives
``amber capture`` inside the per-project container; the graph-writing half is identical.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

from ..ingest.witness import load as load_capture
from . import model
from .claims import Claim
from .graph import ResearchGraph

DEFAULT_ROOT = ".amber-research"
_RESEARCH_GRAPH = "graph-research.json"
_MANIFEST = "project.json"


def workspace_dir(project: str, root: str | Path = DEFAULT_ROOT) -> Path:
    return Path(root) / project


def _research_graph_path(ws: Path) -> Path:
    return ws / _RESEARCH_GRAPH


def load_graph(project: str, root: str | Path = DEFAULT_ROOT) -> ResearchGraph:
    path = _research_graph_path(workspace_dir(project, root))
    return ResearchGraph.load(path) if path.exists() else ResearchGraph(project)


def load_manifest(project: str, root: str | Path = DEFAULT_ROOT) -> dict[str, Any]:
    path = workspace_dir(project, root) / _MANIFEST
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _save(ws: Path, graph: ResearchGraph, manifest: dict[str, Any]) -> None:
    ws.mkdir(parents=True, exist_ok=True)
    graph.save(_research_graph_path(ws))
    (ws / _MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def begin(
    project: str,
    *,
    paper_title: str | None = None,
    paper_url: str | None = None,
    claims: list[Claim] | None = None,
    experiment_path: str | None = None,
    code_graph_path: str | Path | None = None,
    root: str | Path = DEFAULT_ROOT,
) -> Path:
    """Initialize a project: workspace, manifest, seeded graph (Paper + Claims)."""
    ws = workspace_dir(project, root)
    graph = ResearchGraph(project)
    model.seed_project(
        graph, project, paper_title=paper_title, paper_url=paper_url, claims=claims or []
    )
    manifest = {
        "name": project,
        "created_at": _now(),
        "paper": {"title": paper_title, "url": paper_url},
        "claims": [c.as_props() for c in (claims or [])],
        "experiment_path": experiment_path,
        "code_graph_path": str(code_graph_path) if code_graph_path else None,
        "runs": [],
    }
    _save(ws, graph, manifest)
    return ws


def run_ingest(
    project: str,
    bundle_path: str | Path,
    pylibs_path: str | Path | None = None,
    *,
    run_id: str | None = None,
    experiment_path: str | None = None,
    extra_metrics: dict[str, float] | None = None,
    root: str | Path = DEFAULT_ROOT,
) -> str:
    """Ingest an existing capture bundle into the project as a locked Run."""
    ws = workspace_dir(project, root)
    graph = load_graph(project, root)
    manifest = load_manifest(project, root) or {"name": project, "runs": []}

    run_id = run_id or f"run-{int(time.time())}"
    rec = load_capture(bundle_path, pylibs_path)

    # Lock the raw capture under the project (immutable per-run record).
    run_dir = ws / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bundle_path, run_dir / "bundle.json")
    if pylibs_path and Path(pylibs_path).exists():
        shutil.copy2(pylibs_path, run_dir / "amber-pylibs.json")

    exp = experiment_path or manifest.get("experiment_path")
    model.add_run(graph, project, run_id, rec, experiment_path=exp, extra_metrics=extra_metrics)

    manifest.setdefault("runs", []).append(run_id)
    _save(ws, graph, manifest)
    return run_id


def save_graph(project: str, graph: ResearchGraph, root: str | Path = DEFAULT_ROOT) -> None:
    """Persist a mutated graph back to the project (e.g. after writing verdicts)."""
    ws = workspace_dir(project, root)
    manifest = load_manifest(project, root) or {"name": project, "runs": []}
    _save(ws, graph, manifest)


def load_capture_for_run(project: str, run_id: str, root: str | Path = DEFAULT_ROOT):
    """Reload the CaptureRecord for a locked run (needed by verify)."""
    run_dir = workspace_dir(project, root) / "runs" / run_id
    pylibs = run_dir / "amber-pylibs.json"
    return load_capture(run_dir / "bundle.json", pylibs if pylibs.exists() else None)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

"""ResearchGraph + CodeGraph + the cross-graph join."""
from __future__ import annotations

import pytest

from darnit_reproducibility.research.graph import CodeGraph, ResearchGraph, uid


@pytest.mark.unit
def test_uid_is_deterministic_and_scoped():
    assert uid("p", "Run", "r1") == uid("p", "Run", "r1")
    assert uid("p", "Run", "r1") != uid("p", "Run", "r2")
    assert uid("p", "Run", "r1") != uid("q", "Run", "r1")  # scan-scoped


@pytest.mark.unit
def test_add_node_merges_not_duplicates():
    g = ResearchGraph("proj")
    u1 = g.add_node("Run", "r1", {"a": 1})
    u2 = g.add_node("Run", "r1", {"b": 2})  # same natural key -> MERGE
    assert u1 == u2
    assert len(g.nodes("Run")) == 1
    node = g.node(u1)
    assert node["a"] == 1 and node["b"] == 2


@pytest.mark.unit
def test_add_edge_dedups_and_neighbors():
    g = ResearchGraph("proj")
    p = g.add_node("ResearchProject", "proj", {})
    r = g.add_node("Run", "r1", {})
    g.add_edge("HAS_RUN", p, r)
    g.add_edge("HAS_RUN", p, r)  # duplicate
    assert len(g.edges("HAS_RUN")) == 1
    assert g.neighbors(p, "HAS_RUN") == [r]
    assert g.neighbors(r, "HAS_RUN", direction="in") == [p]


@pytest.mark.unit
def test_save_load_round_trip(tmp_path):
    g = ResearchGraph("proj")
    p = g.add_node("ResearchProject", "proj", {"name": "proj"})
    r = g.add_node("Run", "r1", {"run_id": "r1", "exit_code": 0})
    g.add_edge("HAS_RUN", p, r)
    path = tmp_path / "graph.json"
    g.save(path)

    g2 = ResearchGraph.load(path)
    assert g2.scan_id == "proj"
    assert len(g2.nodes("Run")) == 1
    assert g2.node(r)["exit_code"] == 0
    assert g2.neighbors(p, "HAS_RUN") == [r]
    # Round-trips to the orion export shape.
    d = g2.to_dict()
    assert d["meta"]["kind"] == "research"
    assert d["nodes"][0]["labels"] == ["ResearchProject"]
    assert set(d["edges"][0]) == {"type", "start", "end", "props"}


def _tiny_code_graph() -> CodeGraph:
    nodes = [
        {"labels": ["CpgFile"], "props": {"uid": "f1", "file_path": "examples/research/lorenz/experiment.py"}},
        {"labels": ["CpgMethod"], "props": {"uid": "m1", "name": "main", "file_path": "examples/research/lorenz/experiment.py"}},
        {"labels": ["CpgMethod"], "props": {"uid": "m2", "name": "simulate", "file_path": "examples/research/lorenz/experiment.py"}},
        {"labels": ["CpgFile"], "props": {"uid": "f2", "file_path": "examples/research/sir/experiment.py"}},
    ]
    return CodeGraph("code-scan", nodes, [])


@pytest.mark.unit
def test_code_graph_resolve_path_by_suffix():
    code = _tiny_code_graph()
    file_uid, methods = code.resolve_path("experiment.py")  # bare name -> suffix match (longest wins)
    assert file_uid in ("f1", "f2")
    file_uid, methods = code.resolve_path("examples/research/lorenz/experiment.py")
    assert file_uid == "f1"
    assert methods == ["main", "simulate"]


@pytest.mark.unit
def test_join_links_runs_to_code_and_reports_unresolved():
    g = ResearchGraph("proj")
    g.add_node("Run", "r1", {"run_id": "r1", "code_ref": {"file_path": "examples/research/lorenz/experiment.py"}})
    g.add_node("Run", "r2", {"run_id": "r2", "code_ref": {"file_path": "nowhere/missing.py"}})
    report = g.join(_tiny_code_graph())

    assert "examples/research/lorenz/experiment.py" in report["resolved"]
    assert "nowhere/missing.py" in report["unresolved"]
    r1 = next(r for r in g.nodes("Run") if r["run_id"] == "r1")
    assert r1["code_ref"]["resolved"] is True
    assert r1["executed_methods"] == ["main", "simulate"]
    assert g.neighbors(r1["uid"], "EXECUTED_CODE") == ["code:code-scan:f1"]
    r2 = next(r for r in g.nodes("Run") if r["run_id"] == "r2")
    assert r2["code_ref"]["resolved"] is False

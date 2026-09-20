"""End-to-end orchestration (begin/run), portable artifact pack/unpack, and the agent."""
from __future__ import annotations

import pytest

from darnit_reproducibility.research import artifact as artifact_mod
from darnit_reproducibility.research import model
from darnit_reproducibility.research import run as run_mod
from darnit_reproducibility.research.agent import (
    SonnetResearchAgent,
    deterministic_answer,
    find_inconsistencies,
)
from darnit_reproducibility.research.claims import parse_claim
from darnit_reproducibility.research.graph import ResearchGraph


@pytest.mark.unit
def test_begin_then_run_ingest(tmp_path, lorenz_bundle_paths):
    bundle, pylibs = lorenz_bundle_paths
    root = tmp_path / "ws"
    run_mod.begin("demo", paper_title="P", paper_url="u",
                  claims=[parse_claim("exit_code<=0")], root=root)
    run_id = run_mod.run_ingest("demo", bundle, pylibs, run_id="r1",
                                experiment_path="examples/research/lorenz/experiment.py", root=root)
    assert run_id == "r1"

    ws = run_mod.workspace_dir("demo", root)
    assert (ws / "graph-research.json").exists()
    assert (ws / "runs" / "r1" / "bundle.json").exists()   # locked capture
    manifest = run_mod.load_manifest("demo", root)
    assert manifest["runs"] == ["r1"]

    g = run_mod.load_graph("demo", root)
    assert len(g.nodes("Run")) == 1
    assert g.nodes("Paper") and g.nodes("Claim")


@pytest.mark.unit
def test_artifact_pack_unpack_round_trip(tmp_path, lorenz_bundle_paths):
    bundle, pylibs = lorenz_bundle_paths
    root = tmp_path / "ws"
    run_mod.begin("demo", paper_title="P", paper_url="u", root=root)
    run_mod.run_ingest("demo", bundle, pylibs, run_id="r1", root=root)

    out = artifact_mod.pack("demo", tmp_path / "demo.tar.gz", root=root)
    assert out.exists()
    manifest = artifact_mod.read_manifest(out)
    assert manifest["project"] == "demo"
    assert manifest["graph_meta"]["kind"] == "research"

    dest_root = tmp_path / "restored"
    dest = artifact_mod.unpack(out, root=dest_root)
    assert (dest / "graph-research.json").exists()
    g = ResearchGraph.load(dest / "graph-research.json")
    assert len(g.nodes("Run")) == 1


@pytest.mark.unit
def test_unpack_rejects_path_traversal(tmp_path):
    import tarfile
    bad = tmp_path / "evil.tar.gz"
    (tmp_path / "payload").write_text("x")
    with tarfile.open(bad, "w:gz") as tar:
        tar.add(tmp_path / "payload", arcname="../escape.txt")
    with pytest.raises(ValueError, match="unsafe path"):
        artifact_mod.unpack(bad, root=tmp_path / "out")


@pytest.mark.unit
def test_find_inconsistencies_flags_unmet_and_unverified(lorenz_capture):
    from darnit_reproducibility.research import verify
    g = ResearchGraph("proj")
    _, paper_uid = model.seed_project(g, "proj", paper_title="P", paper_url="u",
                                      claims=[parse_claim("memory_gb>=9999")])
    run_uid = model.add_run(g, "proj", "r1", lorenz_capture)
    verify.verify_claims(g, paper_uid, run_uid, lorenz_capture)

    problems = find_inconsistencies(g)
    assert any("memory_gb" in p and "NOT_REPRODUCED" in p for p in problems)


@pytest.mark.unit
def test_agent_uses_responder_stub_and_sees_inconsistencies(lorenz_capture):
    from darnit_reproducibility.research import verify
    g = ResearchGraph("proj")
    _, paper_uid = model.seed_project(g, "proj", paper_title="P", paper_url="u",
                                      claims=[parse_claim("memory_gb>=9999")])
    run_uid = model.add_run(g, "proj", "r1", lorenz_capture)
    verify.verify_claims(g, paper_uid, run_uid, lorenz_capture)

    seen = {}

    def responder(prompt: str) -> str:
        seen["prompt"] = prompt
        return "stub-answer"

    agent = SonnetResearchAgent(responder=responder)
    assert agent.ask("what failed?", g) == "stub-answer"
    # The deterministic inconsistencies were handed to the model.
    assert "memory_gb" in seen["prompt"]


@pytest.mark.unit
def test_deterministic_answer_is_offline_and_lists_problems(lorenz_capture):
    from darnit_reproducibility.research import verify
    g = ResearchGraph("proj")
    _, paper_uid = model.seed_project(g, "proj", paper_title="P", paper_url="u",
                                      claims=[parse_claim("memory_gb>=9999")])
    run_uid = model.add_run(g, "proj", "r1", lorenz_capture)
    verify.verify_claims(g, paper_uid, run_uid, lorenz_capture)

    text = deterministic_answer(g)
    assert "Runs: 1" in text
    assert "memory_gb" in text

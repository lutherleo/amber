#!/usr/bin/env python
"""One-shot runner for the Amber Research Shell (Layer 1).

    uv run python run_amber_research.py

It exercises the whole Layer-1 loop on the committed example captures, with NO
Neo4j / Joern / container / API key required:

  1. `begin` a project seeded with the NDSS gittuf paper + demo claims.
  2. `run` (ingest) the committed redacted captures as locked runs.
  3. `join` the research graph to the committed orion CODE graph
     (knowledge/orion-graph.darnit-repro.json) and resolve Run -> CpgFile -> methods.
  4. deterministic `verify`: claims (paper vs run) AND reproducibility (run vs run).
  5. the Sonnet agent `ask` (deterministic fallback when ANTHROPIC_API_KEY is unset).

Then it runs the token-free test suite.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent
PKG = REPO / "packages" / "darnit-reproducibility"
EXAMPLES = PKG / "examples" / "research"
CODE_GRAPH = PKG / "knowledge" / "orion-graph.darnit-repro.json"

# (project-run id, example dir, experiment path as it appears in the code graph)
RUNS = [
    ("run-lorenz", "lorenz", "examples/research/lorenz/experiment.py"),
    ("run-lorenz-repro", "lorenz", "examples/research/lorenz/experiment.py"),
    ("run-sir", "sir", "examples/research/sir/experiment.py"),
    ("run-pysindy", "pysindy", "examples/research/pysindy/experiment.py"),
    ("run-sklearn", "sklearn_wine", "examples/research/sklearn_wine/experiment.py"),
]


def _rule(title: str) -> None:
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def demo() -> None:
    from darnit_reproducibility.research import run as run_mod
    from darnit_reproducibility.research import verify as verify_mod
    from darnit_reproducibility.research.agent import SonnetResearchAgent, deterministic_answer
    from darnit_reproducibility.research.claims import parse_claim
    from darnit_reproducibility.research.graph import CodeGraph

    root = Path(tempfile.mkdtemp(prefix="amber-research-"))
    project = "amber-demo"

    _rule("1. begin - seed project with the NDSS gittuf paper + claims")
    claims = [
        parse_claim("exit_code<=0"),
        parse_claim("output_count>=1"),
        parse_claim("python_minor>=3.10"),
        parse_claim("memory_gb>=9999"),  # deliberately unmet -> NOT_REPRODUCED demo
    ]
    run_mod.begin(
        project,
        paper_title="Rethinking Trust in Forge-Based Git Security (gittuf)",
        paper_url="https://www.ndss-symposium.org/ndss-paper/rethinking-trust-in-forge-based-git-security/",
        claims=claims,
        code_graph_path=CODE_GRAPH,
        root=root,
    )
    print(f"workspace: {root / project}   ({len(claims)} claims)")

    _rule("2. run - lock the committed example captures as runs")
    for run_id, example, exp_path in RUNS:
        fx = EXAMPLES / example / "fixtures"
        run_mod.run_ingest(
            project, fx / "bundle.redacted.json", fx / "amber-pylibs.redacted.json",
            run_id=run_id, experiment_path=exp_path, root=root,
        )
        print(f"  locked {run_id:18} from {example}")

    _rule("3. join - resolve runs against the orion CODE graph")
    graph = run_mod.load_graph(project, root)
    report = graph.join(CodeGraph.load(CODE_GRAPH))
    print(f"resolved {len(report['resolved'])} / {len(report['resolved']) + len(report['unresolved'])} runs to code")
    for r in graph.nodes("Run"):
        methods = r.get("executed_methods") or []
        if methods:
            print(f"  {r['run_id']}: {r['code_ref'].get('file_path')} -> {len(methods)} methods e.g. {methods[:5]}")
    run_mod.save_graph(project, graph, root)

    _rule("4a. verify claims - paper claims vs a run's measured metrics")
    paper_uid = graph.nodes("Paper")[0]["uid"]
    lorenz_uid = graph.add_node("Run", "run-lorenz", {})
    rec = run_mod.load_capture_for_run(project, "run-lorenz", root)
    for res in verify_mod.verify_claims(graph, paper_uid, lorenz_uid, rec):
        print(f"  claim {res['metric']:16} {res['level']:15} {res['detail']}")

    _rule("4b. verify reproducibility - run vs run (deterministic compare)")
    pairs = [("run-lorenz", "run-lorenz-repro"), ("run-lorenz", "run-sir")]
    for base, cand in pairs:
        b_uid = graph.add_node("Run", base, {})
        c_uid = graph.add_node("Run", cand, {})
        level, _ = verify_mod.verify_reproducibility(
            graph, b_uid, run_mod.load_capture_for_run(project, base, root),
            c_uid, run_mod.load_capture_for_run(project, cand, root),
        )
        print(f"  {base} vs {cand:18} -> {level}")
    run_mod.save_graph(project, graph, root)

    _rule("5. ask - Sonnet agent over the joined graph")
    graph = run_mod.load_graph(project, root)
    graph.join(CodeGraph.load(CODE_GRAPH))
    agent = SonnetResearchAgent()
    has_key = bool(__import__("os").environ.get("ANTHROPIC_API_KEY"))
    print(f"(ANTHROPIC_API_KEY {'set - calling Sonnet' if has_key else 'unset - deterministic fallback'})\n")
    print(agent.ask("Which claims did not reproduce, and what code did the lorenz run execute?", graph)
          if has_key else deterministic_answer(graph))

    print(f"\nresearch graph JSON: {run_mod.workspace_dir(project, root) / 'graph-research.json'}")


def run_tests() -> int:
    _rule("6. TEST SUITE (pytest)")
    return subprocess.run(
        ["uv", "run", "pytest", "tests/darnit_reproducibility/research/", "-q"], cwd=REPO
    ).returncode


def main() -> int:
    try:
        demo()
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"\n(demo failed: {type(exc).__name__}: {exc})")
    rc = run_tests()
    _rule("RESULT")
    print("All Amber research tests passed." if rc == 0 else f"Tests FAILED (exit {rc}).")
    return rc


if __name__ == "__main__":
    sys.exit(main())

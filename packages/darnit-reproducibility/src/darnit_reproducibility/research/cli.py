"""``amber research`` — the research-shell subcommand dispatcher.

    amber research begin <project> --paper-url <u> --claim m<=v -- <experiment...>
    amber research run   <project> --bundle bundle.json [--pylibs amber-pylibs.json]
    amber research verify <project> [--run <id>] [--baseline <id> --candidate <id>]
    amber research artifact <project> -o project.tar.gz
    amber research ask   <project> "which claims did not reproduce?"
"""
from __future__ import annotations

import argparse
import sys

from . import artifact as artifact_mod
from . import run as run_mod
from . import verify as verify_mod
from .agent import SonnetResearchAgent
from .claims import parse_claim
from .graph import CodeGraph, ResearchGraph


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="amber research", description="Amber research shell")
    parser.add_argument("--root", default=run_mod.DEFAULT_ROOT, help="workspace root (default .amber-research)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("begin", help="initialize a project (paper + claims)")
    b.add_argument("project")
    b.add_argument("--paper-title")
    b.add_argument("--paper-url")
    b.add_argument("--claim", action="append", default=[], help="metric=value±tol | metric<=value | metric>=value")
    b.add_argument("--experiment", help="experiment source path (for code-graph linking)")
    b.add_argument("--code-graph", help="path to an orion code-graph export JSON")
    b.add_argument("--from", dest="from_artifact", help="seed from a portable artifact instead")

    r = sub.add_parser("run", help="ingest a capture bundle as a locked run")
    r.add_argument("project")
    r.add_argument("--bundle", required=True)
    r.add_argument("--pylibs")
    r.add_argument("--run-id")
    r.add_argument("--experiment")
    r.add_argument("--metric", action="append", default=[], help="extra measured metric name=value")

    v = sub.add_parser("verify", help="cross-verify (reproducibility and/or claims)")
    v.add_argument("project")
    v.add_argument("--run", help="run id to claim-check against the paper")
    v.add_argument("--baseline", help="baseline run id (reproducibility)")
    v.add_argument("--candidate", help="candidate run id (reproducibility)")

    a = sub.add_parser("artifact", help="pack a portable artifact for future projects")
    a.add_argument("project")
    a.add_argument("-o", "--out", required=True)

    k = sub.add_parser("ask", help="ask the Sonnet agent about the graph")
    k.add_argument("project")
    k.add_argument("question")

    args = parser.parse_args(argv)
    root = args.root

    if args.cmd == "begin":
        return _cmd_begin(args, root)
    if args.cmd == "run":
        return _cmd_run(args, root)
    if args.cmd == "verify":
        return _cmd_verify(args, root)
    if args.cmd == "artifact":
        out = artifact_mod.pack(args.project, args.out, root=root)
        print(f"packed {args.project} -> {out}")
        return 0
    if args.cmd == "ask":
        graph = _joined_graph(args.project, root)
        print(SonnetResearchAgent().ask(args.question, graph))
        return 0
    return 2


def _cmd_begin(args: argparse.Namespace, root: str) -> int:
    if args.from_artifact:
        dest = artifact_mod.unpack(args.from_artifact, root=root)
        print(f"seeded project from artifact -> {dest}")
        return 0
    claims = [parse_claim(c) for c in args.claim]
    ws = run_mod.begin(
        args.project,
        paper_title=args.paper_title,
        paper_url=args.paper_url,
        claims=claims,
        experiment_path=args.experiment,
        code_graph_path=args.code_graph,
        root=root,
    )
    print(f"began project {args.project} at {ws} ({len(claims)} claim(s))")
    return 0


def _cmd_run(args: argparse.Namespace, root: str) -> int:
    extra = {}
    for m in args.metric:
        name, _, val = m.partition("=")
        extra[name.strip()] = float(val)
    run_id = run_mod.run_ingest(
        args.project, args.bundle, args.pylibs,
        run_id=args.run_id, experiment_path=args.experiment, extra_metrics=extra or None, root=root,
    )
    print(f"locked run {run_id} into {args.project}")
    return 0


def _cmd_verify(args: argparse.Namespace, root: str) -> int:
    graph = run_mod.load_graph(args.project, root)
    did = False
    if args.baseline and args.candidate:
        base_rec = run_mod.load_capture_for_run(args.project, args.baseline, root)
        cand_rec = run_mod.load_capture_for_run(args.project, args.candidate, root)
        base_uid = graph.add_node("Run", args.baseline, {})  # resolve existing uid
        cand_uid = graph.add_node("Run", args.candidate, {})
        level, _ = verify_mod.verify_reproducibility(graph, base_uid, base_rec, cand_uid, cand_rec)
        print(f"reproducibility {args.baseline} vs {args.candidate}: {level}")
        did = True
    if args.run:
        papers = graph.nodes("Paper")
        if not papers:
            print("no paper/claims to verify against", file=sys.stderr)
        else:
            rec = run_mod.load_capture_for_run(args.project, args.run, root)
            run_uid = graph.add_node("Run", args.run, {})
            results = verify_mod.verify_claims(graph, papers[0]["uid"], run_uid, rec)
            for res in results:
                print(f"claim {res['metric']}: {res['level']} — {res['detail']}")
            did = True
    if not did:
        print("nothing to verify: pass --run <id> and/or --baseline <id> --candidate <id>", file=sys.stderr)
        return 2
    run_mod.save_graph(args.project, graph, root)
    return 0


def _joined_graph(project: str, root: str) -> ResearchGraph:
    graph = run_mod.load_graph(project, root)
    manifest = run_mod.load_manifest(project, root)
    code_path = manifest.get("code_graph_path")
    if code_path:
        try:
            graph.join(CodeGraph.load(code_path))
        except OSError:
            pass
    return graph


if __name__ == "__main__":
    sys.exit(main())

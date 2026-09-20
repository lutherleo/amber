#!/usr/bin/env python3
"""Build + persist an Orion code graph WITHOUT the discover/verify fleet (zero Claude tokens).

Two modes:
  reference : thin wrapper over graph_build.build(...) -- keeps Orion's structural EntryPoints,
              auto-or-explicit language. Used for our own codebases (Go / Python / C harness) as a
              queryable anti-hallucination reference graph.
  kernel    : inlines graph_build.build's stream pipeline so we can (1) SEED real syscall handlers
              as EntryPoints via normalize(entry_funcs=...), and (2) DROP the structural EntryPoints
              that would otherwise swamp a scoped kernel graph and make reachability/centrality noise.

Why inline for kernel mode: graph_build.build() never exposes `entry_funcs`, and the structural
EntryPoint drop has to happen on the in-memory Batch BEFORE reachability runs. reachability/centrality
are pure-over-Batch and are GC'd when build() returns, so post-build tagging is impossible (see plan
B1/B2). This mirrors graph_build.build() lines ~118-193; keep it in sync if that pipeline changes.

Usage:
  build_graph_only.py reference <repo> --scan-id ID [--language FRONTEND] [--force-parse]
  build_graph_only.py kernel    <repo> --scan-id ID --language c [--force-parse]
                                 [--skip-centrality] [--centrality-k N] [--run-pathfind]
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

# scripts/ lives under the Orion repo root; make `import orion.*` work when run directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

# Curated kernel syscall-handler seeds (short names, matched against CpgMethod.name).
# These are the BFS sources that make hop_distance/centrality meaningful. If any fail to resolve,
# the gate below fails loudly -- a missing seed means the terrain map has no real entry point.
KERNEL_SEEDS: list[str] = [
    # bpf (kernel/bpf/syscall.c command handlers + dispatch). NOTE: the freeze handler is named
    # `map_freeze`, NOT `bpf_map_freeze` (verified against v6.17 source).
    "map_update_elem", "map_delete_elem", "map_lookup_elem", "map_freeze",
    "bpf_prog_load", "bpf_prog_attach", "bpf_prog_detach", "__sys_bpf",
    # nft (net/netfilter/nf_tables_api.c)
    "nf_tables_newtable", "nf_tables_deltable", "nf_tables_newrule", "nf_tables_delrule",
    "nf_tables_newset", "nf_tables_delsetelem", "nf_tables_commit", "nf_tables_abort",
    # sched (net/sched/sch_api.c + cls_api.c)
    "tc_modify_qdisc", "tc_get_qdisc", "tc_ctl_tclass", "tc_new_tfilter", "tc_del_tfilter",
]


def _on_event(ev: dict) -> None:
    """Minimal progress printer (build phase only; no run-log file needed for a graph-only build)."""
    detail = ev.get("detail", "")
    print(f"  [{ev.get('phase')}/{ev.get('event')}] {detail}", flush=True)


def _maybe_force_parse(repo: str, force: bool) -> None:
    """ensure_cpg() silently reuses <repo>/cpg.bin with no staleness check. --force-parse deletes it
    so an iterated file set actually re-parses (plan M6)."""
    cpg = Path(repo) / "cpg.bin"
    if force and cpg.exists():
        cpg.unlink()
        print(f"  [force-parse] removed stale {cpg}")


def run_reference(args: argparse.Namespace) -> int:
    from orion import graph_build

    print(f"== reference graph: {args.repo} (scan_id={args.scan_id}, language={args.language or 'auto'})")
    _maybe_force_parse(args.repo, args.force_parse)
    scan_id = graph_build.build(
        args.repo, args.language, _on_event,
        stream=True, scan_id=args.scan_id,
    )
    print(f"== done: scan_id={scan_id}")
    return 0


def run_kernel(args: argparse.Namespace) -> int:
    # Inlined stream pipeline (mirrors graph_build.build) so we can seed + prune EntryPoints.
    from orion.graph import deps, joern_adapter, pathfind, persist, profiles, reachability
    from orion.graph import stream_build

    repo, scan_id = args.repo, args.scan_id
    print(f"== kernel graph: {repo} (scan_id={scan_id}, language={args.language})")
    _maybe_force_parse(repo, args.force_parse)

    frontend, display_language = joern_adapter.resolve_language(repo, args.language)
    profile = profiles.select_profile(repo, display_language)

    t0 = time.monotonic()
    cpg_bin = joern_adapter.ensure_cpg(repo, frontend)
    # ensure_cpg parses into a TEMP dir (cleaned on reboot). Stage a copy at <repo>/cpg.bin so the
    # next run reuses it (ensure_cpg checks repo/cpg.bin first) and skips the ~150s kernel re-parse.
    # --force-parse already removed any stale one before this. Cheap; never fatal.
    import shutil
    repo_cpg = Path(repo) / "cpg.bin"
    if Path(cpg_bin).resolve() != repo_cpg.resolve():
        try:
            shutil.copy2(cpg_bin, repo_cpg)
            print(f"  [parse] staged cpg.bin -> {repo_cpg} (reused on next run)")
        except OSError as e:
            print(f"  [parse] could not stage cpg.bin ({e}); next run will re-parse")
    print(f"  [parse] cpg.bin ready: {cpg_bin} ({time.monotonic() - t0:.1f}s)")

    work = Path(tempfile.mkdtemp(prefix="orion_kernel_"))
    envelope = stream_build.build_envelope(str(cpg_bin), work, profile, queue_size=args.queue_size)

    dependencies = deps.parse_dependencies(repo)
    # Normalize WITHOUT entry_funcs. normalize() emits a structural EntryPoint (kind="handler") for
    # every call-graph root FIRST and adds it to its own seen-set, so passing our seeds there makes
    # normalize SKIP any seed that is also a structural root (e.g. __sys_bpf, bpf_prog_load, whose
    # callers live outside the checkout) as a "duplicate" -- then our prune deletes the handler copy,
    # leaving the seed with NO EntryPoint at all. We instead seed ourselves below, after pruning.
    batch = joern_adapter.normalize(
        envelope, scan_id, language=display_language, dependencies=dependencies)

    # --- Drop ALL structural EntryPoints (kind="handler") + their ENTERS_AT edges (plan B2). ---
    # In a scoped kernel subtree, _entry_method_ids_from marks 30-60% of functions as structural
    # entries (every _ops callback + every function whose caller is outside the checkout). Every
    # ENTERS_AT is a BFS source in reachability, so leaving them makes reachable_from_entry ~ true
    # everywhere and hop_distance/centrality meaningless. We keep ZERO structural entries and add
    # only our curated seeds as sources.
    dropped_uids = {
        p["uid"] for (label, p) in batch.nodes
        if label == "EntryPoint" and "uid" in p
    }
    before_n, before_e = len(batch.nodes), len(batch.edges)
    batch.nodes = [(label, p) for (label, p) in batch.nodes if label != "EntryPoint"]
    batch.edges = [e for e in batch.edges if e[0] != "ENTERS_AT"]
    print(f"  [prune] dropped {len(dropped_uids)} structural EntryPoints "
          f"(nodes {before_n}->{len(batch.nodes)}, edges {before_e}->{len(batch.edges)})")

    # --- Self-seed: add a kind="http" EntryPoint + ENTERS_AT for every seed present as a first-party
    #     CpgMethod in this batch. Bypasses normalize's dedup entirely (the bug above). Matches on the
    #     method's short `name`; binds the method's real full_name so ENTERS_AT resolves. ---
    from orion.graph.schema import synthesize_uid
    methods_by_name: dict[str, list[str]] = {}
    for (label, p) in batch.nodes:
        if label == "CpgMethod" and not p.get("is_external"):
            methods_by_name.setdefault(p.get("name"), []).append(p.get("full_name"))
    resolved, missing = [], []
    for seed in KERNEL_SEEDS:
        fulls = methods_by_name.get(seed)
        if not fulls:
            missing.append(seed)
            continue
        full = fulls[0]  # first-party; kernel names are unique per subsystem in practice
        uid = synthesize_uid(scan_id, "ENTRYPOINT", full, 0, 0, seed)
        batch.emit_node("EntryPoint",
                        {"uid": uid, "kind": "http", "method_full_name": full, "exposure": "exposed"})
        batch.emit_edge("ENTERS_AT", "EntryPoint", {"uid": uid}, "CpgMethod", {"full_name": full})
        resolved.append(seed)

    # --- GATE (M7): report seed resolution. Missing nft/sched seeds are EXPECTED when scanning one
    #     subsystem in isolation (rehearsal on kernel/bpf); they resolve in the full build. ---
    print(f"  [gate] seeds resolved: {len(resolved)}/{len(KERNEL_SEEDS)}  ({', '.join(resolved)})")
    if missing:
        print(f"  [gate] !! seeds NOT in this graph (expected for out-of-scope subsystems): "
              f"{', '.join(missing)}", file=sys.stderr)
        if not resolved:
            print("  [gate] aborting: NO seeds resolved -> terrain map would have no entry points.",
                  file=sys.stderr)
            if not args.allow_missing_seeds:
                return 2
        elif not args.allow_missing_seeds and len(missing) > len(resolved):
            print("  [gate] aborting: more seeds missing than resolved. Re-run with "
                  "--allow-missing-seeds if this is an intentional single-subsystem scan.",
                  file=sys.stderr)
            return 2

    # --- reachability (BFS from seeded entries) ---
    reach = reachability.tag_reachability(batch)
    print(f"  [reachability] {reach['reached_methods']}/{reach['total_methods']} methods, "
          f"{reach['reached_calls']}/{reach['total_calls']} calls reachable from a seed")

    # --- centrality (optional; hard module constant _CENTRALITY_SAMPLE_K=500 has no env knob) ---
    if args.skip_centrality:
        print("  [centrality] skipped (--skip-centrality); derive Layer-4 chokepoints from in-degree")
    else:
        if args.centrality_k is not None:
            reachability._CENTRALITY_SAMPLE_K = args.centrality_k  # noqa: SLF001 -- intentional tune
            print(f"  [centrality] sample K set to {args.centrality_k}")
        cent = reachability.tag_centrality(batch)
        print(f"  [centrality] {cent['nodes']} reachable nodes, max betweenness {cent['max_centrality']:.3f}")

    # --- pathfind (CandidateFlow) is noise for cartography; skip unless asked ---
    if args.run_pathfind:
        flows = pathfind.pathfind(batch, profile)
        print(f"  [pathfind] {flows['flows']} candidate flows")

    summary = persist.persist(batch)
    print(f"  [persist] {len(batch.nodes)} nodes, {len(batch.edges)} edges -> scan_id={scan_id}")
    print(f"== done in {time.monotonic() - t0:.1f}s "
          f"(summary keys: {list(summary) if isinstance(summary, dict) else summary})")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build+persist an Orion graph with no discover/verify (0 tokens).")
    sub = p.add_subparsers(dest="mode", required=True)

    ref = sub.add_parser("reference", help="thin build() wrapper (keeps structural entrypoints)")
    ref.add_argument("repo")
    ref.add_argument("--scan-id", required=True)
    ref.add_argument("--language", default=None, help="Joern frontend id; omit to auto-detect")
    ref.add_argument("--force-parse", action="store_true")

    ker = sub.add_parser("kernel", help="inlined pipeline: seed handlers + drop structural entries")
    ker.add_argument("repo")
    ker.add_argument("--scan-id", required=True)
    ker.add_argument("--language", default="c", help="C frontend id (confirm via joern-parse --list-languages)")
    ker.add_argument("--force-parse", action="store_true")
    ker.add_argument("--queue-size", type=int, default=64)
    ker.add_argument("--skip-centrality", action="store_true")
    ker.add_argument("--centrality-k", type=int, default=None, help="lower networkx betweenness sample K")
    ker.add_argument("--run-pathfind", action="store_true", help="also emit CandidateFlow nodes (noise)")
    ker.add_argument("--allow-missing-seeds", action="store_true", help="persist even if some seeds didn't resolve")

    args = p.parse_args(argv)
    if not os.path.isdir(args.repo):
        print(f"not a directory: {args.repo}", file=sys.stderr)
        return 2
    if args.mode == "reference":
        return run_reference(args)
    if args.mode == "kernel":
        return run_kernel(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())

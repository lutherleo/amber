#!/usr/bin/env python3
"""Terrain report over an Orion kernel graph -- the cartographer's map for RaceFuzz (Phase 2).

READ-ONLY. Emits four layers as markdown (+ optional JSON) for a kernel scan_id whose EntryPoints
are the seeded syscall handlers (built by build_graph_only.py kernel mode):

  L1  entry -> internal reach   : from each seeded handler, the funcs it reaches, ending at
                                  free/RCU/refcount sinks. Uses a PURE call-graph walk
                                  (CONTAINS_CALL|RESOLVES_TO), NOT raw hop_distance (which mixes
                                  FLOWS_TO and double-counts method->call->method; see plan M3).
  L2  shared-object op-sets     : functions grouped by the object they touch (map/prog/table/qdisc/
                                  filter), split into {modify, free, read} by call-name patterns.
  L3  lock/RCU coverage         : per method that frees/mutates a shared object, whether it also
                                  contains a guard call (spin_lock/mutex_lock/rcu_read_lock/...).
                                  Heuristic: "any guard in the method", NOT "guard held at the call"
                                  (no CFG/lock-scope in the CPG). Flags UNGUARDED free/mutate methods.
  L4  chokepoints               : highest-centrality funcs (or call in-degree if centrality skipped).

Usage:
  python terrain_report.py --scan-id kernel-full [--md out.md] [--json out.json] [--depth 8]
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable

URI = "bolt://localhost:7688"
AUTH = ("neo4j", "orion_dev_changeme")

# Call names that FREE / retire a shared kernel object (a use-after-free half of a race).
# nft/tcf patterns are kept specific (destroy/release/deactivate/put) so lookups aren't mislabeled.
FREE_PATTERNS = ["kfree", "kvfree", "kfree_rcu", "call_rcu", "free_percpu", "bpf_map_put",
                 "bpf_map_free", "bpf_prog_put", "module_put", "put_net",
                 "nft_deactivate", "nft_destroy", "nft_set_destroy", "nft_rule_destroy",
                 "nft_chain_destroy", "nft_table_destroy", "nf_tables_chain_destroy",
                 "qdisc_put", "qdisc_destroy", "qdisc_free", "tcf_destroy", "tcf_block_put",
                 "tcf_chain_put", "tcf_proto_destroy", "refcount_dec", "refcount_set",
                 "kmem_cache_free"]
# Call names that MODIFY a shared object in place.
MODIFY_PATTERNS = ["_update_elem", "_delete_elem", "list_add", "list_del", "rhashtable_insert",
                   "rhashtable_remove", "hlist_add", "hlist_del", "rcu_assign_pointer",
                   "atomic_set", "memcpy", "copy_from_user"]
# Call names that READ / look up a shared object.
READ_PATTERNS = ["_lookup_elem", "lookup", "rhashtable_lookup", "rcu_dereference", "list_for_each",
                 "atomic_read", "copy_to_user"]
# Guard calls that (if present in a method) suggest some synchronization.
GUARD_PATTERNS = ["spin_lock", "spin_unlock", "mutex_lock", "mutex_unlock", "rcu_read_lock",
                  "rcu_read_unlock", "synchronize_rcu", "write_lock", "read_lock", "down_write",
                  "down_read", "local_bh_disable", "preempt_disable", "raw_spin_lock"]


def _wait(driver, tries=45, delay=2):
    for _ in range(tries):
        try:
            with driver.session() as s:
                s.run("RETURN 1").single()
            return True
        except (ServiceUnavailable, OSError):
            time.sleep(delay)
    return False


def _q(session, cypher, **params):
    return list(session.run(cypher, **params))


def layer1_reach(s, sid, depth):
    """From each seeded EntryPoint, count reachable methods and list the free/RCU sinks it can reach
    via a pure call-graph walk (CONTAINS_CALL then RESOLVES_TO), bounded by `depth`."""
    seeds = _q(s, "MATCH (e:EntryPoint {scan_id:$sid}) RETURN e.method_full_name AS m ORDER BY m", sid=sid)
    out = []
    sink_or = " OR ".join([f"c.name CONTAINS '{p}'" for p in FREE_PATTERNS])
    for row in seeds:
        m = row["m"]
        # Reachable free/RCU sink CALLS within `depth` call-graph hops of this entry method.
        cypher = (
            "MATCH (entry:CpgMethod {scan_id:$sid, full_name:$m}) "
            f"MATCH p = (entry)-[:CONTAINS_CALL|RESOLVES_TO*1..{depth}]->(c:CpgCall) "
            f"WHERE ({sink_or}) AND c.scan_id=$sid "
            "RETURN DISTINCT c.name AS sink, min(length(p)) AS hops "
            "ORDER BY hops, sink LIMIT 25"
        )
        try:
            sinks = _q(s, cypher, sid=sid, m=m)
        except Exception as exc:  # noqa: BLE001 -- a too-deep pattern can time out; report + continue
            sinks = []
            print(f"    (L1 walk for {m} failed: {exc.__class__.__name__})", file=sys.stderr)
        out.append({"entry": m,
                    "sinks": [{"sink": r["sink"], "hops": r["hops"]} for r in sinks]})
    return out


def _op_sets(s, sid, patterns):
    """Distinct callee names present in the graph matching any of `patterns`, with count."""
    ors = " OR ".join([f"c.name CONTAINS '{p}'" for p in patterns])
    rows = _q(s, f"MATCH (c:CpgCall {{scan_id:$sid}}) WHERE {ors} "
                 "RETURN c.name AS name, count(*) AS n ORDER BY n DESC LIMIT 40", sid=sid)
    return [{"name": r["name"], "count": r["n"]} for r in rows]


def layer2_opsets(s, sid):
    return {"free": _op_sets(s, sid, FREE_PATTERNS),
            "modify": _op_sets(s, sid, MODIFY_PATTERNS),
            "read": _op_sets(s, sid, READ_PATTERNS)}


def layer3_locks(s, sid, limit=60):
    """Methods that contain a free/mutate call; flag those with NO guard call present. A guard-free
    free/mutate method is a prime race window (no synchronization visible in the method body)."""
    free_or = " OR ".join([f"cc.name CONTAINS '{p}'" for p in (FREE_PATTERNS + MODIFY_PATTERNS)])
    guard_or = " OR ".join([f"g.name CONTAINS '{p}'" for p in GUARD_PATTERNS])
    # Exclude c2cpg synthetic / macro-collapsed method names (<operator>, <global>,
    # BPF_CALL_N<duplicate>M) -- they carry no reliable file/body attribution (plan M2 noise).
    cypher = (
        "MATCH (m:CpgMethod {scan_id:$sid})-[:CONTAINS_CALL]->(cc:CpgCall) "
        f"WHERE ({free_or}) AND NOT m.is_external AND NOT m.full_name CONTAINS '<' "
        "WITH m, collect(DISTINCT cc.name) AS ops "
        "OPTIONAL MATCH (m)-[:CONTAINS_CALL]->(g:CpgCall) "
        f"WHERE {guard_or} "
        "WITH m, ops, collect(DISTINCT g.name) AS guards "
        "RETURN m.full_name AS method, m.file_path AS file, ops, guards, "
        "       size(guards) AS nguards "
        "ORDER BY nguards ASC, method LIMIT $limit"
    )
    rows = _q(s, cypher, sid=sid, limit=limit)
    return [{"method": r["method"], "file": r["file"], "ops": r["ops"],
             "guards": r["guards"], "unguarded": r["nguards"] == 0} for r in rows]


def layer4_chokepoints(s, sid, limit=30):
    """Top-centrality methods; fall back to call in-degree (RESOLVES_TO count) if centrality is 0
    everywhere (i.e. --skip-centrality was used at build time)."""
    cent = _q(s, "MATCH (m:CpgMethod {scan_id:$sid}) WHERE m.centrality > 0 "
                 "AND NOT m.full_name CONTAINS '<' "
                 "RETURN m.full_name AS method, m.centrality AS c ORDER BY c DESC LIMIT $limit",
              sid=sid, limit=limit)
    if cent:
        return {"metric": "betweenness_centrality",
                "top": [{"method": r["method"], "score": r["c"]} for r in cent]}
    indeg = _q(s, "MATCH (c:CpgCall {scan_id:$sid})-[:RESOLVES_TO]->(m:CpgMethod {scan_id:$sid}) "
                  "WHERE NOT m.is_external AND NOT m.full_name CONTAINS '<' "
                  "RETURN m.full_name AS method, count(c) AS indeg ORDER BY indeg DESC LIMIT $limit",
               sid=sid, limit=limit)
    return {"metric": "call_in_degree",
            "top": [{"method": r["method"], "score": r["indeg"]} for r in indeg]}


def render_md(sid, l1, l2, l3, l4):
    L = [f"# Terrain report — `{sid}`", "",
         "Cartographer's map for RaceFuzz. c2cpg fidelity is approximate on macro-heavy kernel "
         "code (function-pointer `_ops` dispatch does not resolve; some cross-subsystem edges are "
         "missing), so treat this as reconnaissance, not ground truth.", ""]

    L += ["## L1 — Entry → internal reach (free/RCU sinks per syscall handler)", ""]
    for e in l1:
        L.append(f"### `{e['entry']}`")
        if not e["sinks"]:
            L.append("  - (no free/RCU sink reached within depth — likely `_ops` dispatch amputation)")
        for s_ in e["sinks"]:
            L.append(f"  - `{s_['sink']}`  (≈{s_['hops']} call-graph steps)")
        L.append("")

    L += ["## L2 — Shared-object op-sets", "",
          "**Free / retire calls present:**"]
    L += [f"  - `{o['name']}` ×{o['count']}" for o in l2["free"]] or ["  - (none)"]
    L += ["", "**Modify calls present:**"]
    L += [f"  - `{o['name']}` ×{o['count']}" for o in l2["modify"]] or ["  - (none)"]
    L += ["", "**Read/lookup calls present:**"]
    L += [f"  - `{o['name']}` ×{o['count']}" for o in l2["read"]] or ["  - (none)"]

    L += ["", "## L3 — Lock/RCU coverage (methods that free/mutate a shared object)", "",
          "⚠ Heuristic: presence of ANY guard call in the method body, not lock-scope at the call. "
          "UNGUARDED rows are the prime race-window candidates.", ""]
    for r in l3:
        flag = "🔴 UNGUARDED" if r["unguarded"] else f"guards={r['guards']}"
        L.append(f"- **{flag}** `{r['method']}`  ({r['file']})")
        L.append(f"    ops: {r['ops']}")

    L += ["", f"## L4 — Chokepoints (metric: {l4['metric']})", ""]
    L += [f"  - `{t['method']}`  ({t['score']:.4f})" if isinstance(t['score'], float)
          else f"  - `{t['method']}`  (in-degree {t['score']})" for t in l4["top"]]
    L.append("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-id", required=True)
    ap.add_argument("--depth", type=int, default=8, help="max call-graph hops for L1 reach walk")
    ap.add_argument("--md", default=None, help="write markdown to this path (else stdout)")
    ap.add_argument("--json", default=None, help="also write structured JSON here")
    args = ap.parse_args()

    d = GraphDatabase.driver(URI, auth=AUTH)
    if not _wait(d):
        print("neo4j not reachable on 7688", file=sys.stderr)
        return 1
    with d.session() as s:
        n = s.run("MATCH (n {scan_id:$sid}) RETURN count(n) AS c", sid=args.scan_id).single()["c"]
        if n == 0:
            print(f"no data for scan_id={args.scan_id}", file=sys.stderr)
            return 1
        print(f"terrain report for {args.scan_id} ({n} nodes)...", file=sys.stderr)
        l1 = layer1_reach(s, args.scan_id, args.depth)
        l2 = layer2_opsets(s, args.scan_id)
        l3 = layer3_locks(s, args.scan_id)
        l4 = layer4_chokepoints(s, args.scan_id)
    d.close()

    md = render_md(args.scan_id, l1, l2, l3, l4)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"wrote {args.md}", file=sys.stderr)
    else:
        print(md)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"scan_id": args.scan_id, "l1_reach": l1, "l2_opsets": l2,
                       "l3_locks": l3, "l4_chokepoints": l4}, f, indent=2)
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

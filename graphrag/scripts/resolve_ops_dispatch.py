#!/usr/bin/env python3
"""
resolve_ops_dispatch.py -- teach the Orion kernel graph about function-pointer
`_ops` dispatch that Joern's C frontend does not resolve.

The kernel dispatches almost everything in bpf/nft/sched through ops tables:

    static const struct bpf_map_ops htab_map_ops = {
        .map_update_elem = htab_map_update_elem,
        .map_free        = htab_map_free,
        ...
    };
    ... map->ops->map_update_elem(map, key, value, flags);   // indirect call

Joern models the indirect call as a CpgCall named after the *field*
("map_update_elem", "map_free", ...) but never links it to the implementation
(htab_map_update_elem). So terrain L1 reach walks are amputated at every
dispatch, and reachable free sinks behind a `->map_free()` look unreachable.

This script closes that gap. Per subsystem (bpf/nft/sched) it:
  1. parses the source for designated-initializer assignments `.field = func`,
     building field -> {implementation functions} (scoped to that subsystem dir),
  2. for each field, adds a synthetic RESOLVES_TO edge from every CpgCall named
     `field` to every implementation CpgMethod for that field (method scoped to
     the same subsystem dir, so a bpf `->map_free()` links only to bpf frees).

Edges are tagged {synthetic:true, via:"ops_dispatch"} and MERGE'd, so the script
is idempotent. It prints a before/after reach measurement so the improvement is
visible. This is reconnaissance enrichment (deliberately over-approximate: a
call site is linked to ALL implementations of its field, since the CPG cannot
say which concrete ops table is live) -- it restores reachability, it does not
claim a specific target.

Run inside ONE wsl invocation that also brings Neo4j up (see run-resolve-dispatch.sh);
the container does not survive between WSL sessions.

Usage:
  python3 resolve_ops_dispatch.py --scan-id kernel-full --src ~/kernel-build/linux-6.17
"""
import argparse
import os
import re
import sys

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable
import time

URI = "bolt://localhost:7688"
AUTH = ("neo4j", "orion_dev_changeme")

SUBSYS_DIRS = {
    "bpf":   "kernel/bpf",
    "nft":   "net/netfilter",
    "sched": "net/sched",
}

# Designated initializer: `.field = func,`  (function-pointer assignment).
# RHS is a bare identifier (optionally &-prefixed); numeric/string/expr RHS is
# skipped, which drops data fields like `.max_entries = 1024`.
INIT_RE = re.compile(r'^\s*\.([A-Za-z_]\w*)\s*=\s*&?([A-Za-z_]\w*)\s*,?\s*$')

# RHS tokens that are never functions -- skip so they don't become bogus targets.
NON_FUNC = {"NULL", "true", "false", "THIS_MODULE", "SIZE_MAX"}


def parse_ops(src_root, subdir):
    """field -> set(impl function names) for one subsystem directory."""
    field2funcs = {}
    root = os.path.join(src_root, subdir)
    if not os.path.isdir(root):
        return field2funcs
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".c"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", errors="replace") as f:
                    for line in f:
                        m = INIT_RE.match(line)
                        if not m:
                            continue
                        field, func = m.group(1), m.group(2)
                        if func in NON_FUNC:
                            continue
                        field2funcs.setdefault(field, set()).add(func)
            except OSError:
                continue
    return field2funcs


def _wait(driver, tries=45, delay=2):
    for _ in range(tries):
        try:
            with driver.session() as s:
                s.run("RETURN 1").single()
            return True
        except (ServiceUnavailable, OSError):
            time.sleep(delay)
    return False


def reach_count(session, sid):
    """How many distinct methods are reachable from __sys_bpf via the pure
    call-graph walk -- the metric dispatch amputation suppresses."""
    q = ("MATCH (e:CpgMethod {scan_id:$sid, name:'__sys_bpf'}) "
         "MATCH (e)-[:CONTAINS_CALL|RESOLVES_TO*1..6]->(c:CpgCall {scan_id:$sid}) "
         "MATCH (c)-[:RESOLVES_TO]->(m:CpgMethod {scan_id:$sid}) "
         "RETURN count(DISTINCT m) AS n")
    try:
        return session.run(q, sid=sid).single()["n"]
    except Exception:  # noqa: BLE001
        return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-id", required=True)
    ap.add_argument("--src", required=True, help="kernel source root (has kernel/bpf, net/...)")
    ap.add_argument("--dry-run", action="store_true", help="parse + report, add no edges")
    args = ap.parse_args()
    src = os.path.expanduser(args.src)

    d = GraphDatabase.driver(URI, auth=AUTH)
    if not _wait(d):
        print("neo4j not reachable on 7688", file=sys.stderr)
        return 1

    with d.session() as s:
        n = s.run("MATCH (n {scan_id:$sid}) RETURN count(n) AS c", sid=args.scan_id).single()["c"]
        if n == 0:
            print(f"no data for scan_id={args.scan_id}", file=sys.stderr)
            return 1
        before = reach_count(s, args.scan_id)
        print(f"scan {args.scan_id}: {n} nodes; reach(__sys_bpf) BEFORE = {before} methods")

        total_edges = 0
        total_fields = 0
        for sub, subdir in SUBSYS_DIRS.items():
            f2f = parse_ops(src, subdir)
            if not f2f:
                print(f"  [{sub}] no ops tables parsed under {subdir} (source missing?)")
                continue
            sub_edges = 0
            sub_fields = 0
            for field, funcs in f2f.items():
                funcs = sorted(funcs)
                # Link calls named `field` to impls of `field` scoped to this subsystem dir.
                q = (
                    "MATCH (c:CpgCall {scan_id:$sid, name:$field}) "
                    "MATCH (m:CpgMethod {scan_id:$sid}) "
                    "WHERE m.name IN $funcs AND m.file_path CONTAINS $subdir "
                    "MERGE (c)-[r:RESOLVES_TO]->(m) "
                    "ON CREATE SET r.synthetic=true, r.via='ops_dispatch' "
                    "RETURN count(r) AS n"
                )
                if args.dry_run:
                    # count only what WOULD link (call + method both present)
                    q = (
                        "MATCH (c:CpgCall {scan_id:$sid, name:$field}) "
                        "MATCH (m:CpgMethod {scan_id:$sid}) "
                        "WHERE m.name IN $funcs AND m.file_path CONTAINS $subdir "
                        "RETURN count(*) AS n"
                    )
                res = s.run(q, sid=args.scan_id, field=field, funcs=funcs, subdir=subdir).single()
                nlinks = res["n"] if res else 0
                if nlinks > 0:
                    sub_edges += nlinks
                    sub_fields += 1
            print(f"  [{sub}] parsed {len(f2f)} fields; "
                  f"{'would link' if args.dry_run else 'linked'} {sub_edges} edges "
                  f"across {sub_fields} dispatch fields")
            total_edges += sub_edges
            total_fields += sub_fields

        after = reach_count(s, args.scan_id)
        verb = "would add" if args.dry_run else "added"
        print(f"\n{verb} {total_edges} synthetic RESOLVES_TO edges over {total_fields} fields")
        print(f"reach(__sys_bpf) AFTER = {after} methods "
              f"(+{after - before} vs before)" if after >= 0 and before >= 0 else "")
    d.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

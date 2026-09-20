#!/usr/bin/env python3
"""Export an Orion scan graph to a portable JSON file (read-only).

Orion persists only into Neo4j. This dumps every node and edge for one ``scan_id`` into a single
self-contained JSON document so the graph can be committed alongside the code as a queryable
knowledge set (an anti-hallucination reference map), surviving a Neo4j volume loss.

Nodes are keyed by their canonical ``uid`` (schema.synthesize_uid), and edges reference endpoints by
that uid, so the JSON re-links without Neo4j's internal ids.

    export_graph.py --scan-id darnit-repro --out graph.json

Only reads the graph (MATCH ... RETURN); it never writes to Neo4j.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from collections import Counter
from pathlib import Path

# scripts/ lives under the Orion repo root; make `import orion.*` work when run directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from orion import config  # noqa: E402
from neo4j import GraphDatabase  # noqa: E402


def export(scan_id: str) -> dict:
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            node_rows = list(s.run(
                "MATCH (n {scan_id:$s}) RETURN labels(n) AS labels, properties(n) AS props",
                s=scan_id,
            ))
            edge_rows = list(s.run(
                "MATCH (a {scan_id:$s})-[r]->(b {scan_id:$s}) "
                "RETURN type(r) AS type, properties(r) AS props, a.uid AS start, b.uid AS end",
                s=scan_id,
            ))
    finally:
        driver.close()

    nodes = [{"labels": r["labels"], "props": dict(r["props"])} for r in node_rows]
    edges = [
        {"type": r["type"], "start": r["start"], "end": r["end"], "props": dict(r["props"])}
        for r in edge_rows
    ]
    label_counts = Counter(lbl for n in nodes for lbl in n["labels"])
    edge_counts = Counter(e["type"] for e in edges)

    return {
        "meta": {
            "scan_id": scan_id,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes_by_label": dict(sorted(label_counts.items(), key=lambda kv: -kv[1])),
            "edges_by_type": dict(sorted(edge_counts.items(), key=lambda kv: -kv[1])),
            "source": "graphrag/scripts/export_graph.py",
        },
        "nodes": nodes,
        "edges": edges,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Export an Orion scan graph to portable JSON (read-only).")
    p.add_argument("--scan-id", required=True)
    p.add_argument("--out", required=True, help="output JSON path")
    p.add_argument("--indent", type=int, default=None, help="pretty-print indent (default: compact)")
    args = p.parse_args(argv)

    data = export(args.scan_id)
    if data["meta"]["node_count"] == 0:
        print(f"WARNING: scan_id={args.scan_id} has 0 nodes — is Neo4j up and the scan built?",
              file=sys.stderr)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=args.indent, sort_keys=False))
    m = data["meta"]
    print(f"wrote {out} ({m['node_count']} nodes, {m['edge_count']} edges)")
    print(f"  nodes_by_label: {m['nodes_by_label']}")
    print(f"  edges_by_type:  {m['edges_by_type']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

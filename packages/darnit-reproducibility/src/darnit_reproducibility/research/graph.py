"""The two knowledge graphs, both in orion's portable export format.

``ResearchGraph`` — the research-domain graph amber writes (Paper / Claim /
ResearchProject / Run / Environment / Result / Artifact / Dependency / Verdict).
``CodeGraph`` — a read-only wrapper over an orion code-property-graph export
(the shape produced by ``graphrag/scripts/export_graph.py`` and committed as
``knowledge/orion-graph.darnit-repro.json``).

Both use the identical on-disk JSON shape so a research graph imports into the
same Neo4j orion uses, and the committed code export loads with zero orion
dependency::

    {"meta": {...},
     "nodes": [{"labels": ["Run"], "props": {"uid": ..., "scan_id": ...}}, ...],
     "edges": [{"type": "HAS_RUN", "start": <uid>, "end": <uid>, "props": {...}}]}

Node identity is a deterministic ``uid`` (sha1 of scan_id|label|natural-key),
mirroring ``orion/graph/schema.py::synthesize_uid`` so re-writes MERGE rather
than duplicate.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def uid(scan_id: str, label: str, natural_key: str) -> str:
    """Deterministic, scan-scoped node id. Same inputs -> same id (MERGE, not dup)."""
    return hashlib.sha1(f"{scan_id}|{label}|{natural_key}".encode()).hexdigest()


class ResearchGraph:
    """A writable knowledge graph in orion export format, scoped to one ``scan_id``."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        # uid -> (label, props); insertion order preserved for deterministic output.
        self._nodes: dict[str, tuple[str, dict[str, Any]]] = {}
        self._edges: list[dict[str, Any]] = []

    # -- writes ---------------------------------------------------------------

    def add_node(self, label: str, natural_key: str, props: dict[str, Any] | None = None) -> str:
        node_uid = uid(self.scan_id, label, natural_key)
        merged = {"uid": node_uid, "scan_id": self.scan_id, **(props or {})}
        if node_uid in self._nodes:
            # MERGE: last write wins on overlapping keys, never a duplicate node.
            self._nodes[node_uid][1].update(merged)
        else:
            self._nodes[node_uid] = (label, merged)
        return node_uid

    def add_edge(
        self, etype: str, start: str, end: str, props: dict[str, Any] | None = None
    ) -> None:
        edge = {"type": etype, "start": start, "end": end, "props": {"scan_id": self.scan_id, **(props or {})}}
        # Dedup identical (type, start, end) edges.
        for existing in self._edges:
            if (existing["type"], existing["start"], existing["end"]) == (etype, start, end):
                existing["props"].update(edge["props"])
                return
        self._edges.append(edge)

    # -- reads ----------------------------------------------------------------

    def node(self, node_uid: str) -> dict[str, Any] | None:
        entry = self._nodes.get(node_uid)
        return entry[1] if entry else None

    def label_of(self, node_uid: str) -> str | None:
        entry = self._nodes.get(node_uid)
        return entry[0] if entry else None

    def nodes(self, label: str | None = None) -> list[dict[str, Any]]:
        return [p for (lbl, p) in self._nodes.values() if label is None or lbl == label]

    def neighbors(
        self, node_uid: str, etype: str | None = None, direction: str = "out"
    ) -> list[str]:
        out: list[str] = []
        for e in self._edges:
            if etype is not None and e["type"] != etype:
                continue
            if direction in ("out", "both") and e["start"] == node_uid:
                out.append(e["end"])
            if direction in ("in", "both") and e["end"] == node_uid:
                out.append(e["start"])
        return out

    def edges(self, etype: str | None = None) -> list[dict[str, Any]]:
        return [e for e in self._edges if etype is None or e["type"] == etype]

    # -- persistence (orion export shape) ------------------------------------

    def to_dict(self) -> dict[str, Any]:
        labels: dict[str, int] = {}
        for lbl, _ in self._nodes.values():
            labels[lbl] = labels.get(lbl, 0) + 1
        types: dict[str, int] = {}
        for e in self._edges:
            types[e["type"]] = types.get(e["type"], 0) + 1
        return {
            "meta": {
                "scan_id": self.scan_id,
                "kind": "research",
                "node_count": len(self._nodes),
                "edge_count": len(self._edges),
                "nodes_by_label": labels,
                "edges_by_type": types,
                "source": "darnit_reproducibility.research",
            },
            "nodes": [{"labels": [lbl], "props": props} for (lbl, props) in self._nodes.values()],
            "edges": list(self._edges),
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=False), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> ResearchGraph:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        g = cls(data.get("meta", {}).get("scan_id", "research"))
        for n in data.get("nodes", []):
            label = (n.get("labels") or ["Node"])[0]
            props = n.get("props", {})
            g._nodes[props["uid"]] = (label, props)
        g._edges = list(data.get("edges", []))
        return g

    # -- cross-graph join (research -> code) ---------------------------------

    def join(self, code: CodeGraph) -> dict[str, Any]:
        """Resolve each Run's ``code_ref`` against a code graph.

        For every ``Run`` carrying ``props.code_ref.file_path``, find the matching
        ``CpgFile`` (and its methods) in ``code`` by path suffix, stamp the resolved
        ``uid`` + method names onto the run, and add an ``EXECUTED_CODE`` edge whose
        endpoint is the namespaced code uid (``code:<scan_id>:<uid>``). Unresolved
        refs keep the path and are reported, never fabricated.
        """
        resolved: list[str] = []
        unresolved: list[str] = []
        for run in self.nodes("Run"):
            ref = run.get("code_ref") or {}
            path = ref.get("file_path")
            if not path:
                continue
            file_uid, methods = code.resolve_path(path)
            if file_uid is None:
                unresolved.append(path)
                run["code_ref"] = {**ref, "resolved": False}
                continue
            ref = {**ref, "uid": file_uid, "scan_id": code.scan_id, "resolved": True}
            run["code_ref"] = ref
            run["executed_methods"] = methods[:50]
            self.add_edge(
                "EXECUTED_CODE",
                run["uid"],
                f"code:{code.scan_id}:{file_uid}",
                {"file_path": path, "method_count": len(methods)},
            )
            resolved.append(path)
        return {"resolved": resolved, "unresolved": unresolved, "code_scan_id": code.scan_id}

    # -- Layer 3 seam --------------------------------------------------------

    def import_to_neo4j(self, driver: Any) -> int:
        """Write this graph into Neo4j (the same store orion uses). Layer-3 seam.

        Research labels are not in orion's frozen ``NODE_KEY``, so this MERGEs on
        ``(:<Label> {scan_id, uid})`` via plain Cypher rather than ``persist()``.
        ``driver`` is a ``neo4j`` driver (lazy import by the caller). Returns the
        node count written.
        """
        with driver.session() as session:
            for label, props in self._nodes.values():
                session.run(
                    f"MERGE (n:`{label}` {{scan_id:$scan_id, uid:$uid}}) SET n += $props",
                    scan_id=props["scan_id"], uid=props["uid"], props=props,
                )
            for e in self._edges:
                session.run(
                    f"MATCH (a {{uid:$s}}),(b {{uid:$e}}) MERGE (a)-[r:`{e['type']}`]->(b) SET r += $props",
                    s=e["start"], e=e["end"], props=e["props"],
                )
        return len(self._nodes)

    def compact_view(self, max_items: int = 40) -> dict[str, Any]:
        """A small JSON view for the Sonnet agent — the whole point is to fit in a prompt."""
        def run_view(r: dict[str, Any]) -> dict[str, Any]:
            outs = [self.node(u) for u in self.neighbors(r["uid"], "PRODUCED")]
            deps = self.neighbors(r["uid"], "USED_DEP")
            results = [self.node(u) for u in self.neighbors(r["uid"], "MEASURED")]
            return {
                "run_id": r.get("run_id"),
                "cmd": r.get("cmd"),
                "exit_code": r.get("exit_code"),
                "python": r.get("python_version"),
                "platform": r.get("platform"),
                "commit": r.get("commit"),
                "outputs": [{"path": o.get("path"), "sha256": o.get("sha256")} for o in outs if o],
                "dependency_count": len(deps),
                "results": [{"metric": x.get("metric"), "value": x.get("value")} for x in results if x],
                "executed_code": r.get("code_ref"),
                "executed_methods": (r.get("executed_methods") or [])[:15],
            }

        return {
            "scan_id": self.scan_id,
            "papers": [
                {
                    "title": p.get("title"),
                    "url": p.get("url"),
                    "claims": [
                        {"metric": c.get("metric"), "comparator": c.get("comparator"),
                         "value": c.get("value"), "tolerance": c.get("tolerance"), "unit": c.get("unit")}
                        for c in (self.node(u) for u in self.neighbors(p["uid"], "HAS_CLAIM")) if c
                    ],
                }
                for p in self.nodes("Paper")[:max_items]
            ],
            "projects": [p.get("name") for p in self.nodes("ResearchProject")],
            "runs": [run_view(r) for r in self.nodes("Run")[:max_items]],
            "verdicts": [
                {"kind": v.get("kind"), "level": v.get("level"), "summary": v.get("summary"),
                 "metric": v.get("metric")}
                for v in self.nodes("Verdict")[:max_items]
            ],
        }


class CodeGraph:
    """Read-only view over an orion code-property-graph export JSON."""

    def __init__(self, scan_id: str, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
        self.scan_id = scan_id
        self._nodes = nodes
        self._edges = edges

    @classmethod
    def load(cls, path: str | Path) -> CodeGraph:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        scan = data.get("meta", {}).get("scan_id", "code")
        return cls(scan, data.get("nodes", []), data.get("edges", []))

    def _by_label(self, label: str) -> list[dict[str, Any]]:
        return [n["props"] for n in self._nodes if label in (n.get("labels") or [])]

    def resolve_path(self, path: str) -> tuple[str | None, list[str]]:
        """Return (CpgFile uid, [method names]) for a source path, matched by suffix.

        Match is tolerant: the research run knows a repo-relative or bare path
        (``experiment.py``); the code graph stores repo-relative paths
        (``examples/research/lorenz/experiment.py``). We match on longest suffix.
        """
        norm = path.replace("\\", "/").lstrip("./")
        file_uid: str | None = None
        best = ""
        for f in self._by_label("CpgFile"):
            fp = str(f.get("file_path", "")).replace("\\", "/")
            if fp == norm or fp.endswith("/" + norm) or norm.endswith("/" + fp) or fp.endswith(norm):
                if len(fp) > len(best):
                    best, file_uid = fp, f.get("uid")
        if file_uid is None:
            return None, []
        matched_path = best
        methods = sorted(
            {
                str(m.get("name") or m.get("full_name"))
                for m in self._by_label("CpgMethod")
                if str(m.get("file_path", "")).replace("\\", "/") == matched_path and (m.get("name") or m.get("full_name"))
            }
        )
        return file_uid, methods

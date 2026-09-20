# Knowledge graph — `darnit-reproducibility`

A queryable **Orion code graph** of this package, committed alongside the code as an
anti-hallucination reference/knowledge set for the **Amber capture** work (the Witness-based
provenance capture front-end). It lets us (and coding agents) ground claims about the package's
structure in a real graph query instead of guessing.

## The artifact

- **`orion-graph.darnit-repro.json`** — a self-contained dump of every node and edge Orion built for
  this package (`scan_id=darnit-repro`).
- Nodes are keyed by their canonical `uid`; edges reference endpoints by that `uid`, so the JSON
  re-links without any database.

### Contents (as generated 2026-09-16, includes the Amber capture/ingest code)

| Nodes | 11,788 | | Edges | 29,874 |
|---|---|---|---|---|
| CpgCall | 7,547 | | RESOLVES_TO | 20,236 |
| CpgMethod | 1,860 | | CONTAINS_CALL | 7,547 |
| CpgReturn | 1,860 | | FLOWS_TO | 1,750 |
| CpgParameter | 229 | | DEFINED_IN | 225 |
| EntryPoint | 116 | | ENTERS_AT | 116 |
| CpgModule | 76 | | | |
| CandidateFlow | 72 | | | |
| CpgFile | 28 | | | |

Source files covered (28): the plugin + the full Amber MVP — `cli`,
`capture/{run,pyprobe,_sitecustomize}`, `ingest/witness`,
`analysis/{compare,sbom,vuln,provenance}`, `generate/environment`, `attestation/reproducibility`,
`models`.
Every `CpgMethod`/`CpgCall` carries `reachable_from_entry`, `hop_distance`, and `centrality`
(build-time precompute); `CandidateFlow` nodes are ranked source→sink data-flow candidates.

## Querying the file directly (no database)

```python
import json
d = json.load(open("orion-graph.darnit-repro.json"))
methods = [n["props"] for n in d["nodes"] if "CpgMethod" in n["labels"]]
print([m["name"] for m in methods if m.get("reachable_from_entry")][:20])
```

## Rebuilding / re-querying via Neo4j (the `graphrag/` tooling)

The graph is produced and re-loaded by the GraphRAG code-graph tooling under `graphrag/` (at the
`amber/` project root). Requires its venv and its Neo4j container. Run these from the project root:

```bash
# bring the graph DB up
docker compose -f graphrag/docker-compose.yml up -d

# rebuild the scan (no discover/verify, 0 Claude tokens)
python graphrag/scripts/build_graph_only.py reference \
    packages/darnit-reproducibility --scan-id darnit-repro --language pythonsrc

# re-export the committed JSON
python graphrag/scripts/export_graph.py \
    --scan-id darnit-repro \
    --out packages/darnit-reproducibility/knowledge/orion-graph.darnit-repro.json
```

Live Cypher (read-only) against `bolt://localhost:7688` (`neo4j` / `orion_dev_changeme`), always
scoped by `scan_id`:

```cypher
MATCH (m:CpgMethod {scan_id:'darnit-repro'})
WHERE m.name = 'check_witness_attestation'
RETURN m.name, m.file_path, m.reachable_from_entry;
```

## Notes

- A whole-repo graph of all of `darnit-main` also exists in Neo4j under `scan_id=darnit-main`
  (~24k methods / ~154k calls) — too large to commit; this package-scoped subset is the portable
  knowledge set.
- Regenerate this file whenever the package's Python source changes materially, so the committed
  graph stays in sync with the code.

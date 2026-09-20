# Amber

> **Lock a piece of programming research into a verifiable state — then prove it reproduces.**

**Amber** runs a research artifact (a paper's code/experiment) in a controlled
environment, captures *everything* about the run (system specs, environment,
dependencies, outputs) as a signed provenance record, and lets anyone
**cross-verify** the results later — against a prior run *and* against the paper's
own quantitative claims. Every run is recorded in a **knowledge graph** that links
what happened (runs, specs, results, verdicts) to the **code** that produced it, and
a small read-only agent lets you ask questions over that graph in plain language.

It is built on three components in this repo:

| Component | Role |
|-----------|------|
| **amber** (`packages/darnit-reproducibility`) | Provenance capture + reproducibility verification (`witness`-backed) and the **research shell** (`amber research`). |
| **darnit** (`packages/darnit*`) | The underlying pluggable compliance/audit framework amber is a plugin of. |
| **orion** (`graphrag/`) | The code-property-graph system whose graph format amber's knowledge graph reuses, and whose scanning agent grounds code questions in real queries. |

---

## What amber does

1. **Capture** — run a command wrapped in [`witness`](https://github.com/in-toto/witness);
   collect OS/hardware/CPU-SIMD/BLAS/env/git/dependency/output specs into a signed
   in-toto bundle.
2. **Lock** — that bundle is the immutable record of the run.
3. **Graph** — write the run into a **research knowledge graph** (runs, environments,
   results, artifacts, verdicts) that **references an orion code graph** (which
   functions the run executed).
4. **Cross-verify (deterministic, no LLM)** —
   - *reproducibility*: re-run and compare outputs (`BIT_FOR_BIT` … `NOT_REPRODUCED`);
   - *claims*: check measured results against the paper's numbers
     (e.g. the gittuf NDSS paper's *< 0.59 s per-push verification*, *< 4 % storage*).
5. **Ask** — a minimal Sonnet agent reads the graph to answer questions and flag
   inconsistencies (unreproduced claims, environment drift, unverified runs). The
   inconsistencies are computed deterministically; the agent only phrases them.
6. **Package** — emit a portable artifact a future project can build on.

---

## Requirements

- Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).
- For **live capture**: a Linux environment with the `witness` binary
  (`witness` uses eBPF / `/proc`, so on Windows/macOS live capture runs inside the
  per-project container — see *Roadmap*). Everything below runs **without** witness,
  Docker, Neo4j, or an API key, using the committed example captures.
- Optional: `ANTHROPIC_API_KEY` to let the `ask` agent call Claude Sonnet. Without
  it, `ask` returns a deterministic summary instead.

## Install

```bash
git clone <this-repo> amber
cd amber
uv sync
```

## Run it (one command)

```bash
uv run python run_amber_research.py
```

This exercises the whole research loop over the committed example captures
(lorenz / sir / pysindy / sklearn_wine) with no external services, then runs the
test suite. It will:

- seed a project with the NDSS gittuf paper + a few claims,
- lock the example captures as runs,
- join them to the committed orion code graph (`Run → experiment.py → methods`),
- verify claims and reproducibility deterministically,
- print the agent's answer (deterministic fallback if no API key).

## The `amber research` CLI

```bash
# 1. begin a project: the paper, its claims, and where the code graph lives
uv run amber research begin gittuf \
    --paper-url "https://www.ndss-symposium.org/ndss-paper/rethinking-trust-in-forge-based-git-security/" \
    --claim "verify_seconds<=0.59" --claim "storage_overhead_pct<=4" \
    --experiment "examples/research/lorenz/experiment.py" \
    --code-graph packages/darnit-reproducibility/knowledge/orion-graph.darnit-repro.json

# 2. lock a captured run (Layer 1 ingests an existing bundle)
uv run amber research run gittuf \
    --bundle path/to/bundle.json --pylibs path/to/amber-pylibs.json \
    --run-id r1 --metric verify_seconds=0.42

# 3. cross-verify
uv run amber research verify gittuf --run r1                     # claims vs measured
uv run amber research verify gittuf --baseline r1 --candidate r2 # reproducibility

# 4. pack a portable artifact / ask the graph
uv run amber research artifact gittuf -o gittuf-artifact.tar.gz
uv run amber research ask gittuf "which claims did not reproduce?"
```

Project state lives under `.amber-research/<project>/` (`graph-research.json`,
`project.json`, `runs/<id>/`).

## The underlying `amber` capture CLI

```bash
amber capture --step run -o bundle.json -- python experiment.py   # run + capture
amber ingest  bundle.json                                         # capture report
amber verify  original.json reproduction.json                     # reproducibility verdict
amber generate bundle.json --target docker --out-dir env/         # reproducible env
```

## Tests

```bash
uv run pytest tests/darnit_reproducibility/research/ -q   # the research shell
uv run pytest tests/ -q                                   # everything
```

---

## Roadmap

The research shell ships in layers (see the design in
`packages/darnit-reproducibility/docs/`):

- **Layer 1 (now):** the two-graph model, deterministic claim + reproducibility
  verification, the portable artifact, and the agent — all runnable on any OS over
  captured bundles.
- **Layer 2:** a **per-project container** whose run-model *is* the `amber` CLI, so
  live `witness` capture runs inside it; a fresh orion **code graph** built per
  project; real ingest of paper artifacts (e.g. the gittuf benchmark).
- **Layer 3:** import both graphs into orion's Neo4j for heavy cross-graph Cypher.

## Architecture note

Amber is a plugin of **darnit**, a pluggable compliance/audit framework
(OpenSSF Baseline is its reference implementation). The core framework never
imports implementations; amber consumes it through the plugin protocol. See
`packages/darnit-reproducibility/` for the amber source and
`packages/darnit/` for the framework.

## License

Apache-2.0

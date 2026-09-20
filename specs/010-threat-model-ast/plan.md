# Implementation Plan: Accurate Threat Model Discovery

**Branch**: `010-threat-model-ast` | **Date**: 2026-04-10 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/010-threat-model-ast/spec.md`

## Summary

Replace the regex-based discovery layer in `packages/darnit-baseline/src/darnit_baseline/threat_model/` with structural AST parsing via `tree-sitter` and optional intra-procedural taint analysis via the `opengrep` CLI binary. The existing remediation handler (`generate_threat_model_handler`) keeps its signature, evidence conventions, file output contract, and calling-agent verification pattern. What changes is the internals: assets and candidate findings come from tree-sitter queries over concrete AST nodes instead of regex over raw text, optionally enriched with data-flow traces when Opengrep is available. The resulting draft `THREAT_MODEL.md` contains far fewer false positives, ranked top-50 findings by severity × confidence, with vendor/dependency directories excluded and shallow-mode behavior for repositories larger than 500 in-scope files.

## Technical Context

**Language/Version**: Python 3.11+ (project targets 3.11/3.12; uses modern type hints and `from __future__ import annotations`)
**Primary Dependencies**: `tree-sitter>=0.25`, `tree-sitter-language-pack>=1.5` (bundles Python/JS/TS/Go/YAML grammars); existing deps: `darnit` (core framework)
**External Prerequisites**: `opengrep` CLI binary (optional; fallback to `semgrep` binary if present) — installed out-of-band, detected at runtime via `shutil.which`
**Storage**: Filesystem only. Writes `THREAT_MODEL.md` (or configured path) via `HandlerContext.local_path`. No persistent state across runs (FR-031).
**Testing**: `pytest` (existing test infra). New `tests/darnit_baseline/threat_model/fixtures/` directory containing fixture repositories with known structural patterns.
**Target Platform**: Linux and macOS developer machines and CI runners. Windows is unsupported for Opengrep (documented limitation); tree-sitter works on all three.
**Project Type**: Python library / MCP server plugin. Single-package change confined to `darnit-baseline`.
**Performance Goals**: <2 minutes wall-clock for 100–500 in-scope file repositories (SC-006). Tree-sitter parsing target: ~1–2 ms per file. Opengrep cold start: ~200–400 ms, per-scan: ~2 s for 116 files with 9 rules (measured on darnit itself).
**Constraints**: No LLM API calls (darnit is an MCP server; calling agent is the LLM). No network I/O during analysis. No execution of target code. No cross-run state.
**Scale/Scope**: Typical repository: 100–500 in-scope files after exclusions. Shallow-mode threshold: 500 in-scope files. No hard upper cap. Default finding cap: 50 findings per draft. Five structurally-scanned languages: Python, JavaScript, TypeScript, Go, YAML. TOML is parsed only for dependency-manifest corroboration (`pyproject.toml`, `package.json`), not structurally queried.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Evaluated against `.specify/memory/constitution.md` v1.1.0:

### I. Plugin Separation — PASS

- Change is entirely confined to `packages/darnit-baseline/`. No framework code changes.
- The rewritten handler continues to use the public `darnit.sieve.handler_registry` types (`HandlerContext`, `HandlerResult`, `HandlerResultStatus`) and `darnit.core.logging`. No new framework imports.
- No new protocol methods added; handler registration uses the existing `register_handlers()` path.

### II. Conservative-by-Default — PASS

- The entire motivation of this change is **reducing false positives** — the exact principle the constitution invokes. Tree-sitter structurally distinguishes code from comments/strings, which is a fundamental correctness improvement over regex.
- Skip-if-exists default (FR-007a) is conservative: never destroy user work without explicit opt-in.
- Shallow-mode (FR-025) explicitly surfaces degraded analysis in the draft's Limitations section rather than silently emitting lower-quality output.
- Finding cap with overflow summary (FR-028–030) prefers legible partial output over unreviewable full output, and tells the calling agent how much was trimmed.
- Opengrep degradation (FR-016–017) guarantees that absence of the optional tool cannot introduce new incorrect findings.

### III. TOML-First Architecture — PASS

- The OSPS-SA-03.02 TOML definition in `openssf-baseline.toml` is not changed. The handler is referenced by name from TOML (`handler = "generate_threat_model"`); only the Python implementation behind that name is rewritten.
- No control metadata moves from TOML into Python. No CEL expression changes.
- New handler config keys (`max_findings`, `exclude_dirs`, `snippet_context_lines`, `shallow_threshold`) and the existing `overwrite` key are all set per-control in TOML, not hardcoded in Python.

### IV. Never Guess User Values — PASS

- Threat model generation does not touch project context (`.project/project.yaml`), maintainers, security contacts, or any user-judgment fields. It analyzes source code, which is observable fact.
- The draft's verification prompts explicitly instruct the calling agent to confirm findings against code snippets — no guessed values are presented as confirmed.
- LLM-facing content (the draft) contains source snippets and structural findings, not executable commands derived from heuristics. Constitution prohibition on "guessed values in executable code snippets" is not engaged here.

### V. Sieve Pipeline Integrity — PASS

- This is a **remediation handler** (Layer 2), not a sieve pass handler (Layer 1). The 4-phase pipeline semantics are unchanged.
- The handler returns `HandlerResult(status=PASS|ERROR)` as it does today. PASS / ERROR semantics are preserved.

**Result**: All five principles satisfied. No complexity-tracking entries needed.

## Project Structure

### Documentation (this feature)

```text
specs/010-threat-model-ast/
├── plan.md              # This file
├── research.md          # Phase 0 — tree-sitter/opengrep decisions and precedents
├── data-model.md        # Phase 1 — entity shapes: EntryPoint, DataStore, CandidateFinding, HandlerConfig
├── quickstart.md        # Phase 1 — dev loop: parse fixture, run handler, verify output
├── contracts/           # Phase 1 — handler contract, output format contract, opengrep runner contract
│   ├── handler-contract.md
│   ├── output-format-contract.md
│   └── opengrep-runner-contract.md
├── checklists/
│   └── requirements.md  # Spec quality checklist (from /speckit.specify)
└── tasks.md             # Phase 2 output — created by /speckit.tasks, NOT by this command
```

### Source Code (repository root)

Single Python package change, confined to `darnit-baseline`:

```text
packages/darnit-baseline/
├── pyproject.toml                       # ADD tree-sitter deps + package-data for opengrep_rules
└── src/darnit_baseline/
    └── threat_model/
        ├── __init__.py                  # KEEP, re-export handler
        ├── remediation.py               # UPDATE internals of generate_threat_model_handler; same signature
        ├── parsing.py                   # NEW — tree-sitter wrappers, compiled queries, parser helpers
        ├── queries/                     # NEW — S-expression query constants
        │   ├── __init__.py
        │   ├── python.py                # decorators, calls, imports, class/function defs
        │   ├── javascript.py            # covers JS + TS (grammar: tsx)
        │   ├── go.py                    # HTTP handler registrations, imports
        │   └── yaml.py                  # workflow/permissions blocks
        ├── opengrep_runner.py           # NEW — subprocess invocation, JSON parsing, graceful degradation
        ├── opengrep_rules/              # NEW — bundled YAML rules (package data)
        │   ├── entry_points.yaml
        │   ├── data_stores.yaml
        │   ├── taint_external_input.yaml
        │   └── config_loaders.yaml
        ├── discovery.py                 # REWRITE — orchestrate tree-sitter queries + opengrep; produce assets/findings
        ├── file_discovery.py            # NEW — walk repo, apply exclusion + .gitignore rules, return in-scope file list
        ├── ranking.py                   # NEW — severity × confidence ranking + top-N cap + overflow accounting
        ├── stride.py                    # UPDATE — map new finding shape to STRIDE categories
        ├── generators.py                # UPDATE — Markdown/SARIF/JSON from new finding shape; preserve section contract
        ├── chains.py                    # KEEP — attack chain detection; skipped in shallow mode
        ├── models.py                    # UPDATE — add EntryPoint, DataStore, CallGraphNode, FileScanStats
        ├── scenarios.py                 # KEEP — deterministic scenario templates; calling agent refines them
        ├── dependencies.py              # KEEP — pyproject/package.json parsing for corroboration
        └── patterns.py                  # DELETE — regex source of truth goes away

tests/darnit_baseline/threat_model/
├── test_parsing.py                      # NEW — tree-sitter query captures against snippets
├── test_file_discovery.py               # NEW — exclusion + .gitignore behavior
├── test_discovery.py                    # REWRITE — end-to-end discovery on fixture repos
├── test_opengrep_runner.py              # NEW — mocked subprocess + error path
├── test_ranking.py                      # NEW — severity × confidence ordering, cap enforcement
├── test_handler.py                      # NEW — generate_threat_model_handler contract preservation
├── test_generators.py                   # UPDATE — markdown/SARIF/JSON output from new model
└── fixtures/                            # NEW — known-structure example repos
    ├── fastapi_minimal/
    ├── flask_minimal/
    ├── mcp_server_minimal/
    ├── go_http_handler/
    ├── subprocess_tainted/
    ├── red_herrings/                    # docstrings mentioning "postgresql", etc.
    └── large_repo_shallow/              # >500 files to exercise shallow mode
```

**Structure Decision**: Single-package change in `packages/darnit-baseline/`. No changes to `packages/darnit/` (the core framework). This preserves plugin separation (Constitution I) and limits the blast radius to the implementation that produces threat models. The feature does not introduce any new cross-package coupling.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

None. All five constitutional principles are satisfied without exceptions.

---
description: "Task list for Accurate Threat Model Discovery (010-threat-model-ast)"
---

# Tasks: Accurate Threat Model Discovery

**Input**: Design documents from `/specs/010-threat-model-ast/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Included. The spec's Acceptance Scenarios (Stories 1–4) and Success Criteria (SC-001 through SC-008) explicitly require fixture-based and dogfood regression tests; quickstart.md lists the concrete test files to produce.

**Organization**: Tasks are grouped by user story. User Stories 1, 2, and 4 are P1; Story 3 is P2.

All paths are absolute. Relative paths are rooted at `/Users/mlieberman/Projects/baseline-mcp/`.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Which user story this task belongs to ([US1], [US2], [US3], [US4])
- Setup, Foundational, and Polish tasks have no story label

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project configuration and dependency wiring. No business logic yet.

- [X] T001 Add `tree-sitter>=0.25` and `tree-sitter-language-pack>=1.5` to `[project.dependencies]` in `packages/darnit-baseline/pyproject.toml`
- [X] T002 Add `"src/darnit_baseline/threat_model/opengrep_rules" = "darnit_baseline/threat_model/opengrep_rules"` entry under `[tool.hatch.build.targets.wheel.force-include]` in `packages/darnit-baseline/pyproject.toml`
- [X] T003 Run `uv sync --all-extras` to install new dependencies and verify they import; resolve any lockfile conflicts
- [X] T004 [P] Create empty module files: `packages/darnit-baseline/src/darnit_baseline/threat_model/parsing.py`, `file_discovery.py`, `ranking.py`, `opengrep_runner.py`, `queries/__init__.py`, `queries/python.py`, `queries/javascript.py`, `queries/go.py`, `queries/yaml.py` (each with just a module docstring)
- [X] T005 [P] Create empty directory `packages/darnit-baseline/src/darnit_baseline/threat_model/opengrep_rules/` with placeholder `.gitkeep`
- [X] T006 [P] Create test fixture directory structure: `tests/darnit_baseline/threat_model/fixtures/fastapi_minimal/`, `flask_minimal/`, `mcp_server_minimal/`, `go_http_handler/`, `subprocess_tainted/`, `red_herrings/`, `large_repo_shallow/` with README.md in each describing the pattern that fixture tests
- [X] T007 Run `uv run ruff check .` and confirm zero errors after adding the new empty modules

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Types, parser helpers, file walking, and the opengrep runner skeleton. Every user story depends on this phase.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

### Data model foundations

- [X] T008 Add the new entity types from `data-model.md` to `packages/darnit-baseline/src/darnit_baseline/threat_model/models.py`: `Location`, `CodeSnippet`, `EntryPointKind`, `DataStoreKind`, `EntryPoint`, `DataStore`, `CallGraphNode`, `FindingSource`, `DataFlowStep`, `DataFlowTrace`, `StrideCategory`, `CandidateFinding`, `FileScanStats`, `TrimmedOverflow` — as `@dataclass(frozen=True)` where appropriate, preserving `from __future__ import annotations`
- [X] T009 Delete the obsolete regex-era types from `models.py`: the current `Threat` dataclass and any types that only exist to support `patterns.py`. Keep any types still used by `scenarios.py`, `chains.py`, `generators.py` (rewritten stubs will re-import them)

### Tree-sitter wrappers

- [X] T010 Implement `packages/darnit-baseline/src/darnit_baseline/threat_model/parsing.py`: `get_parser(language_name) -> Parser`, `parse_file(language_name, content: bytes) -> Tree`, `make_query(language_name, sexpr) -> Query`, `run_query(query, root_node) -> Iterator[dict[str, list[Node]]]`, `detect_language_from_path(path) -> str | None`. Use `tree-sitter-language-pack` for all grammar lookups; use `QueryCursor` for query execution (per research §2). Never wrap `parse_file` in `try/except`; tree-sitter handles malformed input natively (research §3)
- [X] T011 [P] Create `tests/darnit_baseline/threat_model/test_parsing.py` with minimal smoke tests for each supported language: parse a 5-line snippet, run a trivial `(identifier) @id` query, assert at least one capture. Languages: python, javascript, typescript, go, yaml

### File discovery

- [X] T012 Implement `packages/darnit-baseline/src/darnit_baseline/threat_model/file_discovery.py`: `walk_repo(root: Path, extra_excludes: list[str]) -> list[ScannedFile]` and `ScannedFile` dataclass. Apply baseline exclusions (research §11): `.venv`, `venv`, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `node_modules`, `dist`, `build`, `vendor`, `target`, `.git`, `out`, `tmp`. Parse the repo root's `.gitignore` for additional directory prefixes; only match directory names, not full glob semantics. Return per-file language detection via `parsing.detect_language_from_path`. Count and return `FileScanStats`
- [X] T013 [P] Create `tests/darnit_baseline/threat_model/test_file_discovery.py` with tests: (a) baseline directories excluded, (b) `.gitignore`-listed directories excluded, (c) user-supplied `exclude_dirs` additive to baselines, (d) in-scope file count correct on a small fixture

### Ranking foundation

- [X] T014 Implement `packages/darnit-baseline/src/darnit_baseline/threat_model/ranking.py`: `severity_for(category, source, has_taint_trace) -> int`, `confidence_for(source, query_id) -> float`, `rank_findings(findings: list[CandidateFinding]) -> list[CandidateFinding]` sorted by `severity * confidence` desc, `apply_cap(findings, max_findings) -> tuple[list[CandidateFinding], TrimmedOverflow]` with category-diversity tie-break per research §12
- [X] T015 [P] Create `tests/darnit_baseline/threat_model/test_ranking.py` with tests: severity × confidence ordering is correct, cap trims to max_findings, overflow totals match trimmed count, category diversity tie-break kicks in when one category would dominate

### Opengrep runner skeleton

- [X] T016 Implement `packages/darnit-baseline/src/darnit_baseline/threat_model/opengrep_runner.py` per `contracts/opengrep-runner-contract.md`: `OpengrepResult` dataclass, `run_opengrep(target, rules_dir, timeout_s=120)` function. Detection via `shutil.which("opengrep") or shutil.which("semgrep")`. If neither found, return `OpengrepResult(available=False, ...)` immediately. If found, invoke with exact flag vector from the contract, parse JSON stdout, **always inspect `data["errors"]` even on exit 0**, handle timeouts via `subprocess.TimeoutExpired`. Log via `darnit.core.logging`
- [X] T017 [P] Create `tests/darnit_baseline/threat_model/test_opengrep_runner.py` with tests using `subprocess.run` monkeypatched: (a) missing binary → `available=False`, (b) successful exit 0 with findings, (c) exit 0 with rule schema errors in `data["errors"]`, (d) exit 2 scan failure, (e) malformed JSON stdout, (f) timeout

### Handler shell

- [X] T018 Refactor `packages/darnit-baseline/src/darnit_baseline/threat_model/remediation.py` to import the new module layout but keep the existing fallback-to-static-template path intact. The function body at this stage calls a not-yet-implemented `discovery.discover_all(...)` — add a stub that returns empty results so the fallback path runs and returns PASS with `action="created_from_template"`. Preserve the existing `HandlerResult` shape and evidence conventions per `contracts/handler-contract.md`

**Checkpoint**: Foundation ready. Tree-sitter parses, files walk, rankings compute, opengrep detects, handler returns (via fallback). User story implementation can begin.

---

## Phase 3: User Story 1 — Calling agent receives a high-signal draft (Priority: P1) 🎯 MVP

**Goal**: Discovery pipeline produces structurally-grounded findings (no phantom postgresql, no email-in-metadata PII) and feeds them through ranking into a draft that the calling agent can verify with minimal effort.

**Independent Test**: Run the discovery function directly on `tests/darnit_baseline/threat_model/fixtures/` and assert: (a) `red_herrings/` produces zero findings, (b) `fastapi_minimal/`, `flask_minimal/`, `mcp_server_minimal/`, `go_http_handler/`, `subprocess_tainted/` each produce the expected known real findings.

### Test fixtures for US1

- [X] T019 [P] [US1] Create `tests/darnit_baseline/threat_model/fixtures/fastapi_minimal/main.py` with a FastAPI app exposing 2 routes (`@app.get("/healthz")`, `@app.post("/users")`), and a `pyproject.toml` listing `fastapi` as a dependency
- [X] T020 [P] [US1] Create `tests/darnit_baseline/threat_model/fixtures/flask_minimal/app.py` with a Flask app exposing 2 routes (`@app.route("/", methods=["GET"])`, `@app.route("/submit", methods=["POST"])`)
- [X] T021 [P] [US1] Create `tests/darnit_baseline/threat_model/fixtures/mcp_server_minimal/server.py` with a FastMCP server exposing two tools via `@server.tool(...)` decorators
- [X] T022 [P] [US1] Create `tests/darnit_baseline/threat_model/fixtures/go_http_handler/main.go` with `http.HandleFunc("/api", handler)` and one `sql.Open("postgres", ...)` call
- [X] T023 [P] [US1] Create `tests/darnit_baseline/threat_model/fixtures/subprocess_tainted/app.py` with a Python file where `subprocess.run(cmd, shell=True)` receives a command built from `request.query_params` (real command-injection pattern)
- [X] T024 [P] [US1] Create `tests/darnit_baseline/threat_model/fixtures/red_herrings/` files: (a) `docstring_postgres.py` with `"""Uses gpg.ssh.allowedSignersFile"""` docstring and no DB code, (b) `metadata_email.py` with `email=data.get("email", "")` in a maintainer-parse function, (c) `commented_eval.py` with `# eval("x")` comment and no real eval call, (d) `string_subprocess.py` where the literal string `"subprocess.run"` appears in a docstring but no call exists

### Tree-sitter queries

- [X] T025 [US1] Populate `packages/darnit-baseline/src/darnit_baseline/threat_model/queries/python.py` with module-level `Query` constants for: `ENTRY_DECORATED_ROUTE` (FastAPI/Flask decorator pattern), `ENTRY_MCP_TOOL` (`@server.tool` decorator), `DATASTORE_CONSTRUCTOR_CALL` (sqlite3/psycopg/redis/pymongo/boto3/SQLAlchemy constructors), `IMPORTS` (import and import-from statements), `SUBPROCESS_CALL` (subprocess.run/call/Popen, os.system, os.popen, eval, exec), `AUTH_DECORATOR` (decorators whose names match auth/login/jwt/required). Each query assigned a stable string id via `QUERY_REGISTRY: dict[str, Query]` for downstream ranking
- [X] T026 [P] [US1] Populate `packages/darnit-baseline/src/darnit_baseline/threat_model/queries/javascript.py` with queries for Express routes (`app.get/post/...`), `child_process.*` calls, `new X()` constructors for DB clients, ES and CJS imports. Same `QUERY_REGISTRY` pattern. Queries are authored in S-expression once and executed against three separate grammars exposed by `tree-sitter-language-pack` — `javascript`, `typescript`, and `tsx` — via `get_parser(name)`. Some nodes differ between grammars (e.g., TypeScript type annotations); verify per-grammar query compatibility during implementation and add grammar-specific variants if needed
- [X] T027 [P] [US1] Populate `packages/darnit-baseline/src/darnit_baseline/threat_model/queries/go.py` with queries for `http.HandleFunc` / `r.Get` / `r.Post` / etc., `exec.Command`, `sql.Open("<driver>", ...)`, and import specs
- [X] T028 [P] [US1] Populate `packages/darnit-baseline/src/darnit_baseline/threat_model/queries/yaml.py` with queries for GitHub Actions workflow `on:` blocks and `permissions:` blocks (minimal scope for v1)

### Discovery orchestration

- [X] T029 [US1] Implement `packages/darnit-baseline/src/darnit_baseline/threat_model/discovery.py` `discover_entry_points(scanned_files) -> list[EntryPoint]`: iterate files, select query registry by language, run entry-point queries, convert captures into `EntryPoint` records with `source_query`, `framework`, `route_path`, `http_method`, `has_auth_decorator` populated. Use `file_discovery.ScannedFile` as input
- [X] T030 [US1] In `discovery.py` implement `discover_data_stores(scanned_files, dependency_manifest) -> list[DataStore]`: run constructor queries, cross-reference imports via the module's `IMPORTS` query, cross-reference dependency manifest (reuse existing `dependencies.parse_dependency_manifests`) for confidence scoring. Never emit a store from a comment/string/docstring — structurally impossible via tree-sitter queries, which is the point
- [X] T031 [US1] In `discovery.py` implement `discover_subprocess_candidates(scanned_files) -> list[CandidateFinding]`: run the `SUBPROCESS_CALL` query per file, wrap each match as a `CandidateFinding` with `source=TREE_SITTER_STRUCTURAL`, category `StrideCategory.TAMPERING`, severity from `ranking.severity_for` with `has_taint_trace=False`. Populate `code_snippet` using the file contents ± the configured context window
- [X] T032 [US1] In `discovery.py` implement `discover_call_graph(scanned_files) -> list[CallGraphNode]`: for each file, find function definitions and their internal call sites; build `CallGraphNode` records. Used downstream for DFD rendering and enclosing-function context. Intra-module only in v1
- [X] T033 [US1] In `discovery.py` implement `discover_all(repo_root: Path, config: dict) -> DiscoveryResult` dataclass containing: `entry_points`, `data_stores`, `call_graph`, `findings` (pre-ranking), `file_scan_stats`, `opengrep_result`. This is the single entry point the handler calls. At this task's completion, the Opengrep result is always `OpengrepResult(available=False, ...)` because Opengrep integration comes in US3
- [X] T034 [US1] Replace the stub in `remediation.py` (`generate_threat_model_handler`'s call into discovery) with real `discover_all(...)` + `ranking.rank_findings(...)` + `ranking.apply_cap(...)`. Populate `HandlerResult.evidence` with `file_scan_stats` and `trimmed_overflow`. At this task's completion the draft content is still whatever `generators.py` currently produces — US4 rewrites generators

### Tests for US1

- [X] T035 [P] [US1] Create `tests/darnit_baseline/threat_model/test_discovery.py::test_fastapi_fixture_entry_points` — load `fixtures/fastapi_minimal/`, call `discover_entry_points`, assert exactly 2 entry points with kind `HTTP_ROUTE`, framework `fastapi`, expected route paths and methods
- [X] T036 [P] [US1] In `test_discovery.py::test_flask_fixture_entry_points` assert the same for Flask
- [X] T037 [P] [US1] In `test_discovery.py::test_mcp_server_fixture_entry_points` assert 2 `MCP_TOOL` entry points are found
- [X] T038 [P] [US1] In `test_discovery.py::test_go_fixture_entry_points` assert `http.HandleFunc` is found as an `HTTP_ROUTE` entry point with language `go`
- [X] T039 [P] [US1] In `test_discovery.py::test_subprocess_tainted_fixture_candidate` assert a subprocess candidate finding exists at the right file/line with `source=TREE_SITTER_STRUCTURAL` and `category=TAMPERING`
- [X] T040 [P] [US1] In `test_discovery.py::test_data_stores_from_fixtures` assert the Go fixture produces a `DataStore(technology="postgresql")` finding from the `sql.Open("postgres", ...)` call and that its `import_evidence` is populated
- [X] T041 [US1] In `test_discovery.py::test_red_herrings_produce_zero_findings` load every file in `fixtures/red_herrings/`, run full `discover_all`, assert `len(findings) == 0` and the `DiscoveryResult` entry-point/data-store lists are empty. This is the regression test for SC-001
- [X] T042 [US1] In `test_discovery.py::test_dogfood_no_phantom_postgres` run `discover_all` against `packages/darnit-gittuf/src/darnit_gittuf/handlers.py` (which contains `gpg.ssh.allowedSignersFile` in a docstring) and assert no PostgreSQL data store is reported from that file

**Checkpoint**: Story 1 complete. Running `discover_all` against fixtures produces high-signal findings with zero false positives from the red-herring regression cases. The handler writes a draft (with stub markdown from existing generators), OSPS-SA-03.02 still passes. The core accuracy value is delivered.

---

## Phase 4: User Story 2 — OSPS-SA-03.02 still passes with a better artifact (Priority: P1)

**Goal**: Preserve the compliance contract unconditionally. The handler writes a file at the accepted path on first run, skips on subsequent runs unless `overwrite=True`, and fallback-to-template still works when dynamic analysis fails.

**Independent Test**: Run `audit_openssf_baseline → remediate_audit_findings → audit_openssf_baseline` against a clean repo fixture and assert OSPS-SA-03.02 transitions FAIL → PASS. Run it twice and assert the second run returns `action="skipped"`. Force a tree-sitter import failure via monkeypatch and assert the fallback template path still returns PASS.

### Implementation

- [X] T043 [US2] Verify the current `remediation.py::generate_threat_model_handler` file-write semantics match `contracts/handler-contract.md`: path resolution via `os.path.join(context.local_path, config["path"])`, skip-if-exists behavior when `config.get("overwrite", False) == False`, fallback-to-template behavior when dynamic analysis raises. Fix any drift that crept in during the US1 refactor
- [X] T044 [US2] In `remediation.py`, extend the fallback path so that even when dynamic analysis raises, the `HandlerResult.evidence` includes `file_scan_stats={"total_files_seen": 0, "in_scope_files": 0, ...}` and `opengrep_available=False` stubs, so downstream consumers of evidence never see `KeyError` regardless of which path ran
- [X] T045 [US2] In `remediation.py`, ensure `evidence["llm_verification_required"]` is set `True` on `action="created"` and **not set** on `action="skipped"` or `action="created_from_template"` per the handler contract

### Tests for US2

- [X] T046 [P] [US2] Create `tests/darnit_baseline/threat_model/test_handler.py::test_writes_file_at_configured_path` — pass `config={"path": "THREAT_MODEL.md", ...}` with a tmp repo dir, assert the file exists after invocation and is non-empty
- [X] T047 [P] [US2] In `test_handler.py::test_skip_if_exists_default` create a pre-existing `THREAT_MODEL.md` with sentinel content, invoke the handler with `overwrite=False`, assert file is untouched, result is `PASS`, `action="skipped"`, `evidence["llm_verification_required"]` is NOT set
- [X] T048 [P] [US2] In `test_handler.py::test_overwrite_true_replaces_file` create a pre-existing file, invoke with `overwrite=True`, assert file was replaced, result is `PASS`, `action="created"`, `evidence["llm_verification_required"] is True`
- [X] T049 [P] [US2] In `test_handler.py::test_fallback_to_template_on_discovery_failure` monkeypatch `discovery.discover_all` to raise, invoke with `config["content"]=<template>`, assert result is `PASS`, `action="created_from_template"`, file contains the template content, `evidence["fallback_reason"]` is populated
- [X] T050 [P] [US2] In `test_handler.py::test_error_when_no_path` invoke with `config={}` and assert `HandlerResultStatus.ERROR` with message mentioning missing path
- [X] T051 [US2] End-to-end compliance test `test_handler.py::test_sa0302_audit_remediate_audit_cycle`: use a tmp fixture repo, run the baseline audit for SA-03.02 via the orchestrator and assert FAIL, run remediation via the handler, re-run audit, assert PASS. This is the SC-004 regression

**Checkpoint**: Story 2 complete. The compliance contract is preserved. Pre-existing user drafts are never destroyed without explicit opt-in. Fallback path still produces a valid compliance artifact if dynamic analysis ever breaks.

---

## Phase 5: User Story 4 — Calling-agent verification contract is preserved (Priority: P1)

**Goal**: The draft's Markdown structure exactly matches `contracts/output-format-contract.md` — required sections, embedded code snippets per finding, verification prompt block with the HTML comment marker, and SARIF/JSON outputs describing the same finding set. This is what lets the existing `darnit-remediate` skill's review instructions work unchanged.

**Independent Test**: Generate a draft for a fixture, parse the Markdown headings, and assert all 9 required top-level sections exist in order. Assert the `<!-- darnit:verification-prompt-block -->` marker appears exactly once. Generate SARIF and JSON for the same fixture and assert finding counts match the Markdown.

### Implementation

- [X] T052 [US4] Rewrite `packages/darnit-baseline/src/darnit_baseline/threat_model/generators.py::generate_markdown_threat_model` to emit the 9 required sections from `contracts/output-format-contract.md` in the specified order: `# Threat Model Report`, `## Executive Summary`, `## Asset Inventory` (with `### Entry Points`, `### Data Stores`, `### Authentication Mechanisms` subsections), `## Data Flow Diagram`, `## STRIDE Threats` (with the six category subsections), `## Attack Chains`, `## Recommendations Summary`, `## Verification Prompts`, `## Limitations`
- [X] T053 [US4] In `generators.py`, implement `_render_finding(finding: CandidateFinding) -> str` producing the per-finding Markdown block: `#### TM-<CATEGORY>-<NNN>: <title>`, severity/confidence line, file:line, fenced code block with `>>>` marker on the marker line, source query id, optional Data Flow fenced block when `finding.data_flow is not None`
- [X] T054 [US4] In `generators.py`, implement `_render_verification_prompts() -> str` that emits the instruction block wrapped in `<!-- darnit:verification-prompt-block -->` HTML comments per `output-format-contract.md`. Content instructs the calling agent to review each finding against its embedded snippet, remove false positives, refine narratives, and preserve category headings
- [X] T055 [US4] In `generators.py`, implement `_render_limitations(file_scan_stats, trimmed_overflow, opengrep_result) -> str` producing the required Limitations content: languages scanned, file counts, Opengrep availability, shallow-mode indicator and skipped analyses, per-category trimmed-overflow counts, boilerplate threat-modeling-aid note
- [X] T056 [US4] In `generators.py`, implement `_render_dfd(entry_points, data_stores, call_graph) -> str` producing a Mermaid `flowchart LR` from structural data. Simplify when nodes >50. In shallow mode, emit a "DFD omitted in shallow mode" note instead
- [X] T057 [US4] Rewrite `packages/darnit-baseline/src/darnit_baseline/threat_model/generators.py::generate_sarif_threat_model` to consume the new `CandidateFinding` shape and emit SARIF 2.1.0 per `output-format-contract.md`: ruleId=query_id, level mapped from severity, physicalLocation with region + contextRegion + snippet, properties including `dataFlowTrace` and `source`, rules array in `tool.driver`
- [X] T058 [US4] Rewrite `generators.py::generate_json_summary` to emit a pretty-printed JSON serialization of `FileScanStats`, the list of `EntryPoint`, `DataStore`, `CandidateFinding` (capped), and `TrimmedOverflow`. Use `dataclasses.asdict` with enum-value serialization
- [X] T059 [US4] Update `remediation.py` so the handler calls the new `generate_markdown_threat_model` signature with the discovery result, ranked-and-capped findings, trimmed overflow, and file-scan stats. Ensure the file written to disk is the Markdown output

### Tests for US4

- [X] T060 [P] [US4] Create `tests/darnit_baseline/threat_model/test_generators.py::test_required_sections_present` — generate a draft for `fastapi_minimal`, parse H2 headings, assert all 9 required sections appear in order
- [X] T061 [P] [US4] In `test_generators.py::test_verification_prompt_marker` assert the rendered Markdown contains exactly one occurrence of `<!-- darnit:verification-prompt-block -->` and one of `<!-- /darnit:verification-prompt-block -->` (or equivalent closing marker if that's the chosen format)
- [X] T062 [P] [US4] In `test_generators.py::test_finding_has_code_snippet_with_marker` pick any finding from the `subprocess_tainted` fixture draft, assert its rendered block contains a fenced code block where the marker line starts with `>>>` and surrounding lines do not
- [X] T063 [P] [US4] In `test_generators.py::test_sarif_finding_count_matches_markdown` count findings in the Markdown (via STRIDE subsection entries) and in the SARIF `results[]` array, assert equal
- [X] T064 [P] [US4] In `test_generators.py::test_json_serialization_shape` assert the JSON output contains the documented top-level keys: `file_scan_stats`, `entry_points`, `data_stores`, `findings`, `trimmed_overflow`
- [X] T065 [P] [US4] In `test_generators.py::test_limitations_section_surfaces_evidence` generate a draft with a synthetic `TrimmedOverflow` and `FileScanStats(shallow_mode=True, ...)`, assert the Limitations section text contains the overflow counts and "shallow" indicator
- [X] T066 [US4] In `test_handler.py::test_skill_review_contract_preserved` compare the draft sections against the list in `contracts/output-format-contract.md`. This is the SC-005 regression — guarantees the `darnit-remediate` skill's review flow works unchanged

**Checkpoint**: Story 4 complete. The draft's structural contract is preserved byte-for-byte in the sections that matter. The calling agent's skill-driven review flow works without changes. SARIF and JSON consumers get consistent output.

---

## Phase 6: User Story 3 — Graceful behavior when Opengrep is absent (Priority: P2)

**Goal**: Opengrep enrichment works when the binary is installed, and the pipeline cleanly degrades to tree-sitter-only when it isn't — without introducing any new incorrect findings.

**Independent Test**: Run the handler in two environments (Opengrep present, Opengrep absent). Assert both return `PASS`. Assert the "without" draft findings are a strict subset of the "with" draft findings. Assert the `evidence["opengrep_available"]` flag and the Limitations section both reflect availability.

### Bundled Opengrep rules

- [X] T067 [P] [US3] Create `packages/darnit-baseline/src/darnit_baseline/threat_model/opengrep_rules/entry_points.yaml` with FastAPI, Flask, Express, Go `http.HandleFunc`, and MCP tool decorator rules per research §8. Each rule has an id matching a `CandidateFinding.query_id` convention
- [X] T068 [P] [US3] Create `opengrep_rules/data_stores.yaml` with rules for `sqlite3.connect`, `redis.Redis`, `psycopg.connect`, `pymongo.MongoClient`, SQLAlchemy `create_engine`
- [X] T069 [P] [US3] Create `opengrep_rules/taint_external_input.yaml` with `mode: taint` rules: sources = `request.*`, `os.environ[...]`, `sys.argv`; sinks = `subprocess.run`, `os.system`, `eval`, `exec`; sanitizers = `shlex.quote`, `shlex.split`
- [X] T070 [P] [US3] Create `opengrep_rules/config_loaders.yaml` with taint rules from `tomllib.load`, `yaml.safe_load`, `json.load` sources to subprocess sinks
- [X] T071 [US3] Validate all four rule files by running `opengrep scan --config <rules_dir> --json <small_fixture>` manually and confirming zero `errors[]` entries

### Opengrep integration into discovery

- [X] T072 [US3] In `discovery.py::discover_all`, after tree-sitter discovery, call `opengrep_runner.run_opengrep(repo_root, rules_dir, timeout_s=120)` using `importlib.resources.files("darnit_baseline.threat_model").joinpath("opengrep_rules")` + `as_file()` to resolve the rules directory (handles zipped wheels)
- [X] T073 [US3] In `discovery.py`, implement `_normalize_opengrep_findings(raw: list[dict]) -> list[CandidateFinding]` mapping Opengrep JSON entries to `CandidateFinding` with `source=OPENGREP_PATTERN` or `source=OPENGREP_TAINT` depending on whether the rule has `mode: taint`, `query_id = result["check_id"]`, location from `start`/`end`, `code_snippet` from `extra.lines` plus file context, `data_flow` from `extra.dataflow_trace` when present
- [X] T074 [US3] In `discovery.py`, join Opengrep findings with tree-sitter findings by `(file, line)` deduplication key: if a tree-sitter subprocess candidate already exists at a location where Opengrep has a taint finding, prefer the taint finding (it has higher confidence and includes the data-flow trace), keeping the original `primary_location` but overwriting `source` and `data_flow`
- [X] T075 [US3] In `remediation.py`, surface `opengrep_available`, `opengrep_degraded_reason`, and `binary_used` / `version` (from `OpengrepResult`) in `HandlerResult.evidence` per the handler contract

### Tests for US3

- [X] T076 [P] [US3] In `test_discovery.py::test_opengrep_enriches_subprocess_taint` mock `opengrep_runner.run_opengrep` to return a synthetic `OpengrepResult` with a taint finding matching the `subprocess_tainted` fixture location, run `discover_all`, assert the merged finding has `source=OPENGREP_TAINT` and `data_flow is not None`
- [X] T077 [P] [US3] In `test_discovery.py::test_without_opengrep_findings_are_strict_subset` run `discover_all` twice against the same fixture: once with a mocked `OpengrepResult(available=True, findings=[...])`, once with `OpengrepResult(available=False)`. Assert the "without" findings set is contained in the "with" findings set (SC-007 regression)
- [X] T078 [P] [US3] In `test_handler.py::test_handler_sets_opengrep_evidence_flags` invoke the handler with Opengrep present (mocked) and absent (mocked); in both cases assert `evidence["opengrep_available"]` reflects reality and the message is reasonable
- [X] T079 [P] [US3] In `test_generators.py::test_limitations_mentions_opengrep_degradation` when `OpengrepResult(available=False, degraded_reason="opengrep/semgrep binary not installed")`, assert the Limitations section of the generated Markdown contains language about the missing binary

**Checkpoint**: Story 3 complete. Opengrep enrichment works when installed, cleanly degrades when not. SC-007 (no incorrect findings without Opengrep) is enforced by a regression test.

---

## Phase 7: Cross-cutting — shallow mode, finding cap, STRIDE mapping, attack chains, patterns.py deletion

**Purpose**: The features that span multiple stories and can be delivered once the story-specific tasks are complete.

### Shallow mode

- [X] T080 In `discovery.py::discover_all`, after `file_discovery.walk_repo` completes, check `len(in_scope_files) > config.get("shallow_threshold", 500)`. If so, set `shallow_mode=True` on `FileScanStats` and pass a "shallow" flag through to subsequent discovery functions
- [X] T081 In `discovery.py`, when `shallow_mode=True`: run only entry-point and data-store queries (skip subprocess candidates, call graph, auth decorators), use `snippet_context_lines=5` instead of 10, and skip `chains.detect_attack_chains` entirely
- [X] T082 In `generators.py::_render_limitations`, when `shallow_mode=True`, clearly state that shallow mode was activated because of file count, list the analyses that were reduced or skipped, and report the `in_scope_files` number
- [X] T083 [P] Create `tests/darnit_baseline/threat_model/fixtures/large_repo_shallow/README.md` describing how to generate the fixture, plus `tests/darnit_baseline/threat_model/fixtures/scripts/generate_large_repo.py` that produces 600 synthetic Python files (simple `def f(): pass` stubs) under a tmp dir for shallow-mode tests. Do not check in the generated files themselves
- [X] T084 [P] In `test_discovery.py::test_shallow_mode_activates_above_threshold` call the generator script via a pytest fixture, run `discover_all` on the result, assert `file_scan_stats["shallow_mode"] is True`, attack chains are empty, code snippet context is narrower, only entry-point and data-store findings are present

### STRIDE mapping

- [X] T085 Rewrite `packages/darnit-baseline/src/darnit_baseline/threat_model/stride.py::map_to_stride(finding_candidates, entry_points, data_stores) -> list[CandidateFinding]` as a deterministic mapping table. Subprocess with taint → Tampering + EoP (emit two findings). Subprocess without taint → Tampering only. Unauthenticated entry point → Spoofing. Data store without encryption-at-rest annotation → Information Disclosure (low confidence). Preserve the existing `enrich_threats_with_code_context` function for code snippet population — rename if needed but keep the behavior
- [X] T086 [P] In `test_discovery.py::test_stride_mapping_subprocess_taint` assert a taint finding produces both Tampering and EoP candidates at the same location

### Attack chains

- [X] T087 Update `packages/darnit-baseline/src/darnit_baseline/threat_model/chains.py::detect_attack_chains` to consume the new `CandidateFinding` shape. Logic is unchanged from the existing implementation: findings that share an asset and span multiple STRIDE categories form a chain. Skip entirely when `shallow_mode=True`
- [X] T088 [P] In `test_discovery.py::test_attack_chain_detection` use the `subprocess_tainted` fixture (which after US3 produces both a Tampering taint finding and a Spoofing finding on the same `request.query_params` entry point) and assert a chain is detected

### Scenarios

- [X] T089 Update `packages/darnit-baseline/src/darnit_baseline/threat_model/scenarios.py::get_scenario(finding: CandidateFinding) -> Scenario` to consume the new finding shape. Scenario templates remain deterministic — the calling agent refines them during verification

### Delete patterns.py

- [X] T090 Delete `packages/darnit-baseline/src/darnit_baseline/threat_model/patterns.py` entirely. Verify no imports reference it anywhere under `packages/darnit-baseline/`

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, lint, dogfood verification, and commit gates.

- [X] T091 [P] Update `README.md` and/or `docs/` to document Opengrep as an optional prerequisite for the threat model generator, with install instructions from research §5
- [X] T092 [P] Update `CLAUDE.md` "Active Technologies" section to reference the new tree-sitter dependencies (the `update-agent-context.sh` script already added entries; verify and tighten wording)
- [X] T093 Run `uv run ruff check .` — zero errors. Run `uv run ruff format .` if any formatting nits remain
- [X] T094 Run `uv run pytest tests/darnit_baseline/threat_model/ -v` — all pass
- [X] T095 Run `uv run pytest tests/ --ignore=tests/integration/ -q` — the full non-integration test suite passes (regression check against the rest of darnit-baseline)
- [X] T096 Run `uv run python scripts/validate_sync.py --verbose` — spec-implementation sync passes (this spec change should not touch `openspec/specs/framework-design/spec.md`, so a clean sync is expected)
- [X] T096a Verify `packages/darnit-baseline/openssf-baseline.toml` is unchanged by this feature. Run `git diff upstream/main -- packages/darnit-baseline/openssf-baseline.toml` (or compare against the branch base `009-context-aware-remediation` if upstream is not yet up to date). Confirm the `[controls."OSPS-SA-03.02"]` section and its remediation block are not modified. Guards Constitution III (TOML-First Architecture)
- [X] T097 Run `uv run python scripts/generate_docs.py` — regenerate `docs/generated/`. Commit any changes
- [X] T097a Performance benchmark for SC-006: synthesize a 300-file fixture repo by reusing `tests/darnit_baseline/threat_model/fixtures/scripts/generate_large_repo.py` with `num_files=300`. Run `discover_all` against it and measure wall-clock time via `time.perf_counter()`. Assert the elapsed time is under 120 seconds on a machine matching the FR-022 baseline profile (4 cores, 8 GB RAM, SSD). Record the actual elapsed time in the PR body as a baseline for future regression checks
- [X] T097b Syntax-recovery regression test: add a file containing deliberately broken Python syntax (unclosed paren, stray token) to `tests/darnit_baseline/threat_model/fixtures/red_herrings/broken_syntax.py`. Write a test that runs `discover_all` against the red_herrings fixture and asserts (a) it completes without raising, (b) the broken file appears in `file_scan_stats.total_files_seen`, and (c) no findings reference the broken file. Guards FR-019
- [X] T097c No-network assertion test: in `tests/darnit_baseline/threat_model/test_handler.py`, add a test that monkeypatches `urllib.request.urlopen`, `socket.socket.connect`, and `http.client.HTTPConnection.connect` to raise `AssertionError("network call not allowed")`. Run the handler end-to-end against a small fixture (Opengrep-absent mode so no subprocess invocation either). Assert no `AssertionError` is raised. Guards FR-021
- [X] T098 Dogfood SC-001: run `audit_openssf_baseline → remediate_audit_findings → audit_openssf_baseline` against this repo via the MCP tools. Inspect the generated `THREAT_MODEL.md`. Assert no phantom PostgreSQL finding from `gpg.ssh.allowedSignersFile`, no PII finding from `email=data.get("email", "")`, and real findings for subprocess execution in sieve handlers and MCP tool decorators
- [X] T099 Dogfood SC-008: run the full `/darnit-comply` skill against this repo. Count findings Claude strips as false positives during verification. Compare against the current-pipeline count from the most recent pre-rewrite run. Record the delta in the commit message or PR body as evidence of the quality improvement
- [X] T100 Final rebase from upstream before push: `git fetch upstream && git rebase upstream/main`. Resolve any conflicts. Re-run T093–T096 after rebase

---

## Phase 9: Retrospective Fixes (2026-04-12)

**Purpose**: Address gaps found when dogfooding the generated `THREAT_MODEL.md` against darnit itself. The v1 implementation produced a shallow draft: empty asset inventory, 28 identical subprocess findings, 5 of 6 STRIDE categories empty. These tasks close the gap between "tests pass on fixtures" and "useful output on real codebases."

**Prerequisite**: Phase 8 complete (all prior tasks done).

### Imperative entry point detection (FR-001a)

- [ ] T101 Add tree-sitter query `MCP_TOOL_IMPERATIVE` to `queries/python.py` matching `server.add_tool(handler, name=..., ...)` and `mcp.add_tool(...)` imperative call patterns. The query MUST capture the handler argument (for call-graph linkage), the `name` keyword argument (for tool naming), and the whole call expression. Test against a new fixture
- [ ] T102 [P] Add tree-sitter query `HTTP_ROUTE_IMPERATIVE` to `queries/python.py` matching `app.add_url_rule(rule, endpoint, view_func)` and `router.add_route(path, handler)` patterns. Test against a new fixture
- [ ] T103 [P] Create fixture `tests/darnit_baseline/threat_model/fixtures/mcp_server_imperative/server.py` — a minimal MCP server that registers tools via `server.add_tool()` (no decorators). Expected discovery: 2+ MCP_TOOL entry points with framework="mcp" and `source_query="MCP_TOOL_IMPERATIVE"`
- [ ] T104 Wire `MCP_TOOL_IMPERATIVE` into `ts_discovery.py`'s entry-point extraction. When matched, produce `DiscoveredEntryPoint(kind=MCP_TOOL, framework="mcp", source_query="MCP_TOOL_IMPERATIVE", ...)`
- [ ] T105 [P] In `test_ts_discovery.py`, add `test_imperative_mcp_registration_detected` using the T103 fixture. Assert entry points are found with correct kind, framework, and source_query
- [ ] T106 [P] In `test_ts_discovery.py`, add `test_imperative_http_route_detected` using a new fixture with `app.add_url_rule()`. Assert entry points are found

### Empty asset inventory diagnostic (FR-001b)

- [ ] T107 In `ts_discovery.py::discover_all`, after discovery completes, if `len(entry_points) == 0` and `file_scan_stats.in_scope_files > 50`, emit a `logger.warning(...)` with the diagnostic message from FR-001b
- [ ] T108 In `ts_generators.py::_render_asset_inventory`, when entry points list is empty and `file_scan_stats.in_scope_files > 50`, render the diagnostic warning note instead of the bare "No HTTP route handlers detected" text
- [ ] T109 [P] In `test_ts_discovery.py`, add `test_empty_inventory_warning_on_large_repo` that runs discovery against a fixture with 60+ Python files but no recognized entry-point patterns. Assert the warning is logged (use `caplog`)

### Subprocess finding differentiation (FR-004a)

- [ ] T110 In `queries/python.py`, update the post-processing for `DANGEROUS_ATTRIBUTE_CALL` to classify each `subprocess.run()` match into one of three tiers based on argument shape: (a) STATIC — first argument is a list literal where all elements are string literals, (b) PARAMETERIZED — first argument is a list containing at least one non-literal element (variable, f-string, call), (c) DYNAMIC — first argument is a bare variable or call expression. Store the tier as a field on the finding
- [ ] T111 In `ranking.py`, adjust the severity × confidence heuristic so that STATIC subprocess calls score severity=1, confidence=0.2 (INFO-level, likely filtered by cap); PARAMETERIZED calls score severity=3, confidence=0.6; DYNAMIC calls score severity=6, confidence=0.8. These replace the current flat severity=1.8 for all subprocess findings
- [ ] T112 [P] In `test_ranking.py`, add `test_subprocess_tiered_scoring` with three synthetic findings (one per tier). Assert STATIC < PARAMETERIZED < DYNAMIC in final score and that STATIC findings would be excluded by a cap of 10 when higher-tier findings exist
- [ ] T113 [P] In `test_ts_discovery.py`, add `test_subprocess_tiers_on_darnit_repo` that runs discovery against the actual darnit repo (using the real `packages/` directory as target). Assert that: (a) at least one STATIC finding exists (e.g., `["git", "init"]`), (b) at least one DYNAMIC finding exists (e.g., `resolved_cmd` in `builtin_handlers.py`), (c) their scores differ. This is the SC-001b regression test

### TOML-driven command construction detection (FR-004b)

- [ ] T114 Add a heuristic to `ts_discovery.py` that flags subprocess calls where the command argument variable is assigned from a dict/config lookup within the same function scope. Implementation: for each DYNAMIC-tier subprocess finding, walk the enclosing function's AST for assignment statements where the RHS is a subscript expression (dict access) or a method call on a dict-like object (`.get()`, `.items()`). If found, elevate the finding's confidence to 0.9 and add a note to the rationale
- [ ] T115 [P] Create fixture `tests/darnit_baseline/threat_model/fixtures/config_driven_subprocess/app.py` — a function that reads command parts from a config dict and passes them to `subprocess.run()`. Expected: one DYNAMIC finding with elevated confidence
- [ ] T116 [P] In `test_ts_discovery.py`, add `test_config_driven_subprocess_elevated` using the T115 fixture. Assert the finding has confidence >= 0.9 and the rationale mentions config-driven construction

### Self-scan dogfood validation (SC-001a, SC-001b, SC-009)

- [ ] T117 In `test_ts_discovery.py`, add `test_self_scan_finds_entry_points` (SC-001a): run `discover_all` against the actual repo root. Assert `len(entry_points) >= 5`. This test MUST NOT be skipped in CI — it is the primary integration test for the feature
- [ ] T118 [P] In `test_ts_discovery.py`, add `test_self_scan_stride_coverage` (SC-009): run `discover_all` and build the STRIDE mapping against the actual repo. Assert at least 3 of 6 STRIDE categories contain findings
- [ ] T119 [P] In `test_ts_discovery.py`, add `test_self_scan_subprocess_differentiation` (SC-001b): run `discover_all` against the actual repo. Collect all subprocess findings. Assert `max(scores) > min(scores)` — i.e., not all scores are identical

### Fixture-reality alignment (SC-002a)

- [ ] T120 Add the T103 `mcp_server_imperative` fixture to the SC-002 curated fixture suite. Update the `test_curated_fixture_90pct_recall` test to include it in the expected-risk count

---

## Dependencies & Execution Order

### Phase dependencies

- **Phase 1 (Setup)**: No dependencies. Start immediately.
- **Phase 2 (Foundational)**: Depends on Phase 1. **BLOCKS all user stories.**
- **Phase 3 (US1 — MVP)**: Depends on Phase 2. Delivers the core discovery accuracy value.
- **Phase 4 (US2)**: Depends on Phase 2, loose dependency on Phase 3 (US2 tests exercise the handler which routes through discovery).
- **Phase 5 (US4)**: Depends on Phase 2, loose dependency on Phase 3 (US4 tests generate drafts from discovered findings).
- **Phase 6 (US3)**: Depends on Phase 2. Can run in parallel with Phase 5 once Phase 3 is done.
- **Phase 7 (cross-cutting)**: Depends on Phases 3, 5, 6 being complete (needs the discovery pipeline, generators, and Opengrep integration all in place).
- **Phase 8 (Polish)**: Depends on Phase 7 being complete.
- **Phase 9 (Retrospective Fixes)**: Depends on Phase 8. Addresses gaps found during real-world dogfooding.

### User story dependencies

- **US1 (P1, MVP)**: Deep dependency on Phase 2 foundations. All other stories ride on this one functionally.
- **US2 (P1)**: Independent of US1 in principle (tests the handler contract), but US2's tests become meaningful once US1's discovery produces real findings. Can start in parallel with US1 using the US1 discovery stubs, with the final regression (T051) landing after US1 is done.
- **US4 (P1)**: Independent of US1 for generator rewrite, but end-to-end tests need US1 findings to be meaningful. Can start in parallel with US1.
- **US3 (P2)**: Depends on US1 because Opengrep findings are merged into the tree-sitter result shape that US1 defines.

### Within each user story

- Test fixtures (hand-authored source files) can be created first and in parallel.
- Tree-sitter queries and discovery orchestration within US1 have an internal ordering: queries (T025–T028) before discovery functions that use them (T029–T033).
- Output format generators within US4 have ordering: individual `_render_*` helpers (T053–T056) before the top-level `generate_markdown_threat_model` rewrite (T052) — or write the top-level first and fill helpers in. Either order works; tests cover both.

### Parallel opportunities

- **Phase 1**: T004, T005, T006 all create different files — all can run in parallel after T003 completes.
- **Phase 2**: T008 must complete first (types used by everything else). Then T010 (parsing), T012 (file_discovery), T014 (ranking), T016 (opengrep runner) can run in parallel — they share `models.py` but touch separate files.
- **Phase 3 (US1)**: Fixture creation T019–T024 all parallelizable. Per-language query files T025–T028 parallelizable. Discovery function tests T035–T042 all parallelizable.
- **Phase 4 (US2)**: Handler tests T046–T050 all parallelizable.
- **Phase 5 (US4)**: Generator tests T060–T065 all parallelizable.
- **Phase 6 (US3)**: Rule files T067–T070 parallelizable. Tests T076–T079 parallelizable.
- **Phase 7**: T083 (fixture script) parallel with rest.
- **Phase 8**: T091, T092 can run in parallel.

---

## Parallel Example: User Story 1 (test fixtures)

```bash
# After Phase 2 is complete, kick off fixture creation in parallel:
# T019 (fastapi), T020 (flask), T021 (mcp), T022 (go), T023 (subprocess), T024 (red_herrings)
# Each is a different directory, zero shared files. All can be authored by separate workers / in separate sessions.
```

## Parallel Example: Foundational

```bash
# After T008 (models.py) completes:
# T010 (parsing.py) + T012 (file_discovery.py) + T014 (ranking.py) + T016 (opengrep_runner.py) in parallel
# Each file is independent; tests (T011, T013, T015, T017) follow in their own parallel batch
```

---

## Implementation Strategy

### MVP scope (ship after Phase 3 + Phase 4 + the minimal Phase 5 scaffold)

User Story 1 (tree-sitter discovery) + User Story 2 (handler contract) + the structural minimum of User Story 4 (enough generator output that the committed file is valid Markdown with required sections) is the smallest shippable slice that delivers the spec's core value:

- Accurate discovery (SC-001, SC-002)
- Compliance contract preserved (SC-004)
- Skill review flow unchanged (SC-005)

This slice does not yet have Opengrep taint enrichment (US3, P2) or the full verification-prompt block formatting polish, but it is a complete replacement for the current pipeline and produces strictly better drafts.

### Incremental delivery

1. **Phase 1–2 (Setup + Foundational)**: Plumbing. Nothing user-facing ships yet.
2. **Phase 3 (US1)**: Ship the discovery accuracy improvement. Users see a better draft. *This is the real goal of the feature.*
3. **Phase 4 (US2)**: Ship the handler contract preservation. Users see the compliance contract unchanged. *Safety net.*
4. **Phase 5 (US4)**: Ship the full output-format contract compliance. Users see the calling-agent verification flow working unchanged. *Polish.*
5. **Phase 6 (US3)**: Ship Opengrep enrichment. Users with Opengrep installed see taint-flow findings. *Enhancement.*
6. **Phase 7 (cross-cutting)**: Ship shallow mode, STRIDE mapping, attack chains, and the `patterns.py` deletion. *Completeness.*
7. **Phase 8 (Polish)**: Docs, lint, dogfood verification, spec sync. *Quality gates.*

8. **Phase 9 (Retrospective Fixes)**: Ship imperative registration detection, subprocess differentiation, empty-inventory diagnostics, and self-scan validation. *Closes the gap between "tests pass" and "useful output on real codebases."*

Each phase leaves the repo in a shippable state (tests pass, control passes, no regressions).

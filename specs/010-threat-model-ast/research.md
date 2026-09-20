# Phase 0: Research & Decisions

Resolved technical decisions derived from the specification and prior research against the tree-sitter and Opengrep ecosystems.

## 1. Tree-sitter package selection

**Decision**: Use `tree-sitter>=0.25` + `tree-sitter-language-pack>=1.5`.

**Rationale**:
- `tree-sitter-language-pack` bundles pre-built wheels for 100+ languages including Python, JavaScript, TypeScript (both `.ts` and `.tsx`), Go, YAML, and TOML. A single dependency replaces six individual grammar packages and eliminates per-grammar version skew. `tree-sitter-typescript` individually is currently one version behind the current tree-sitter core release; the language-pack handles that.
- Exposes a uniform `get_language(name)` / `get_parser(name)` API, so query code can be parameterized by language name without per-language glue.
- Tree-sitter core 0.25 is the current stable API after the significant 0.22 rewrite. Earlier examples on the internet use deprecated APIs (`query.captures()` on `Query` rather than `QueryCursor`, `Node.sexp()`, `Language(lib_path, name)` constructor). All new code must use the 0.25 idioms.

**Alternatives considered**:
- Individual grammar packages (`tree-sitter-python`, `tree-sitter-javascript`, etc.). Rejected: six dependencies with divergent release cadences, and at least one grammar (typescript) currently behind core.
- `tree-sitter-languages` (the older package). Rejected: stuck on pre-0.22 API, incompatible with current tree-sitter core.
- `libcst`. Rejected: Python-only, and we need multi-language parsing. Libcst's metadata providers are overkill for read-only analysis.

## 2. Tree-sitter API idioms to use

**Decision**: Use `Parser(language)` constructor, `Query(language, sexpr)` + `QueryCursor(query).matches(root)` for execution.

**Rationale**:
- `Parser.set_language()` is deprecated; the constructor form is idiomatic in 0.25.
- `query.captures()` and `query.matches()` directly on `Query` are gone or deprecated; execution goes through `QueryCursor`.
- Capture results are `dict[str, list[Node]]` — always index `[0]` (or iterate) even when there is one match. This is the subtle gotcha that trips up migrations from older bindings.
- Queries must be constructed as module-level constants and reused across files (query construction is not cheap relative to execution).

**Alternatives considered**:
- Walking the tree manually via `root_node.walk()`. Rejected: much more verbose, easier to introduce bugs, no predicate filtering in C code.

## 3. Error recovery on malformed files

**Decision**: Never wrap `parser.parse()` in `try/except`. Tree-sitter handles malformed input natively.

**Rationale**:
- `parser.parse(content)` never raises on syntactically invalid input. It produces a tree with `ERROR` and `MISSING` nodes inserted to continue parsing, and queries still work on the recoverable portions.
- Check `tree.root_node.has_error` for diagnostic logging but still process captures.
- This is precisely the behavior FR-019 requires ("recover from syntax errors in individual source files and continue analyzing the remainder of the repository").

**Alternatives considered**:
- Skipping files with any parse errors. Rejected: throws away recoverable signal for no benefit.

## 4. Parallelism strategy

**Decision**: Serial parsing in v1. Defer parallelism until measured bottleneck.

**Rationale**:
- Measured parse cost for tree-sitter on typical Python files is ~1–2 ms per file. 500 files serial = ~0.5–1.0 s. Well under the 2-minute SC-006 budget.
- `Parser` and `QueryCursor` are not thread-safe; parallelism would require `multiprocessing.Pool` or per-thread parser instances. Complexity not justified at current scale.
- Opengrep's own `--jobs` flag handles parallelism within its own process if needed.

**Alternatives considered**:
- `multiprocessing.Pool` with per-worker parsers. Rejected for v1: complexity tax for speedup we don't need yet.

## 5. Opengrep invocation pattern

**Decision**: Subprocess invocation with a fixed argument vector, always use `--json --quiet --disable-version-check --metrics=off`, always inspect the `errors[]` array even on exit 0.

**Rationale**:
- `--quiet` suppresses progress bars that otherwise pollute stderr capture.
- `--disable-version-check` prevents network calls (matches FR-021).
- `--metrics=off` prevents telemetry.
- **Critical gotcha**: rule schema errors surface in the JSON `errors[]` array with exit code 0. Treating exit code alone as success will silently swallow broken rules. The runner must check `len(data["errors"]) > 0` and log appropriately (FR-018).
- Empirically measured performance on darnit itself: ~1.9 s for 116 Python files with 9 rules, ~200–400 ms cold start.

**Alternatives considered**:
- Using Opengrep's `--sarif` format instead of `--json`. Rejected: SARIF output loses the `metavars` and `dataflow_trace` fields needed for taint findings.
- Using the `semgrep` Python PyPI package directly. Rejected: darnit should not depend on Semgrep's commercial-license ecosystem. Keep it subprocess-only.

## 6. Opengrep detection and fallback

**Decision**: `shutil.which("opengrep") or shutil.which("semgrep")`. Fall through to tree-sitter-only mode if neither is present.

**Rationale**:
- Opengrep was forked from Semgrep CE 1.100 in January 2025. Rules and JSON output schemas are fully compatible. Users with Semgrep installed get the same benefit.
- `shutil.which` is the standard detection pattern in darnit (`gh` CLI detection in `tools.py` uses the same approach).
- Missing binary is not an error — it's a documented optional prerequisite. Log a warning via `darnit.core.logging`, set a flag in `HandlerResult.evidence`, and the draft's Limitations section notes the degradation.

**Alternatives considered**:
- Requiring Opengrep as a hard dependency. Rejected: contradicts Story 3 and FR-016.
- Running Opengrep in a separate thread/process and timing out. Rejected for v1: the simple `subprocess.run` with a wall-clock timeout is sufficient and matches existing patterns.

## 7. Bundled Opengrep rules

**Decision**: Ship YAML rule files as package data under `packages/darnit-baseline/src/darnit_baseline/threat_model/opengrep_rules/`. Load via `importlib.resources.files(...).joinpath("opengrep_rules")` with `as_file()` to handle zipped-wheel cases.

**Rationale**:
- Bundling with the package removes the need for a network fetch at runtime (FR-021).
- `importlib.resources` handles both installed-from-wheel and editable-install paths uniformly.
- `as_file()` materializes the rules to a temporary directory when the wheel is zipped, so Opengrep can read the files by path as it expects.
- Rules are authored in-tree and version-controlled alongside the Python code that invokes them. Rule changes go through the same review/lint/test gate.

**Alternatives considered**:
- A global rule directory in the user's home. Rejected: adds installation complexity and environmental coupling.
- Downloading rules from a registry at first run. Rejected: violates FR-021 (no network calls).

## 8. Rule authoring scope for v1

**Decision**: Ship four rule files for the common attack-surface patterns darnit cares about.

| File | Purpose | Rules |
|------|---------|-------|
| `entry_points.yaml` | Identify callable attack surface | FastAPI routes, Flask routes, Express routes, Go `http.HandleFunc`, MCP `@server.tool` decorators |
| `data_stores.yaml` | Identify real data store construction | `sqlite3.connect`, `redis.Redis`, `psycopg.connect`, `pymongo.MongoClient`, SQLAlchemy `create_engine` |
| `taint_external_input.yaml` | Intra-procedural taint from user input to dangerous sinks | Source: `request.*`, `os.environ[...]`, `sys.argv`; sink: `subprocess.run`, `os.system`, `eval`, `exec`; sanitizer: `shlex.quote` |
| `config_loaders.yaml` | Config-driven command construction | `tomllib.load`, `yaml.safe_load`, `json.load` whose output reaches subprocess sinks |

**Rationale**: These cover the real attack surface the current pipeline misses (subprocess execution via TOML handlers, MCP tool handlers), stay within Opengrep 1.6.0's intra-procedural capability, and are small enough to maintain and test exhaustively.

**Alternatives considered**:
- Importing the existing `semgrep-rules` / `opengrep-rules` repositories wholesale. Rejected: rule volume defeats the top-50 finding cap, and the license on `semgrep-rules` restricts redistribution.

## 9. Tree-sitter query scope for v1

**Decision**: Author queries for each language covering the categories in the table below. Queries live as module-level constants in `queries/<language>.py`.

| Category | Python queries | JS/TS queries | Go queries | YAML queries |
|----------|----------------|---------------|------------|--------------|
| Entry points | FastAPI `@app.get/post/...`, Flask `@app.route`, MCP `@server.tool`, `click`/`argparse` dispatch | Express `app.get/post/...`, Next.js API routes, Fastify | `http.HandleFunc`, chi/gorilla `r.Get/Post/...` | workflow `on:` blocks |
| Data stores | `sqlite3.connect`, `psycopg*.connect`, `redis.Redis`, `pymongo.MongoClient`, `boto3.client`, SQLAlchemy `create_engine` | `new Client()` constructors, `mongoose.connect`, `redis.createClient` | `sql.Open("<driver>", ...)` | — |
| Imports | `import X` / `from X import Y` | ES `import` / CJS `require` | `import` specs | — |
| Subprocess candidates | `subprocess.run/call/Popen`, `os.system`, `os.popen`, `eval`, `exec` | `child_process.*`, `eval` | `exec.Command` | — |
| Auth mechanisms | Decorators containing "auth"/"login_required"/"jwt" on function definitions | Middleware calls, passport/clerk/nextauth imports | middleware registrations | — |
| Call graph adjacency | Function definition names + call sites within the same module | Function definitions + call sites | Function definitions + call sites | — |

**Rationale**: These map 1:1 to the finding categories the Markdown generator already renders. No speculative queries for categories we do not emit. TOML coverage is deliberately narrow — TOML files in scope are usually config, not code.

**Alternatives considered**:
- A single huge query that unions everything. Rejected: query performance is faster with smaller focused queries, and debug diagnostics are easier when failures are per-category.

## 10. Shallow-mode query subset

**Decision**: In shallow mode (>500 in-scope files), run only the "Entry points" and "Data stores" queries. Skip injection-sink, call-graph-adjacency, and auth-mechanism queries. Reduce the per-finding code context window from ±15 to ±5 lines. Skip attack-chain computation entirely.

**Rationale**:
- Entry points and data stores are the highest-signal asset categories and are sufficient to produce a useful asset inventory and DFD.
- Injection sinks at scale produce the most noise (subprocess calls are everywhere); dropping them keeps the draft readable.
- Attack chain computation is O(findings²) over call-graph adjacency; skipping it saves the most time on large repos.
- Limitations section explicitly enumerates what was reduced (FR-026), so the calling agent can advise the user to re-run with a larger cap or on a smaller scope.

**Alternatives considered**:
- Proportional scaling (e.g., half the queries at 2× the threshold). Rejected: introduces a sliding scale users have to reason about. Binary shallow/full is simpler.

## 11. Vendor directory exclusion list

**Decision**: Exclude a fixed baseline set, plus any directory listed in the repository's `.gitignore` at the root.

**Baseline exclusions**:
- Python: `.venv`, `venv`, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`
- JS/TS: `node_modules`, `dist`, `build`
- Go: `vendor`
- Rust/JVM: `target`
- VCS: `.git`
- General build: `out`, `tmp`

**Rationale**:
- `.gitignore`-listed directories are the project's own declaration of "not my code." Honoring it matches user expectations.
- Baseline list covers language ecosystems even when `.gitignore` is missing or incomplete.
- FR-024 requires this behavior. User can supplement via handler config but cannot disable the defaults.
- Implementation: parse `.gitignore` only at the repository root, not recursively. Full `.gitignore` semantics (negation, wildcards) are deferred to future work; match against directory name prefixes only.

**Alternatives considered**:
- Full `.gitignore` parsing with a library like `pathspec`. Deferred: adds a dependency for marginal benefit at this scope. The simple name-prefix match handles 95% of real-world cases.
- A project-specific `threat-model.exclude` file. Rejected: adds a new config surface with no demonstrated need.

## 12. Finding ranking heuristic

**Decision**: Rank by `severity × confidence` with ties broken by category diversity.

**Severity mapping**:
| Category | Base severity |
|----------|---------------|
| Tampering (with taint trace) | 9 |
| Elevation of Privilege | 9 |
| Information Disclosure (with taint trace) | 8 |
| Tampering (structural only) | 6 |
| Information Disclosure (structural only) | 5 |
| Spoofing (unauthenticated entry point) | 5 |
| DoS | 3 |
| Repudiation | 2 |

**Confidence mapping**:
| Source | Confidence |
|--------|------------|
| Opengrep taint finding with full trace | 1.0 |
| Opengrep structural pattern match | 0.9 |
| Tree-sitter query on constructor call (e.g., `sqlite3.connect`) | 0.9 |
| Tree-sitter query on decorator (e.g., `@app.get`) | 0.85 |
| Tree-sitter query on bare call (e.g., `subprocess.run`) with no taint | 0.6 |

**Tie-break**: When the ranked list is trimmed to the cap, prefer category diversity — after filling the first N ranks, if one category would otherwise dominate (>60% of emitted findings), swap in the next-highest-ranked finding from an underrepresented category. This prevents a repo with 200 subprocess calls from producing a draft that is 100% Tampering.

**Rationale**:
- Simple multiplicative heuristic is transparent and debuggable. No ML model, no trained weights.
- Category diversity tie-break ensures the calling agent sees coverage across STRIDE categories even when one finding type numerically dominates.
- Exact numbers are tunable via the handler config; defaults ship in `ranking.py`.

**Alternatives considered**:
- CVSS-style scoring. Rejected: overkill for a threat-model-draft quality heuristic.
- Pure by-category round-robin. Rejected: would elevate low-severity findings above high-severity ones.

## 13. Code-context window size

**Decision**: Default ±10 lines, ±5 in shallow mode. Configurable via handler config (`snippet_context_lines`).

**Rationale**:
- ±10 lines is enough for a calling agent to see the finding in local context (imports, enclosing function signature, surrounding statements) without bloating the draft.
- Shallow mode uses ±5 to keep the file size manageable at scale.
- The existing `enrich_threats_with_code_context` function in `stride.py` already uses a similar pattern; we reuse its structure and only parameterize the window size.

**Alternatives considered**:
- Full enclosing function body. Rejected: unbounded size, defeats the top-50 finding cap's page-budget goal.

## 14. Handler config keys and backward compatibility

**Decision**: Keep the existing `overwrite: bool` TOML config key as the override flag (not introduce a new `force_overwrite` name). Add new keys `max_findings`, `exclude_dirs`, `snippet_context_lines`, `shallow_threshold`.

**Rationale**:
- The existing handler already uses `overwrite: bool` in `config.get("overwrite", False)`. The spec's use of `force_overwrite` as an example should be resolved in favor of the existing name to avoid a breaking TOML change.
- All new keys are additive with sensible defaults. Existing `openssf-baseline.toml` control definitions continue to work unchanged.

**Alternatives considered**:
- Renaming `overwrite` → `force_overwrite` for clarity. Rejected: breaks any user TOML that has already set `overwrite = true`. The semantics are identical; the name difference isn't worth the churn.

## 15. Test fixture strategy

**Decision**: Small, hand-authored fixture repositories under `tests/darnit_baseline/threat_model/fixtures/`. Each fixture is a few files demonstrating one structural pattern. Tests assert on captured nodes / finding counts / draft sections, not on byte-exact output.

**Rationale**:
- Hand-authored fixtures are trivially auditable. A reviewer can read `fastapi_minimal/main.py` and know exactly what findings should appear.
- Byte-exact output tests would be brittle against Markdown formatting changes. Assert on structural properties (finding count per category, section headers present, evidence flags set).
- A dedicated `red_herrings/` fixture contains the exact patterns that broke the old pipeline: docstrings mentioning "postgresql", variable names containing "email" in metadata parsing, commented-out `eval()` calls. These are regression tests for the false-positive classes enumerated in SC-001.
- `large_repo_shallow/` is generated by a script (not checked in) to produce >500 in-scope files for shallow-mode verification. The script lives under `tests/darnit_baseline/threat_model/fixtures/` with a short README.

**Alternatives considered**:
- Using darnit's own source as the fixture. Partially used for the final dogfood verification (SC-001), but not as the primary unit test harness — changes to darnit's source would cause unrelated test failures.

## 16. Rollout and deletion of `patterns.py`

**Decision**: Full replacement in one PR. Delete `patterns.py` and all regex-based discovery functions in the same change. The existing fallback-to-static-template path in `remediation.py` stays as a safety net.

**Rationale**:
- The spec's Migration decision (confirmed during spec authoring): full replacement, no parallel coexistence.
- Keeping the regex path alongside the tree-sitter path would double test surface and invite drift.
- The static-template fallback in `remediation.py` catches the case where tree-sitter import or Opengrep invocation fails unexpectedly. It is not a parallel code path; it's a crash-safety net.

**Alternatives considered**:
- Feature-flagged coexistence. Rejected: explicitly against the spec's migration decision. Avoids long-lived dual-path tech debt.

---

All NEEDS CLARIFICATION items from the Technical Context have been resolved. Ready for Phase 1.

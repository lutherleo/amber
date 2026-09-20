# Phase 1: Data Model

Entity shapes produced and consumed by the rewritten threat model pipeline. All types live in `packages/darnit-baseline/src/darnit_baseline/threat_model/models.py` and its sibling modules. Python dataclasses with `from __future__ import annotations` and `frozen=True` where immutability is appropriate.

## 1. Core discovery entities (new)

### `Location`

Single source-file position. Reused across all finding/asset types.

```python
@dataclass(frozen=True)
class Location:
    file: str          # repo-relative path, forward slashes
    line: int          # 1-indexed
    column: int        # 1-indexed, inclusive
    end_line: int
    end_column: int
```

**Invariants**: `line >= 1`, `end_line >= line`, `end_column >= column` when `line == end_line`.

### `CodeSnippet`

Source code context attached to each finding/asset for calling-agent verification.

```python
@dataclass(frozen=True)
class CodeSnippet:
    lines: list[str]           # one entry per line, no trailing newline
    start_line: int            # 1-indexed line of lines[0]
    marker_line: int           # the line where the finding/asset was discovered (absolute, 1-indexed)
```

**Invariants**: `len(lines) >= 1`; `start_line <= marker_line < start_line + len(lines)`.

**Usage**: The Markdown generator renders this as a fenced code block with a `>>> ` marker on `marker_line`. The ±N context window is controlled by the handler's `snippet_context_lines` config (default 10, 5 in shallow mode).

### `EntryPointKind` / `DataStoreKind`

Enums identifying the *shape* of a discovered asset. Used for STRIDE mapping and rendering.

```python
class EntryPointKind(str, Enum):
    HTTP_ROUTE = "http_route"          # fastapi, flask, express, go http.Handle
    MCP_TOOL = "mcp_tool"              # @server.tool() decorator OR server.add_tool() imperative call
    CLI_COMMAND = "cli_command"        # click/argparse/cobra entry
    MESSAGE_HANDLER = "message_handler"  # queue consumer, webhook (future)

class DataStoreKind(str, Enum):
    RELATIONAL_DB = "relational_db"    # sqlite, postgres, mysql
    DOCUMENT_DB = "document_db"        # mongodb
    KEY_VALUE = "key_value"            # redis
    OBJECT_STORE = "object_store"      # s3, gcs
    FILE_IO = "file_io"                # plain file writes/reads (future; not v1)
```

### `DiscoveredEntryPoint` (conceptually `EntryPoint`)

A callable attack-surface element discovered in source. Implemented as
`DiscoveredEntryPoint` in `threat_model/discovery_models.py` to avoid a
name clash with the legacy `threat_model.models.EntryPoint` type during
Phases 2–4; Phase 5 will rename or merge.

```python
@dataclass(frozen=True)
class DiscoveredEntryPoint:
    kind: EntryPointKind
    name: str                          # function name or route path
    location: Location
    language: str                      # "python" | "javascript" | "typescript" | "tsx" | "go"
    framework: str | None              # "fastapi" | "flask" | "express" | "mcp" | None
    route_path: str | None             # HTTP route template, if applicable
    http_method: str | None            # "GET" | "POST" | ... if applicable
    has_auth_decorator: bool           # True if decorated with an auth-looking decorator
    source_query: str                  # tree-sitter query id that revealed this asset
    id: str                            # auto-derived from kind/language/location
```

**Invariants** (enforced in `__post_init__`):
- `id` is auto-generated as `f"ep:{language}:{location.file}:{location.line}"` if not explicitly provided. IDs are stable across runs against an unchanged repository.
- `framework` MUST be set when `kind in {HTTP_ROUTE, MCP_TOOL}`. `CLI_COMMAND` and `MESSAGE_HANDLER` may leave `framework=None`.
- `route_path` is set when `framework in {"fastapi", "flask", "express"}` (documentation contract, not enforced programmatically).
- `source_query` is the string id of the query in `queries/<language>.py` that produced the match.

**Registration pattern coverage** *(added 2026-04-12)*: `MCP_TOOL` entry points may be discovered via two distinct code patterns:
1. **Decorator**: `@server.tool()` / `@mcp.tool()` — matched by the `MCP_TOOL_DECORATOR` tree-sitter query.
2. **Imperative**: `server.add_tool(handler, name=..., ...)` — matched by a new `MCP_TOOL_IMPERATIVE` tree-sitter query. The `name` keyword argument provides the tool name; the `handler` argument provides the function reference for call-graph linkage.

Both patterns produce `DiscoveredEntryPoint` instances with `kind=MCP_TOOL, framework="mcp"`. The `source_query` field distinguishes which pattern was matched. Analogous decorator/imperative pairs exist for `HTTP_ROUTE` (e.g., `@app.route()` vs `app.add_url_rule()`) and should be added as coverage gaps are discovered.

**Lifecycle**: Produced by `discovery.discover_entry_points()`. Consumed by `stride.py` (for Spoofing and EoP candidate generation) and `generators.py` (for the Asset Inventory section).

### `DiscoveredDataStore` (conceptually `DataStore`)

A data-storage asset discovered via a real constructor/client call.
Implemented as `DiscoveredDataStore` to avoid a name clash with the legacy
type; see note above.

```python
@dataclass(frozen=True)
class DiscoveredDataStore:
    kind: DataStoreKind
    technology: str                    # "sqlite" | "postgresql" | "redis" | ...
    location: Location                 # where the client/connection is constructed
    language: str
    import_evidence: str | None        # matched import module, if known
    dependency_manifest_evidence: str | None  # matched dep in pyproject/package.json
    source_query: str
    id: str                            # auto-derived from kind/language/location
```

**Invariants** (enforced in `__post_init__`):
- `id` is auto-generated as `f"ds:{language}:{location.file}:{location.line}"` if not explicitly provided.
- At least one of `import_evidence` or `dependency_manifest_evidence` MUST be set. A data store with no corroborating evidence is exactly the low-signal kind of finding the regex pipeline used to produce, and the new pipeline explicitly refuses to emit them.
- Never emitted for string-literal matches inside docstrings/comments (structurally impossible via tree-sitter queries over AST nodes).

**Lifecycle**: Produced by `discovery.discover_data_stores()`. Consumed by `stride.py` (for Information Disclosure candidates) and `generators.py` (Asset Inventory, DFD).

### `CallGraphNode`

Intra-module adjacency record used for DFD rendering and enclosing-function context in findings.

```python
@dataclass(frozen=True)
class CallGraphNode:
    function_name: str
    location: Location
    language: str
    calls: frozenset[str]              # names of functions called within this function
    is_exported: bool                  # Python: top-level; JS/TS: exported; Go: capitalized
```

**Lifecycle**: Produced by `discovery.discover_call_graph()`. Consumed by the Mermaid DFD generator and by the code-context enricher (to answer "what function encloses this finding"). Not emitted to the user directly; it's an internal structural aid.

## 2. Candidate finding shape (new)

### `FindingSource`

Enum identifying how a finding was discovered.

```python
class FindingSource(str, Enum):
    TREE_SITTER_STRUCTURAL = "tree_sitter_structural"
    OPENGREP_PATTERN = "opengrep_pattern"
    OPENGREP_TAINT = "opengrep_taint"
```

### `DataFlowTrace`

Optional intra-procedural data-flow trace, populated only when the finding came from an Opengrep taint rule.

```python
@dataclass(frozen=True)
class DataFlowStep:
    location: Location
    content: str                       # e.g., "cmd = request.query_params['q']"

@dataclass(frozen=True)
class DataFlowTrace:
    source: DataFlowStep
    intermediate: tuple[DataFlowStep, ...]
    sink: DataFlowStep
```

**Invariants** (enforced in `__post_init__`): `source.location`, `sink.location`, and each `intermediate` step MUST be in the same file. This matches Opengrep 1.6.0's intra-procedural taint constraint. Future releases with `--taint-intrafile` may relax this constraint (see research.md §6).

### `StrideCategory`

Enum used across STRIDE mapping and generator output.

```python
class StrideCategory(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"
```

### `CandidateFinding`

The fundamental unit that discovery produces and the generator consumes. Pre-verification by the calling agent.

```python
@dataclass(frozen=True)
class CandidateFinding:
    category: StrideCategory
    title: str                         # short, human-readable ("Potential command injection via subprocess")
    source: FindingSource
    primary_location: Location         # where the finding is "anchored" in source
    related_assets: tuple[str, ...]    # IDs of EntryPoint/DataStore entries it involves
    code_snippet: CodeSnippet
    data_flow: DataFlowTrace | None    # set when source == OPENGREP_TAINT
    enclosing_function: str | None     # from the call graph
    severity: int                      # 1–10; from the ranking heuristic (research.md §12)
    confidence: float                  # 0.0–1.0; from the ranking heuristic
    rationale: str                     # why the ranking rules awarded this severity × confidence
    query_id: str                      # tree-sitter query id or opengrep rule id
```

**Invariants** (all enforced in `__post_init__`):
- `severity` is in `1..10` inclusive.
- `confidence` is in `0.0..1.0` inclusive.
- `severity * confidence` is the ranking key used by `ranking.py`.
- `data_flow is None` iff `source != FindingSource.OPENGREP_TAINT`.
- `code_snippet.marker_line == primary_location.line` — the embedded snippet's `>>>` marker must point at the finding's anchor line, so reviewers see the correct line highlighted when they open the draft.

**Lifecycle**: Produced by `discovery.discover_all()`. Ranked and filtered by `ranking.py`. Consumed by `stride.py` (already categorized on production; stride module mostly groups and generates scenarios). Consumed by `generators.py` to render the draft.

## 3. File-scan accounting (new)

### `FileScanStats`

Surfaced in `HandlerResult.evidence` (FR-027) and in the draft's Limitations section (FR-026).

```python
@dataclass(frozen=True)
class FileScanStats:
    total_files_seen: int              # files walked after vendor-dir pruning
    excluded_dir_count: int            # directories pruned during the walk
    unsupported_file_count: int        # walked files with no tree-sitter grammar
    in_scope_files: int                # files actually parsed
    by_language: dict[str, int]        # {"python": 123, "typescript": 45, ...}
    shallow_mode: bool                 # True when in_scope_files > shallow_threshold
    shallow_threshold: int             # the configured threshold (default 500)
```

**Invariants**:
- `total_files_seen == unsupported_file_count + in_scope_files`. (Vendor directories are pruned before descent, so their files never enter `total_files_seen`; the count of pruned directory entries is tracked separately in `excluded_dir_count`.)
- `shallow_mode == (in_scope_files > shallow_threshold)`.

**Naming note**: An earlier draft used `excluded_file_count` for what is now
`unsupported_file_count`. The rename was made during post-Phase 2 review
because the old name suggested "files excluded by vendor rules" when in fact
vendor files are never counted at all — the number was always "files with
unsupported extensions that we walked past".

### `TrimmedOverflow`

Per-STRIDE-category count of candidates that were ranked out of the draft by the finding cap.

```python
@dataclass(frozen=True)
class TrimmedOverflow:
    by_category: dict[StrideCategory, int]
    total: int
```

**Invariants**: `total == sum(by_category.values())`.

**Lifecycle**: Produced by `ranking.apply_cap()`. Rendered in the draft's Limitations section (FR-029) and surfaced in `HandlerResult.evidence` (FR-030).

## 4. Handler I/O contracts (unchanged from today)

### `HandlerContext` (from `darnit.sieve.handler_registry`, already public)

Used as-is. Fields we rely on: `local_path`, `project_context`, `logger`.

### `HandlerResult` (from `darnit.sieve.handler_registry`, already public)

Used as-is. The rewritten handler returns it with the following evidence shape (new keys additive to what exists today):

```python
HandlerResult(
    status=HandlerResultStatus.PASS,
    message=f"Generated threat model: {path}",
    confidence=1.0,
    evidence={
        # existing keys (preserved for backward compatibility)
        "path": path,
        "action": "created" | "skipped" | "created_from_template",
        "llm_verification_required": True,  # always True for "created"
        "note": "<human-readable review guidance>",
        # new keys
        "file_scan_stats": FileScanStats(...).__dict__,
        "trimmed_overflow": TrimmedOverflow(...).__dict__,
        "opengrep_available": bool,
        "opengrep_degraded_reason": str | None,
    },
)
```

**Backward compatibility note**: `action` values are preserved (`created`, `skipped`, `created_from_template`). The spec's `force_overwrite` terminology maps to the existing `overwrite` config key (research.md §14) — no breaking TOML changes.

## 5. Config shape

### `ThreatModelHandlerConfig`

Logical representation of the keys the handler reads from its TOML config section. Not a persisted type — just documentation of what the handler looks for in the `config` dict argument.

```python
# TOML:
# [[controls."OSPS-SA-03.02".remediation.handlers]]
# handler = "generate_threat_model"
# path = "THREAT_MODEL.md"
# overwrite = false                    # existing key — honor user's setting
# max_findings = 50                    # NEW, default 50
# snippet_context_lines = 10           # NEW, default 10 (5 in shallow mode)
# shallow_threshold = 500              # NEW, default 500
# exclude_dirs = ["custom/vendor"]     # NEW, appended to baseline exclusion list
```

**Defaults**:
- `path`: required, no default.
- `overwrite`: `False`.
- `max_findings`: `50`.
- `snippet_context_lines`: `10` (automatically reduced to 5 in shallow mode).
- `shallow_threshold`: `500`.
- `exclude_dirs`: empty (user additions merged with baseline list; baselines cannot be disabled per FR-024).

## 6. Entity relationships

```
repository (input)
    │
    ▼
FileScanStats (one per run) ──────┐
    │                              │
    │                              ▼
discovery                      HandlerResult.evidence
    │
    ├── list[EntryPoint] ──┐
    ├── list[DataStore] ──┼──► stride mapping ──► list[CandidateFinding]
    ├── list[CallGraphNode]┘                         │
    │                                                ▼
    │                                            ranking
    │                                                │
    │                                                ▼
    │                                          TrimmedOverflow + capped list[CandidateFinding]
    │                                                │
    │                                                ▼
    │                                          generators (Markdown/SARIF/JSON)
    │                                                │
    │                                                ▼
    └─────────────────────────────────► DraftThreatModel (file on disk)
```

## 7. Deleted types (from today's pipeline)

The following types in the current `threat_model/models.py` are either replaced or deleted:
- `Threat` → replaced by `CandidateFinding` (same role, different field set)
- Any internal "pattern-match result" container in `patterns.py` → deleted with the file

The current `Asset` / `Framework` dataclasses are subsumed by `EntryPoint` / `DataStore` / a detected-framework string; no standalone `Asset` type in the new pipeline.

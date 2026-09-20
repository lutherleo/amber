# Implementation Plan: mcp handler for calling external MCP servers as observation sources

**Branch**: `031-mcp-server-handler` | **Date**: 2026-08-17 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/031-mcp-server-handler/spec.md` (with 3 clarifications recorded 2026-08-16: curated env safe-set for child processes; 60-second default per-call timeout; `dispatching_mcp` INFO progress line symmetric with feature 026's `dispatching_llm`).

## Summary

Add a new built-in sieve handler named `mcp` that lets TOML controls invoke tools on external MCP (Model Context Protocol) servers as observation sources, symmetric with the existing `exec` and `api_call` handlers. Servers are declared in the framework configuration under `[mcp_servers.<name>]` blocks with a required `command` field (allowlist entry) and optional `env`, `trusted_publisher`, `optional`, `install_hint`. When a control's pass references `server = "<name>"`, the handler dispatches the tool call over stdio, exposes the response as `result.*` to the CEL `expr`, and records the raw response plus trust label in evidence. Server sessions are spawned lazily on first use, pooled across the audit run, and torn down at audit end. Trust is allowlist-required (no allowlist entry → ERROR without spawning) with optional `trusted_publisher` Sigstore verification (verification failure → ERROR, never PASS). Child processes inherit only a curated env safe-set (PATH, HOME, LANG, LC_*, SSL_CERT_FILE, XDG_*) plus the operator's TOML `env` block; other parent-shell vars are dropped. The feature adds no new runtime dependency: `mcp>=1.23,<2` is already declared for darnit-core, and this feature uses its client-side APIs.

Reference server (`uwu-tools/scorecard-mcp`) is deliberately out of scope for v0; the machinery ships with a mock MCP server driving the integration test.

## Technical Context

**Language/Version**: Python 3.11/3.12 (workspace targets - same as the rest of darnit).

**Primary Dependencies**: `mcp>=1.23,<2` (already a runtime dep, declared for darnit-core; this feature uses its client-side `mcp.client.stdio.stdio_client` + `mcp.ClientSession` APIs). `sigstore` (already declared under `darnit-core[attestation]`) for the optional `trusted_publisher` verification path. No new pip dependencies.

**Storage**: Filesystem only. `.baseline.toml` and framework TOMLs are the sole persistence surface for `[mcp_servers.<name>]` declarations. Pool state and tool-invocation records are audit-run scoped and never persisted across audits.

**Testing**: pytest, extending existing `tests/darnit/sieve/` and `tests/darnit/config/` layers. New fixture: an in-repo mock MCP server (a small Python module using `mcp.server` primitives) used exclusively by the feature's integration test to verify spawn-lazy semantics, tool invocation, timeout enforcement, and teardown. The mock server counts its own lifecycle events so SC-002 (spawns == 1, terminations == 1 across 20 controls) is mechanically verifiable.

**Target Platform**: Same as darnit workspace - any platform Python 3.11+ runs on. Constraint: the MCP client-side stdio transport uses process pipes, which behave identically across Linux, macOS, and Windows-with-WSL. No platform-specific code paths introduced.

**Project Type**: Library/framework internal change; scoped to `packages/darnit/` core. No new packages, no new plugins.

**Performance Goals**: Not a hot path; MCP calls are network-bound by definition and dominate their own timing. Spec's SC-002 (single spawn across N controls) is the primary performance property. Non-goal: minimize handshake latency; that belongs to the MCP SDK.

**Constraints**:
- Zero product-source additions outside `packages/darnit/`.
- No new required arguments on any public callable that existing internal callers pass without modification (matches feature 030 FR-008 in spirit).
- Default per-call timeout MUST be 60 seconds (spec FR-002, clarified 2026-08-16). Handler-level default; per-pass override via `timeout = <seconds>`.
- Child process environment MUST be constructed as the union of a curated safe-set inherited from darnit's own process AND the TOML `env` block; no other parent-shell env leaks through (spec FR-005, clarified 2026-08-16).
- `dispatching_mcp` INFO log line MUST fire on `darnit.harness` at call dispatch (spec FR-019, clarified 2026-08-16) using the `[N/M] <control_id> dispatching_mcp <server>.<tool>` shape.

**Scale/Scope**: One new handler module (`darnit_mcp_handler` inside `builtin_handlers.py`) + one new pool module in `packages/darnit/src/darnit/sieve/mcp_pool.py` + a schema extension to `FrameworkConfig` + one integration test with a mock server. Estimated diff: ~600 lines of production code, ~500 lines of test code (mostly the mock server + fixtures).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

The darnit constitution (5 core principles, plus architecture constraints and workflow rules) evaluated against this feature:

| Principle | Applies | Assessment |
|-----------|---------|------------|
| I. Plugin Separation | Yes | PASS. The `mcp` handler + pool live in `packages/darnit/src/darnit/sieve/` (core framework). This feature does not import any implementation package. Implementation packages may still register their own domain-specific handlers via `register_handlers()` unchanged. |
| II. Conservative-by-Default | Yes | PASS. Absence of the allowlisted binary produces INCONCLUSIVE by default (never PASS) with a specific install-hint message; `[mcp_servers.<name>].optional = false` promotes absence to FAIL. Sigstore verification failure produces ERROR (never PASS). A tool invocation that errors resolves the affected control ERROR, never leaks into another control's evidence. Every one of these paths is a "silence is safe" posture. |
| III. TOML-First Architecture | Yes | PASS. Control-author-facing surface is entirely in TOML (`handler = "mcp"` on a pass, `[mcp_servers.<name>]` allowlist blocks). No Python-code-only escape hatch. Existing control-loader validation extends to the new `mcp_servers` field via a schema addition to `FrameworkConfig`. |
| IV. Never Guess User Values | Yes | PASS. MCP tool results are observation-based dispositive (external tool observed ground truth) - the handler registers with `default_authority = "dispositive"`. It does NOT synthesize `asserted` authority: an operator-trusted PATH binary and a Sigstore-verified binary both produce `dispositive` results because the tool is observing ground truth; the trust label surfaces separately on the evidence record. |
| V. Sieve Pipeline Integrity | Yes | PASS. The handler returns a single `HandlerResult` per invocation; the orchestrator's phase semantics and disposition logic are unchanged. `dispatching_mcp` progress log is a side effect, not a phase modifier. INCONCLUSIVE from missing binary correctly falls through to the next pass (or resolves the control per the sieve orchestrator's `_dispatch_handler_invocations`, the existing flat-invocation dispatch loop). |

Architecture constraints (three-layer architecture, package structure): PASS. The change is confined to `packages/darnit/` core. No new layers or packages.

Development workflow (lint, tests, spec sync, no-emoji rules): PASS. Standard workflow; no new gates required.

**Gate result: PASS. Proceed to Phase 0.**

## Project Structure

### Documentation (this feature)

```text
specs/031-mcp-server-handler/
├── plan.md              # This file
├── research.md          # Phase 0 output — MCP client-API choice, pool lifecycle, mock-server design
├── data-model.md        # Phase 1 output — new schema types (McpServerConfig, PooledSession, invocation record)
├── quickstart.md        # Phase 1 output — control-author + operator worked example
├── contracts/
│   └── mcp-handler-contract.md   # Phase 1 output — TOML surface + evidence shape + log shape
├── checklists/
│   └── requirements.md  # From /speckit-specify
└── tasks.md             # /speckit-tasks output (not created here)
```

### Source Code (repository root)

```text
packages/darnit/src/darnit/sieve/
├── builtin_handlers.py       # Add `mcp_handler` alongside exec/api_call. Registers via register_builtin_handlers().
├── mcp_pool.py               # NEW. Per-audit connection pool: spawn-lazy, session cache, teardown-on-exit.
├── mcp_trust.py              # NEW. Sigstore verification for `trusted_publisher`; small module isolated so the sandboxing follow-up (issue #375) can extend it without touching the pool.
├── orchestrator.py           # Small edit: initialize the pool on the orchestrator instance; clear it in reset_caches(); teardown in verify_batch() finally-block.
└── (no new modules beyond mcp_pool + mcp_trust)

packages/darnit/src/darnit/config/
└── framework_schema.py       # Add McpServerConfig BaseModel + `mcp_servers: dict[str, McpServerConfig]` on FrameworkConfig.

packages/darnit/src/darnit/harness/
└── (no changes — dispatching_mcp log line is emitted by the handler on darnit.harness logger; harness-side wiring is already generic)

tests/darnit/sieve/
├── test_mcp_handler.py           # NEW. Unit tests: TOML parsing, arg substitution, expr evaluation over result, timeout, absent-binary paths.
├── test_mcp_pool.py              # NEW. Unit tests: spawn-lazy, session reuse, teardown on all exit paths, respawn-on-invalidation, single-retry.
├── test_mcp_trust.py             # NEW. Unit tests: Sigstore-verify path, verification failure, trusted_publisher absent (operator-trusted PATH label).
└── fixtures/
    └── mock_mcp_server/          # NEW. Small Python mock MCP server that counts spawn/teardown/tool-call events. Uses the `mcp` package's own server primitives.

tests/darnit/config/
└── test_framework_schema.py      # Add coverage for [mcp_servers.<name>] block: required command, optional env/trusted_publisher/optional/install_hint, precedence between .baseline.toml and framework TOML.
```

**Structure Decision**: Split concerns into three small modules under `sieve/`: the handler itself (in the existing `builtin_handlers.py` alongside its peers), the per-audit pool (`mcp_pool.py`), and the trust verification (`mcp_trust.py`). The trust module is deliberately isolated so issue #375's sandbox exploration can extend the pre-spawn hooks without needing to change the pool. Testing extends existing `tests/darnit/sieve/` and `tests/darnit/config/`; a new `fixtures/mock_mcp_server/` directory holds the mock server used by the integration test.

## Complexity Tracking

No constitution violations to justify. The feature is a scoped handler addition with zero new architecture.

## Phase 0: Research

Research questions surfaced by Technical Context and the spec's Assumptions/Edge Cases:

1. **What is the correct MCP client-side API surface to use?** — The `mcp` package (already a darnit-core runtime dep) exposes both server and client primitives. The client-side entry is `mcp.client.stdio.stdio_client` returning a context-manager pair of read/write streams, plus `mcp.ClientSession` wrapping them into a call surface. Research confirms the specific API version (mcp>=1.23) exposes `session.call_tool(name, arguments)` returning a `CallToolResult`, and that this is stable across the 1.x major. Decision: use `stdio_client` + `ClientSession.call_tool`; keep the client-side use behind a thin adapter in `mcp_pool.py` so a future HTTP-transport follow-up can add a parallel adapter without changing the handler.

2. **Pool lifecycle: which lifecycle hook clears the pool?** — The sieve orchestrator has an existing `reset_caches()` method that clears `_shared_cache` and `_dependency_results` at the start of each `verify_batch`. `verify_batch` is the natural boundary for a single audit run. Decision: pool state lives as `_mcp_pool: dict[str, PooledSession]` on the orchestrator, cleared in `reset_caches()`. Teardown of active sessions happens in a `try/finally` around `verify_batch`'s loop so any exit path (success, failure, exception, interrupt) tears down before returning. Alternative considered: audit-level context-manager wrapping the whole run. Rejected because it requires threading a new lifetime object through every caller of `verify_batch` (agent graph, harness driver, MCP tool wrapper), whereas the orchestrator-owned pool is the shortest correct path.

3. **What are the exact env-safe-set semantics?** — Spec FR-005 names PATH, HOME, LANG, LC_*, SSL_CERT_FILE, XDG_*. Research resolves the `LC_*` and `XDG_*` glob expansion at spawn time: read `os.environ` once, filter by predicate `k.startswith("LC_") or k.startswith("XDG_") or k in {"PATH", "HOME", "LANG", "SSL_CERT_FILE"}`, then apply the TOML `env` block's `$VAR` substitutions from the operator's shell (looking up the substituted vars in `os.environ` at substitution time; empty string if unset, matching how `exec` handler substitutes `$OWNER`). Decision documented explicitly so the sandbox follow-up (issue #375) can extend the predicate without ambiguity.

4. **Sigstore verification against a `trusted_publisher` value: what shape?** — Darnit already has sigstore machinery for plugin-wheel verification (`.baseline.toml [plugins].trusted_publishers = [...]`). The mcp verification path can reuse the same underlying `sigstore.verify.Verifier.production()` + `GitHubWorkflowRepository` policy composition. Research: for a locally-installed binary, the darnit-known reference is the binary's bundled `.sigstore` sidecar (produced by GoReleaser's Sigstore step or similar). Decision: `mcp_trust.verify(binary_path, trusted_publisher)` looks for `<binary_path>.sigstore` or `<binary_path>.sigstore.json` sidecar next to the binary; if absent, verification fails (ERROR, per FR-007). Alternative considered: fetching an attestation from the transparency log using the binary's SHA-256 as the reference. Rejected for v0 because it adds a network round-trip that Constitution II says can't be silently required at audit time.

5. **How does the mock MCP server work in the integration test?** — The `mcp` package exposes server primitives that let us write a mock in <100 lines. The mock counts spawn events (by writing to a shared file the test can inspect), exposes a small tool surface (`echo`, `get_score`, `raise_error`, `sleep_forever`), and is launched via `stdio_client(StdioServerParameters(command=["python", "-m", "tests.darnit.sieve.fixtures.mock_mcp_server"]))`. Decision: mock server module is at `tests/darnit/sieve/fixtures/mock_mcp_server/__init__.py` with a `__main__.py` for `-m` invocation. The counter file path is passed via TOML `env` block so different test cases can isolate their own counts.

**Output**: `research.md` documenting each decision with rationale and rejected alternatives.

## Phase 1: Design & Contracts

**Prerequisites**: `research.md` complete.

### Data Model (`data-model.md`)

New schema types and their relationships:

- **`McpServerConfig`** (Pydantic model in `framework_schema.py`): fields `command: list[str]` (required); `env: dict[str, str]` (default empty); `trusted_publisher: str | None` (default None); `optional: bool` (default True); `install_hint: str` (default empty). Validation rules: `command` must be non-empty; `trusted_publisher`, when set, must look like a URL or GitHub identity string.
- **`FrameworkConfig.mcp_servers: dict[str, McpServerConfig]`** (default empty). Merged from `.baseline.toml` over framework TOML via the existing config-merge path (spec FR-016).
- **`PooledSession`** (runtime-only dataclass in `mcp_pool.py`): fields `server_name: str`; `config: McpServerConfig`; `session: mcp.ClientSession`; `trust_label: Literal["sigstore-verified", "operator-trusted-path"]`; `spawn_ts: datetime`; `broken: bool` (default False). Lifecycle: `spawn()` → `use()` → `teardown()` or `invalidate()`. Distinguishable by `(audit_id, server_name)` — new audit gets fresh sessions.
- **`McpInvocationRecord`** (dict shape in evidence, mirrored in the reader-contract docs): `server`, `tool`, `args_after_substitution`, `raw_response` (or `error`), `trust_label`, `elapsed_ms`.
- **`HandlerContext.mcp_pool: McpPool | None = None`** (added field on the existing `HandlerContext` dataclass in `sieve/handler_registry.py`). The orchestrator assigns this to `self._mcp_pool` when constructing the context for an invocation whose `invocation.handler == "mcp"`; None for every other handler kind. The mcp handler reads `context.mcp_pool` to obtain the pool; a `None` value indicates a plumbing bug and resolves the pass ERROR (not a user-facing failure).

State transitions for `PooledSession`:

```
      spawn()      first .use()      terminated
[ ---- ] ------> [ FRESH ] ------> [ USED ] ------> [ TEARDOWN ]
                    |                  |
                    v                  v
              invalidate()       invalidate()
                    |                  |
                    v                  v
              [ BROKEN ]         [ BROKEN ]
```

`FRESH → BROKEN` (handshake failure) triggers exactly one respawn attempt on next reference; `USED → BROKEN` (crash mid-audit) also triggers one respawn. Two consecutive broken states → all subsequent references for that server produce INCONCLUSIVE (or FAIL if `optional = false`) without further respawn attempts, per FR-012.

### Contracts (`contracts/mcp-handler-contract.md`)

The public control-author API. Contents:

- **TOML pass surface**: exact field list for `handler = "mcp"` (`server`, `tool`, `args`, `expr`, `timeout`, `authority`). Table of accepted CEL context vars (`result.*`, `$OWNER`/`$REPO`/`$BRANCH`/`$PATH`).
- **TOML allowlist surface**: exact field list for `[mcp_servers.<name>]` (`command`, `env`, `trusted_publisher`, `optional`, `install_hint`). Merge precedence between `.baseline.toml` and framework TOML.
- **Evidence shape**: the `McpInvocationRecord` fields a downstream evidence-reader will see per invocation.
- **Progress-log shape**: the exact format string `[{n}/{m}] {control_id} dispatching_mcp {server}.{tool}` fired on the `darnit.harness` logger at INFO level.
- **Failure modes**: table with rows for each named failure (missing allowlist, missing binary + optional=true, missing binary + optional=false, Sigstore verify fail, handshake fail, tool error, timeout, crash mid-audit) and the corresponding control status.
- **Non-goals for v0**: repeats the spec's Assumptions §non-goals list at the contract level so a control author does not accidentally rely on a deferred feature (HTTP transport, cross-audit caching, install-helper subcommand, parallel calls).

### Quickstart (`quickstart.md`)

Two worked examples:

1. **Control author perspective**: write a level-1 OSPS-style pass that consults the mock MCP server. Includes the exact TOML for `[mcp_servers.mock]` and the pass. Shows the expected evidence output and the progress-log line.
2. **Operator perspective**: register a real MCP server (using a real-world example like `uwu-tools/scorecard-mcp` when its interface is known, or a placeholder for now). Show adding a `trusted_publisher` line and what the verification failure message looks like.

Also includes the "failure-mode diagnostics" section: how to interpret each failure-status message from the contract.

### Agent Context Update

Update the reference between `<!-- SPECKIT START -->` and `<!-- SPECKIT END -->` markers in `CLAUDE.md` to point at `specs/031-mcp-server-handler/plan.md`.

## Post-Design Constitution Recheck

The design phase artifacts do not introduce any new principle-touching decisions:

- **I. Plugin Separation**: unchanged; all new modules are in `packages/darnit/`.
- **II. Conservative-by-Default**: reinforced by the state-transition model — `BROKEN` sessions produce INCONCLUSIVE/FAIL rather than silently retrying, and no code path produces PASS from a Sigstore verification failure.
- **III. TOML-First**: reinforced by the exact TOML surface documented in the reader contract; no Python-code escape hatch introduced.
- **IV. Never Guess User Values**: reinforced by the trust-label being separate from the authority — an "operator-trusted-path" invocation still produces `dispositive` results because the underlying observation is ground-truth (a tool observed the world); the label surfaces the trust level for auditors.
- **V. Sieve Pipeline Integrity**: reinforced by the handler returning a single `HandlerResult` and the pool being invisible to the disposition logic.

**Post-design gate: PASS.**

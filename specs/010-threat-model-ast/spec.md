# Feature Specification: Accurate Threat Model Discovery

**Feature Branch**: `010-threat-model-ast`
**Created**: 2026-04-10
**Status**: Draft
**Input**: User description: "Rewrite threat model generator using AST parsing and taint analysis to replace regex-based discovery, producing higher-quality drafts for the calling agent to verify"

## Context (architectural framing)

Darnit is a plugin-based compliance auditing framework that runs as an MCP server. The calling agent (an LLM like Claude, invoked via a skill such as `/darnit-comply` or `/darnit-remediate`) drives the compliance workflow by calling MCP tools. Darnit itself **does not make LLM API calls** — when a check needs judgment, the framework returns a `PENDING_LLM` result with a consultation request, and the calling agent resolves it in-conversation.

The threat model feature lives as a **remediation handler for control OSPS-SA-03.02** (`generate_threat_model_handler` in `packages/darnit-baseline/src/darnit_baseline/threat_model/remediation.py`). The handler produces a draft `THREAT_MODEL.md` file with pattern-matched findings and embedded code snippets, then marks `llm_verification_required: True` in its evidence. The `darnit-remediate` skill (at `~/.claude/skills/darnit-remediate/`) instructs the calling agent to review the generated file, strip false positives, refine narratives, and commit the final result.

**This spec covers replacing the discovery layer that feeds the draft.** It does not change the handler contract, the MCP tool surface, the skill orchestration, or the way the calling agent verifies findings. What changes is the *quality of the raw material* the agent receives to review.

## Clarifications

### Session 2026-04-10

- Q: How should the handler behave when a threat model file already exists at the configured path? → A: Skip by default (preserve the existing file) with a clear evidence note, but honor the existing `overwrite` TOML config flag — when set to `true`, regenerate the file.
- Q: How should the handler behave on repositories larger than the calibrated 100–500 file envelope? → A: No hard cap. Exclude vendor / dependency / build directories (node_modules, .venv, vendor/, dist/, build/, __pycache__, .tox, .git, etc.) from discovery. When more than 500 in-scope files remain after exclusions, the handler enters a shallower analysis mode (narrower query set, reduced code context window, skipped attack-chain computation) and clearly surfaces in the draft's Limitations section that this was a simpler threat model due to repository size.
- Q: Should the draft have an upper bound on the number of findings it emits? → A: Yes — rank candidates by severity × confidence and emit a configurable top-N (default 50) in the draft. Overflow is summarized as per-category counts in the Limitations section so the calling agent knows how much was trimmed. Users can raise the cap via the handler's config.
- Q: Should findings have stable cross-run identities or a suppression/triage mechanism? → A: No. The handler is stateless and idempotent like every other darnit remediation handler. Each run re-discovers and re-emits from scratch; no finding fingerprints, no suppression file. Users who want to preserve their triage edits rely on the default skip-if-exists behavior (FR-007a). The triage-memory problem is deferred to a future iteration if real usage demands it.

### Session 2026-04-12 — Post-Implementation Retrospective

A full compliance pipeline run (`/darnit-comply`) against darnit's own repository exposed critical gaps in the discovery layer. The generated `THREAT_MODEL.md` had:

- **Empty asset inventory**: Zero entry points, zero data stores detected — despite darnit being an MCP server with 15+ tool endpoints.
- **28 identical subprocess findings**: All LOW-confidence, all "Potential command injection via subprocess.run", no differentiation between `["git", "rev-parse", "HEAD"]` (completely safe) and `subprocess.run(resolved_cmd, ...)` where `resolved_cmd` is built from TOML config with variable substitution (real attack surface).
- **5 of 6 STRIDE categories empty**: Because entry points weren't found, Spoofing, Repudiation, Information Disclosure, DoS, and Elevation of Privilege all cascaded to "No threats identified."
- **No agent verification step**: The `/darnit-comply` skill calls `remediate_audit_findings` which writes and commits the file directly. The agent-verification step described in User Story 1 only triggers via the separate `/darnit-remediate` skill, which was never invoked.

**Root causes identified:**

1. **Decorator-only entry point detection**: The MCP tool query matches `@server.tool()` (FastMCP decorator convention), but darnit registers tools via `server.add_tool(handler, name=name, ...)` in `factory.py` — an imperative call pattern. The query finds zero matches in production code.
2. **Fixture-reality gap**: Test fixtures use `@server.tool()` decorators (matching the query), so all tests pass. But no fixture mimics darnit's actual imperative registration pattern. Success criteria SC-001 and SC-002 were satisfied on paper without validating against the real codebase.
3. **No empty-inventory diagnostic**: The pipeline silently produces a valid but empty asset inventory. There is no warning when a repository with 100+ Python files yields zero entry points — a strong signal that queries are missing coverage.
4. **Subprocess finding noise**: Without taint analysis distinguishing user-controlled input from internal parameters, all `subprocess.run()` calls receive identical LOW scores. Calls with fully static arguments (e.g., `["git", "init"]`) and calls with config-driven dynamic arguments (e.g., `resolved_cmd` built from TOML substitution) are indistinguishable in the output.
5. **TOML-driven command construction not covered**: The spec's Problem section explicitly called out "TOML-driven command construction" as a missed attack surface, but no query or heuristic was added to detect it.

The following requirements, success criteria, and clarifications address these gaps. Changes are additive — no existing FR or SC is removed, only strengthened or supplemented.

### Session 2026-04-12 — LLM Consultation Loop for Remediation Handlers

A manual walkthrough of the `/darnit-remediate` flow against darnit's own repository confirmed that the structural pipeline produces a high-quality draft, but the generated `THREAT_MODEL.md` still contained one false positive (opengrep_runner.py:131 — fully hardcoded args flagged as command injection) and three findings that were technically true but already mitigated by allowlist checks without any annotation. The calling agent (Claude, running the skill) manually:

1. Read each HIGH/MEDIUM finding and cross-referenced it against the source code
2. Removed the false positive
3. Added "**Mitigation in place:**" notes to findings with existing defenses
4. Flagged a genuinely unmitigated finding (server/registry.py:151 — dynamic import without allowlist check)
5. Updated the executive summary counts

This manual step is exactly what the `llm_consultation` payload already describes — but the skill didn't act on it. The payload was surfaced in the MCP output, the instructions were clear, but no skill told the agent to follow them.

**Resolution**: The `llm_consultation` evidence field is a **generic protocol**, not threat-model-specific. Any remediation handler can return `evidence["llm_consultation"]` with structured review instructions. The skill layer must treat this as a mandatory post-remediation step: when the MCP tool returns consultation payloads, the agent follows them before offering to commit or create a PR. This applies to all skills that call `remediate_audit_findings` — not just `/darnit-remediate` but also `/darnit-comply`.

**Spec impact**: This changes the "Out of Scope" claim that skill changes aren't needed. The skill layer needs a generic rule: "when any remediation result includes `llm_consultation`, follow its instructions." The handler contract and MCP tool surface remain unchanged — the consultation payload is already there, it just needs a consumer.

## Problem

The current discovery pipeline in `packages/darnit-baseline/src/darnit_baseline/threat_model/discovery.py` uses regex patterns to identify entry points, data stores, injection sinks, authentication mechanisms, and sensitive data. Regex cannot distinguish code structure from string content, and 5–6 iteration cycles of patching specific false positives have failed to produce trustworthy output. Concrete failures observed when the current pipeline ran against darnit itself:

- The regex `pg\.` matched `gpg.ssh.allowedSignersFile` inside a Python docstring, producing a phantom PostgreSQL data-store finding in a codebase that has no database at all.
- `email=data.get("email", "")` in a maintainer-metadata parser was flagged as PII-handling code requiring GDPR/CCPA controls.
- None of the actual attack surface (MCP tool handlers, subprocess execution via the `exec` sieve handler, TOML-driven command construction) was detected, because the pattern set only knows web frameworks.

The draft delivered to the calling agent under the current pipeline contains enough false positives that even with verification, agents waste tokens defending against nonexistent threats and may produce a final file that still misleads a reviewer. The remediation handler passes the OSPS-SA-03.02 compliance check (because a file is generated), but the checkbox is the only value the user receives.

## Goal

Replace the regex-based discovery layer with structural parsing (tree-sitter) and optional intra-procedural taint analysis (Opengrep CLI binary, when installed) so that the draft `THREAT_MODEL.md` produced by `generate_threat_model_handler` contains substantially fewer false positives and substantially more real findings. Preserve the existing integration contract: the handler continues to return a file-based result, continues to embed verification prompts in the draft, continues to mark `llm_verification_required: True`, and the calling agent continues to finalize the document via the `darnit-remediate` skill.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Calling agent receives a high-signal draft to verify (Priority: P1)

A project maintainer runs the `/darnit-comply` skill on their repository. The skill calls `audit_openssf_baseline`, discovers that OSPS-SA-03.02 is failing, collects any missing context via `get_pending_context`, and then calls `remediate_audit_findings`. The remediation handler for OSPS-SA-03.02 runs the new tree-sitter–based discovery and produces a draft `THREAT_MODEL.md`. The draft contains findings that correspond to real code patterns in the repository. The calling agent (Claude), following the `darnit-remediate` skill's review instructions, reads the draft, confirms each finding against the embedded code snippets, makes minor narrative refinements, and commits the file. The agent does not have to delete phantom findings or argue against false positives — the draft is trustworthy enough that verification is quick.

**Why this priority**: This is the core value. Today the agent spends most of its verification effort stripping false positives and apologizing for misleading content. A higher-quality draft means the agent's time is spent refining real findings, and the committed file is actually useful to a human security reviewer.

**Independent Test**: Run the remediation flow against a fixture repository containing a known mix of real risks (a real subprocess call receiving external input, a real database connection, a real MCP tool handler) and red herrings (docstrings mentioning "postgresql", variable names containing "email" in metadata parsing, commented-out `eval()` calls). Verify the draft contains the real findings and omits the red herrings *before* the calling agent runs its verification step.

**Acceptance Scenarios**:

1. **Given** a repository with a docstring that mentions "postgresql" but no database client code, **When** the remediation handler generates a threat model draft, **Then** no database data-store finding references that file
2. **Given** a repository with config-metadata parsing code that assigns to a field named `email`, **When** the draft is generated, **Then** no PII finding is raised for that code
3. **Given** a repository with a real `subprocess.run(...)` call whose command argument is constructed from an external input, **When** the draft is generated, **Then** a command-injection candidate finding exists at that file and line
4. **Given** a draft produced by the new pipeline, **When** the calling agent follows the `darnit-remediate` skill to verify it, **Then** the agent's review output reports that most findings were confirmed and few were stripped, and the committed file contains LLM-refined narratives anchored to the real findings
5. *(added 2026-04-12)* **Given** the handler runs against darnit's own repository, **When** the draft is generated, **Then** the Asset Inventory lists MCP tool entry points from `packages/darnit/src/darnit/server/factory.py` (the `server.add_tool()` registration site), the STRIDE Threats section contains findings in at least 3 categories, and subprocess findings are differentiated by risk level (not all identical LOW scores)
6. *(added 2026-04-12)* **Given** a repository with an MCP server that registers tools via `server.add_tool(handler, name=name)` (imperative, no decorators), **When** the draft is generated, **Then** entry points are detected for each `add_tool` call, each with `kind=MCP_TOOL` and `framework="mcp"`

---

### User Story 2 — OSPS-SA-03.02 still passes, with a better artifact (Priority: P1)

A maintainer runs an audit and sees OSPS-SA-03.02 failing. They run remediation. The control passes on re-audit because a `THREAT_MODEL.md` file now exists at one of the expected paths. This is the existing compliance behavior. What changes is the quality of the committed file: it is now worth keeping as compliance evidence because its content corresponds to the repository's real shape.

**Why this priority**: The compliance contract is sacred. The control must continue to pass after remediation, and the file must remain at the filesystem location the existence-check looks for. Everything else about the feature is moot if this breaks.

**Independent Test**: Run `audit_openssf_baseline` → `remediate_audit_findings` → `audit_openssf_baseline` against a repository with no pre-existing threat model. Verify OSPS-SA-03.02 transitions from FAIL to PASS, and verify the committed file is in the location the control's `file_exists` pass expects.

**Acceptance Scenarios**:

1. **Given** a repository where OSPS-SA-03.02 is failing due to missing threat model, **When** remediation runs, **Then** a file is created at one of the paths checked by the control's existence pass (`THREAT_MODEL.md`, `docs/threat-model.md`, `docs/security/threat-model.md`)
2. **Given** a file created by the handler, **When** a subsequent audit runs, **Then** OSPS-SA-03.02 is reported as PASS without requiring manual edits

---

### User Story 3 — Graceful behavior when optional tooling is absent (Priority: P2)

A maintainer runs the threat model flow on a machine that does not have the optional Opengrep binary installed. The handler detects the absence, logs a warning (via the existing `darnit.core.logging` subsystem), and proceeds with the tree-sitter–only discovery. The draft is still produced and the control still passes. Findings that would have required data-flow (taint) analysis are omitted, but no incorrect findings are emitted in their place.

**Why this priority**: Opengrep is a documented prerequisite, not a hard dependency. Users who cannot or will not install it must still get a usable (though narrower) threat model, and the handler must degrade cleanly rather than crash or produce lower-quality output.

**Independent Test**: Run the handler in two environments — one with Opengrep installed, one without — against the same fixture repository. Verify both complete successfully. Verify the "without" variant is a strict subset of the "with" variant (no findings in the degraded run that are absent from the full run).

**Acceptance Scenarios**:

1. **Given** Opengrep is not installed, **When** the handler runs, **Then** a warning is logged identifying the missing tool, the draft is produced using tree-sitter alone, and the `llm_verification_required` flag is still set
2. **Given** Opengrep is installed, **When** the handler runs, **Then** findings that depend on taint analysis (e.g., "external input reaches subprocess via a chain of assignments") appear in the draft with data-flow trace context

---

### User Story 4 — Calling-agent verification contract is preserved (Priority: P1)

Every finding in the generated draft includes a file path, a line number, a source code snippet (±N lines), and a verification prompt block. The `darnit-remediate` skill's existing instructions to "review generated files" apply without modification. The calling agent can verify each finding against the actual code without any new tooling or protocol changes.

**Why this priority**: Preserving the existing handoff contract is what lets us scope this change to just the discovery layer. If the calling-agent verification contract changes, we have to update skills, documentation, and user mental models simultaneously.

**Independent Test**: Inspect a generated draft and confirm it has the same structural sections as the current output: executive summary, asset inventory, STRIDE threats with embedded code blocks, verification prompts, limitations. Confirm the `llm_verification_required` evidence flag is still set.

**Acceptance Scenarios**:

1. **Given** a draft produced by the new pipeline, **When** its structure is compared to a draft produced by the old pipeline, **Then** both have the same top-level sections and both embed code snippets alongside findings
2. **Given** the `darnit-remediate` skill's existing review instructions, **When** a calling agent follows them against a new-pipeline draft, **Then** the skill completes without needing new steps or new tools

---

### Edge Cases

- **Malformed source files**: The parser must recover and continue extracting findings from the valid portions. Tree-sitter's native error recovery handles this — the handler must not crash on partially-broken files.
- **Very large repositories**: Above the calibrated envelope (500 in-scope files after vendor/dependency exclusions), the handler enters a shallow-mode analysis with a narrower query set and simplified outputs, clearly surfaced in the draft's Limitations section. There is no hard cap; the tool remains usable on large monorepos, trading depth for coverage and transparency.
- **Vendor and dependency directories**: By default, the handler does not descend into `node_modules`, `.venv`, `venv`, `vendor/`, `dist/`, `build/`, `target/`, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.git`, or directories listed in the repository's `.gitignore`. A threat model should describe the project under analysis, not the code it depends on.
- **Overwhelming finding counts**: The draft caps at a configurable number of top-ranked findings (default 50), with trimmed overflow summarized per STRIDE category in the Limitations section. The calling agent sees both the rendered cap and the overflow counts in its evidence payload and can recommend raising the cap if the user wants to see more.
- **Languages outside the supported set**: Files in unsupported languages are skipped silently. They are not treated as evidence of absent threats, and the draft's "Limitations" section mentions which languages were scanned.
- **Opengrep rule errors**: Opengrep surfaces rule-schema errors in its `errors[]` array even on exit code 0. The runner must inspect that array and treat rule errors as degraded operation with a logged warning, not as silent success.
- **Empty repository**: A repository with no analyzable code produces a well-formed draft document that explicitly states no assets were discovered. The existence check still passes because a file is still written.
- **Concurrent runs**: The handler must tolerate being invoked multiple times against the same repository without interfering with itself (e.g., two remediation runs should not corrupt each other's draft output).
- **Pre-existing threat model**: If a maintainer has a hand-written file at the configured path, the handler preserves it by default and the control still passes on re-audit. Users who want to regenerate the draft must explicitly opt into overwrite by setting `overwrite = true` in the handler's TOML config.
- **Adversarial input**: The target repository may contain files designed to confuse parsers. Darnit must not execute any code from the target; parsing is read-only and uses the parser library's own safety guarantees.
- *(added 2026-04-12)* **Self-scan dogfooding**: The handler MUST produce a meaningful threat model when run against darnit itself. This is the primary integration test. A draft with an empty asset inventory for an MCP server codebase is a test failure, not an edge case. The handler runs against its own repo as part of CI validation (SC-001a, SC-001b, SC-009).
- *(added 2026-04-12)* **Comply-skill integration**: The `/darnit-comply` skill calls `remediate_audit_findings`, which invokes the threat model handler and commits the result directly. The agent-verification step (User Story 1, Story 4) only runs when the `/darnit-remediate` skill is invoked separately. This means the draft produced by the handler must be high-quality standalone — the "calling agent will clean it up" assumption does not hold for the comply workflow. The handler SHOULD NOT rely on post-generation agent verification to produce an acceptable artifact.

## Requirements *(mandatory)*

### Functional Requirements

**Discovery accuracy**

- **FR-001**: The threat model handler MUST identify entry points (HTTP route handlers, CLI commands, MCP tool decorators, middleware endpoints) based on the structural shape of declarations, not on substring matches in source text.
- **FR-001a** *(added 2026-04-12)*: Entry point detection MUST cover both decorator-style registration (`@server.tool()`, `@app.route()`) AND imperative registration (`server.add_tool(handler, ...)`, `app.add_url_rule(...)`, `router.HandleFunc(...)`) patterns. The decorator-only approach failed to detect any entry points in darnit itself because darnit uses `server.add_tool()` calls driven by a TOML-based `ToolRegistry`. Queries MUST be validated against at least one real-world codebase that uses each registration pattern, not only against fixture code that was written to match the queries.
- **FR-001b** *(added 2026-04-12)*: When the discovery pipeline finds zero entry points in a repository containing more than 50 in-scope source files, the handler MUST emit a WARNING-level log message and include a diagnostic note in the Asset Inventory section of the draft (e.g., "⚠️ No entry points detected in a repository with N source files. This likely indicates missing query coverage for the project's framework or registration pattern. Review the Limitations section."). An empty asset inventory in a non-trivial codebase is a strong signal of a detection gap, not evidence that the codebase has no attack surface.
- **FR-002**: The handler MUST identify data stores based on how connections or clients are actually constructed in code (constructor or factory calls), not on keyword presence in strings, comments, or docstrings.
- **FR-003**: The handler MUST distinguish code from comments, string literals, and docstrings, such that a mention of a keyword inside any of those contexts does not produce a finding.
- **FR-004**: The handler MUST detect injection-style risks (subprocess invocation, command construction, query construction) based on real call structure and, when data-flow analysis is available, real data flow.
- **FR-004a** *(added 2026-04-12)*: Subprocess/exec findings MUST be differentiated by the nature of their arguments. At minimum, the handler MUST distinguish between: (a) calls with fully-static literal argument lists (e.g., `["git", "init"]`) — which SHOULD be filtered out or reported as INFO-level at most, (b) calls where the command or arguments include variables that originate from function parameters or config (e.g., `local_path`, `endpoint`) — which represent potential injection vectors, and (c) calls where the entire command is built dynamically (e.g., `resolved_cmd` constructed from TOML substitution, `cmd` built from a config dict) — which represent the highest-risk pattern. When taint analysis is not available, the handler MUST use structural heuristics (argument shape: all-literal list vs. variable-containing list vs. bare variable) to rank findings rather than assigning them all the same LOW score.
- **FR-004b** *(added 2026-04-12)*: The handler MUST detect TOML-driven command construction patterns — specifically, code that reads command templates or arguments from configuration (TOML, YAML, or dict-based config) and passes them to `subprocess.run()` or similar execution sinks. This was explicitly identified in the Problem section as a missed attack surface in the prior pipeline and remained undetected in the v1 implementation. At minimum, the handler MUST flag cases where a subprocess call's argument is a variable that was populated from a config/dict lookup within the same function scope.
- **FR-005**: The handler MUST support structural analysis of Python, JavaScript, TypeScript, Go, and YAML files — the source and workflow-configuration languages present in darnit's typical target repositories. TOML files (`pyproject.toml`, `package.json`, `go.mod`) are read by the existing dependency-manifest parser for corroboration of data-store findings; they do not receive their own tree-sitter queries in v1.

**Integration with existing framework**

- **FR-006**: The handler MUST continue to satisfy the `SieveHandler` contract used by the remediation orchestrator — same function signature, same `HandlerResult` return shape, same evidence dict conventions.
- **FR-007**: The handler MUST continue to write a file at one of the paths checked by the OSPS-SA-03.02 existence pass, so that a subsequent audit reports the control as PASS.
- **FR-007a**: When any file already exists at the configured path (as detected by `os.path.exists`), the handler MUST skip writing by default, return a successful result with an evidence note explaining that an existing threat model was preserved, and leave the file untouched. The control still passes because the pre-existing file satisfies the existence check.
- **FR-007b**: The handler MUST honor the `overwrite` boolean in its TOML config — when set to `true`, the handler MUST replace the existing file with a freshly generated draft. The override MUST NOT be the default behavior. (This field is called `overwrite` to match the existing handler configuration; earlier drafts of this spec referred to it as `force_overwrite` for narrative clarity, but the TOML field name is authoritative.)
- **FR-008**: The handler MUST continue to mark `llm_verification_required: True` in its evidence, so the existing `darnit-remediate` skill knows to trigger calling-agent verification.
- **FR-009**: The handler MUST continue to embed source code snippets alongside each finding, so the calling agent can verify findings against real code without additional tool calls.
- **FR-010**: The handler MUST continue to include a verification prompt section that instructs the calling agent how to review the draft (analogous to the current `_build_verification_section` output), updated to reflect the new finding categories where appropriate.

**Output formats**

- **FR-011**: The handler MUST produce a human-readable Markdown draft as its primary artifact, containing: executive summary, asset inventory, data-flow diagram, STRIDE-categorized findings with embedded code snippets, verification prompts, and a limitations section.
- **FR-012**: The handler MUST continue to emit SARIF and JSON output formats for the same finding set, for consumers that ingest those formats (preserving the existing multi-format contract).
- **FR-013**: The draft's data-flow diagram MUST be generated from the structural call graph produced during discovery, not from a fixed template.

**Optional enrichment**

- **FR-014**: The handler MUST detect the presence of the Opengrep CLI binary at runtime via `shutil.which("opengrep")`, with a fallback check for `shutil.which("semgrep")` since rule formats are compatible.
- **FR-015**: When Opengrep is available, the handler MUST run the bundled rule set to produce taint-flow–enriched findings and attach data-flow traces to the relevant findings in the draft.
- **FR-016**: When Opengrep is not available, the handler MUST log a warning via `darnit.core.logging` identifying the missing tool and continue generation using only the tree-sitter layer. The draft MUST note the degraded mode in its Limitations section.
- **FR-017**: Findings emitted without Opengrep MUST be strict subsets of findings that Opengrep would add — the absence of Opengrep must never cause new incorrect findings to appear.
- **FR-018**: When Opengrep returns findings but also reports rule-schema errors in its `errors[]` array, the handler MUST log those errors as a degraded-operation warning and continue with whatever findings were returned successfully.

**Operational**

- **FR-019**: The handler MUST recover from syntax errors in individual source files and continue analyzing the remainder of the repository.
- **FR-020**: The handler MUST NOT execute, import, or evaluate code from the repository being analyzed.
- **FR-021**: The handler MUST NOT make network calls during analysis. (Opengrep is invoked locally via subprocess; tree-sitter is in-process.)
- **FR-022**: The handler MUST complete analysis of a medium-sized repository (on the order of 100–500 in-scope source files) within 2 minutes of wall-clock time on a baseline hardware profile of 4 CPU cores, 8 GB RAM, and SSD storage — representative of CI runners and modern developer laptops.
- **FR-023**: The handler MUST emit debug-level log lines for each discovery phase (tree-sitter parse, tree-sitter query execution, Opengrep invocation, draft assembly) via `darnit.core.logging`, for post-hoc troubleshooting of unexpected results.
- **FR-024**: The handler MUST exclude vendor, dependency, and build directories from discovery by default. At minimum: `node_modules`, `.venv`, `venv`, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `vendor/`, `dist/`, `build/`, `target/`, `.git`, and any directory listed in the project's `.gitignore` at the repository root. `.gitignore` parsing matches directory names only (name-prefix match, not full glob semantics) — wildcards, negation rules, and nested `.gitignore` files are deferred to future work. Users MUST be able to supplement the exclusion list via the handler's config (e.g., an `exclude_dirs` setting) without having to disable the defaults.
- **FR-025**: When more than 500 in-scope source files remain after exclusions, the handler MUST enter a "shallow" analysis mode that produces a simpler but still accurate threat model. Shallow mode characteristics: a reduced query set (only the highest-signal entry-point and data-store queries), a narrower code-context window per finding, and skipped or simplified attack-chain computation.
- **FR-026**: When the handler runs in shallow mode, the draft's Limitations section MUST clearly state that a simpler analysis was performed because the in-scope file count exceeded the full-analysis envelope, report the number of in-scope files scanned, and note which analyses were reduced or skipped.
- **FR-027**: The handler MUST surface the scanned-file count, excluded directory count, and (if applicable) shallow-mode indicator in its `HandlerResult` evidence, so the calling agent can mention these in its review output.
- **FR-028**: The handler MUST rank candidate findings by a severity × confidence heuristic and cap the number emitted to the draft at a configurable default of 50. Users MUST be able to raise or lower the cap via the handler's config (e.g., a `max_findings` setting).
- **FR-029**: When candidate findings exceed the cap, the handler MUST include a per-STRIDE-category summary of the trimmed overflow in the draft's Limitations section (e.g., "Tampering: 12 additional candidates trimmed; Information Disclosure: 8 additional candidates trimmed") so the calling agent can inform the user and, if needed, advise re-running with a higher cap.
- **FR-030**: The trimmed-overflow counts MUST also appear in the `HandlerResult` evidence so the calling agent has structured access to them without re-parsing the Markdown draft.
- **FR-031**: The handler MUST be stateless across runs. It MUST NOT persist finding fingerprints, suppression lists, or any triage memory between invocations. Each run re-discovers from source and re-emits findings from scratch. Consistency across runs against an unchanged repository is a property of the deterministic discovery pipeline, not of persisted state.

### Key Entities

- **Asset**: A real structural element of the target codebase with a stable identity: an entry point, a data store, an authentication mechanism, a sensitive-data sink. Has a file path, a location in the file, a kind, and supporting evidence (the code pattern that revealed it — typically a tree-sitter query match).
- **Candidate Finding**: A potentially-interesting observation produced by discovery. Contains a STRIDE category, a proposed title, a reference to one or more assets, the source of the finding (tree-sitter structural match or Opengrep taint trace), surrounding code context, and — when available — a data-flow trace.
- **Draft Threat Model**: The file artifact written by the handler. Contains executive summary, assets, data-flow diagram, candidate findings grouped by STRIDE category, verification prompts, and limitations. Marked with `llm_verification_required: True` in handler evidence.
- **Verification Prompt Block**: A self-contained instruction block embedded in the draft telling the calling agent how to review and finalize the document. Specifies per-finding review questions (is this real? is the narrative accurate? what should the controls be?) and per-section refinement guidance.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: When the handler runs against its own source repository, zero findings correspond to false-positive patterns from the prior pipeline — specifically, no phantom PostgreSQL finding from `gpg.ssh.allowedSignersFile` and no PII finding from `email=data.get("email", "")` in metadata parsing.
- **SC-001a** *(added 2026-04-12)*: When the handler runs against its own source repository (darnit), the Asset Inventory MUST contain at least 5 entry points. Darnit is an MCP server with 15+ tool endpoints registered via `server.add_tool()` in `factory.py`. An empty asset inventory for this codebase is a test failure, not an acceptable result. This criterion validates that imperative registration detection (FR-001a) works against real code, not just fixtures.
- **SC-001b** *(added 2026-04-12)*: When the handler runs against its own source repository, subprocess/exec findings MUST NOT all have identical severity × confidence scores. Specifically: calls with fully-static literal arguments (e.g., `["git", "rev-parse", "HEAD"]`) MUST score lower than calls with config-driven dynamic arguments (e.g., `resolved_cmd` in `builtin_handlers.py:137`). This validates FR-004a's structural heuristic differentiation.
- **SC-002**: When the handler runs against a curated fixture repository containing seeded real risks (fastapi route, flask route, MCP tool decorator, subprocess call with tainted input, SQLite connection, Redis client), at least 90% of seeded real risks appear in the draft.
- **SC-002a** *(added 2026-04-12)*: The curated fixture set MUST include at least one fixture that uses imperative tool/route registration (e.g., `server.add_tool(handler, name=...)` or `app.add_url_rule(rule, endpoint, view_func)`) rather than decorator syntax. This fixture MUST produce entry points in the draft. Fixtures that only test decorator patterns create a false sense of coverage when the real target codebase uses a different registration mechanism.
- **SC-003**: Every finding in a generated draft, when spot-checked against the referenced file and line, corresponds to code that a human reviewer would describe as "related to the stated threat" — measured as a spot check on any 10 randomly-selected findings.
- **SC-004**: The OSPS-SA-03.02 compliance control continues to pass after remediation, without manual edits to the generated file — verified by running `audit` → `remediate` → `audit` against a repository with no pre-existing threat model.
- **SC-005**: A draft produced by the new pipeline is structurally identical (same top-level sections, same evidence flags) to a draft produced by the old pipeline, so the existing `darnit-remediate` skill's review instructions work unchanged.
- **SC-006**: Generating a draft for a 100–500 file repository completes in under 2 minutes of wall-clock time on the baseline hardware profile defined in FR-022, not counting the calling agent's subsequent verification pass.
- **SC-007**: When Opengrep is not installed, the handler produces a draft that contains no incorrect findings compared to a full-capability run, though it may contain fewer findings.
- **SC-008**: A calling agent reviewing a new-pipeline draft against the same fixture repository spends measurably less effort stripping false positives than it does reviewing an old-pipeline draft, measured by the count of findings the agent removes or marks as false positives during verification.
- **SC-009** *(added 2026-04-12)*: When the handler runs against its own source repository, at least 3 of the 6 STRIDE categories MUST contain findings. The v1 implementation produced findings in only 1 category (Tampering) because empty asset inventory cascaded to empty Spoofing, Information Disclosure, and Elevation of Privilege. With entry points detected (SC-001a), the Spoofing category at minimum should be populated (unauthenticated MCP tools), and subprocess findings should span Tampering and potentially Elevation of Privilege.

## Assumptions

- The framework's existing MCP tool, skill, and handler-registration infrastructure (`darnit-remediate` skill, `SieveHandlerRegistry`, `HandlerContext`, evidence conventions) remains stable and is not part of this change.
- The calling agent (Claude via MCP, invoked through a skill) has access to the generated draft file and is capable of reading, modifying, and committing it — this is how darnit currently works and is not in scope.
- Users running this tool on repositories containing Python, JS/TS, Go, and YAML represent the majority of darnit's user base. TOML files are read for dependency-manifest corroboration only, not scanned structurally. Additional language support can be added later by extending the tree-sitter grammar set without changing the architecture.
- Users who want taint-flow findings will install Opengrep out-of-band following documented instructions. The handler does not bundle or auto-install the binary.
- "Accurate" means "does not contain misleading findings." It does not mean "finds every real vulnerability" — this is a threat-modeling aid, not an exhaustive SAST tool. Full vulnerability scanning is the job of Kusari Inspector (or equivalent), not this feature.
- The existing pattern of having the calling agent resolve ambiguity (via `PENDING_LLM` consultation requests or post-remediation file review) is the correct architectural model and is preserved. Darnit does not make LLM API calls; the calling agent is the LLM.

## Out of Scope

- Finding fingerprinting, triage memory, and suppression mechanisms. The handler is stateless in v1; users preserve triage edits via the default skip-if-exists behavior and override intentionally when they want to regenerate.
- Changes to the MCP tool surface. The existing `generate_threat_model` tool and the OSPS-SA-03.02 remediation handler keep the same names, arguments, and return shapes.
- ~~Changes to the `darnit-remediate` skill.~~ *(Moved in-scope per 2026-04-12 LLM consultation session.)* The skill now has a generic rule to follow `llm_consultation` payloads returned by any remediation handler. This is a skill-layer change, not a framework change.
- Changes to the sieve orchestrator, handler registry, or plugin protocol. This is a discovery-layer rewrite confined to `packages/darnit-baseline/src/darnit_baseline/threat_model/`.
- Cross-function (inter-procedural) taint analysis. Opengrep's `--taint-intrafile` flag is documented but unreleased in 1.6.0; intra-procedural taint is sufficient for v1.
- Structural scanning for languages outside {Python, JavaScript, TypeScript, Go, YAML}. TOML parsing is limited to dependency manifests (`pyproject.toml`, `package.json`).
- Dynamic analysis, runtime instrumentation, or any form of executing target code.
- Persistent caching of discovery results across runs.
- Auto-remediation of threats discovered by the tool (i.e., suggesting fixes for the findings the draft contains). Findings are reported; fixing them is the user's responsibility.
- Rewriting any other part of darnit-baseline beyond the `threat_model/` subpackage.
